// SPDX-License-Identifier: Apache-2.0

package apns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/sideshow/apns2"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// fakeClient records what it was asked to push and returns a canned response, so Send can
// be exercised without real APNs credentials or a network call.
type fakeClient struct {
	resp *apns2.Response
	err  error
	got  []*apns2.Notification
}

func (f *fakeClient) PushWithContext(_ apns2.Context, n *apns2.Notification) (*apns2.Response, error) {
	f.got = append(f.got, n)
	return f.resp, f.err
}

func TestSendMapsResponseToStatus(t *testing.T) {
	tests := []struct {
		name string
		resp *apns2.Response
		err  error
		want push.Status
	}{
		{"delivered", &apns2.Response{StatusCode: 200}, nil, push.StatusDelivered},
		{"unregistered token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered}, nil, push.StatusUnregistered},
		{"bad device token", &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadDeviceToken}, nil, push.StatusUnregistered},
		{"expired token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonExpiredToken}, nil, push.StatusUnregistered},
		{"provider credential rejected", &apns2.Response{StatusCode: 403, Reason: apns2.ReasonForbidden}, nil, push.StatusRetry},
		{"expired provider token", &apns2.Response{StatusCode: 403, Reason: apns2.ReasonExpiredProviderToken}, nil, push.StatusRetry},
		{"throttled", &apns2.Response{StatusCode: 429, Reason: apns2.ReasonTooManyRequests}, nil, push.StatusRetry},
		{"gateway trouble", &apns2.Response{StatusCode: 503, Reason: apns2.ReasonServiceUnavailable}, nil, push.StatusRetry},
		{"internal error", &apns2.Response{StatusCode: 500, Reason: apns2.ReasonInternalServerError}, nil, push.StatusRetry},
		{"payload too large", &apns2.Response{StatusCode: 413, Reason: apns2.ReasonPayloadTooLarge}, nil, push.StatusRejected},
		{"bad topic", &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadTopic}, nil, push.StatusRejected},
		{"transport error", nil, errors.New("boom"), push.StatusRetry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeClient{resp: tt.resp, err: tt.err}
			s := &Sender{client: fc, bundleID: "com.example.app"}
			results := s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "cipher"}})
			if len(results) != 1 || results[0].Status != tt.want {
				t.Fatalf("results = %+v, want status %v", results, tt.want)
			}
		})
	}
}

// Only "wake" stays a silent background push: the bundle id as topic, PushTypeBackground,
// and low priority.
func TestSendWakeKindUsesSilentBackgroundPush(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "cipher"}})

	if len(fc.got) != 1 {
		t.Fatalf("got %d notifications, want 1", len(fc.got))
	}
	n := fc.got[0]
	if n.Topic != "com.example.app" {
		t.Errorf("topic = %q, want the configured bundle id", n.Topic)
	}
	if n.PushType != apns2.PushTypeBackground {
		t.Errorf("push type = %q, want background", n.PushType)
	}
	if n.Priority != apns2.PriorityLow {
		t.Errorf("priority = %d, want PriorityLow (a background push must not use high priority)", n.Priority)
	}
}

// A message or mention must actually surface on a locked device, which a
// content-available-only push never does. Both take an alert push on the plain bundle id
// topic at high priority.
func TestSendMessageKindsUseAlertPush(t *testing.T) {
	for _, kind := range []push.Kind{push.KindMessage, push.KindMention} {
		t.Run(string(kind), func(t *testing.T) {
			fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
			s := &Sender{client: fc, bundleID: "com.example.app"}
			s.Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: "cipher"}})

			n := fc.got[0]
			if n.Topic != "com.example.app" {
				t.Errorf("topic = %q, want the configured bundle id", n.Topic)
			}
			if n.PushType != apns2.PushTypeAlert {
				t.Errorf("push type = %q, want alert so the device shows something", n.PushType)
			}
			if n.Priority != apns2.PriorityHigh {
				t.Errorf("priority = %d, want PriorityHigh for a user-visible alert", n.Priority)
			}
		})
	}
}

// A "call" kind must ring the device: it takes the separate ".voip" PushKit topic,
// PushTypeVOIP, and high priority, derived from the one configured bundle id rather than a
// second operator-supplied value.
func TestSendCallKindUsesVoipTopicAndPushType(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindCall, Payload: "cipher"}})

	if len(fc.got) != 1 {
		t.Fatalf("got %d notifications, want 1", len(fc.got))
	}
	n := fc.got[0]
	if n.Topic != "com.example.app.voip" {
		t.Errorf("topic = %q, want the bundle id with .voip appended", n.Topic)
	}
	if n.PushType != apns2.PushTypeVOIP {
		t.Errorf("push type = %q, want voip", n.PushType)
	}
	if n.Priority != apns2.PriorityHigh {
		t.Errorf("priority = %d, want PriorityHigh (10) for a call push", n.Priority)
	}
}

// The payload must never carry anything derived from the message. A visible alert is
// allowed, but only the fixed generic string: it must be byte-identical regardless of the
// sender, channel, or text, so APNs learns nothing it did not already know from the kind.
func TestSendPayloadIsContentFree(t *testing.T) {
	send := func(kind push.Kind, payload string) string {
		fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
		s := &Sender{client: fc, bundleID: "com.example.app"}
		s.Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: payload}})
		raw, err := json.Marshal(fc.got[0].Payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		return string(raw)
	}

	// Two different messages in the same channel from different senders must produce
	// byte-identical alert text.
	a := send(push.KindMessage, "ciphertext-one")
	b := send(push.KindMessage, "totally-different-ciphertext")
	extractAlert := func(body string) string {
		var d struct {
			Aps struct {
				Alert string `json:"alert"`
			} `json:"aps"`
		}
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return d.Aps.Alert
	}
	if extractAlert(a) != extractAlert(b) {
		t.Errorf("alert text varies between messages (%q vs %q); it must be a fixed string",
			extractAlert(a), extractAlert(b))
	}
	if extractAlert(a) != "New message" {
		t.Errorf("alert = %q, want the fixed generic string", extractAlert(a))
	}

	body := send(push.KindMention, "opaque-ciphertext")
	var decoded struct {
		Aps struct {
			Alert          string `json:"alert"`
			MutableContent int    `json:"mutable-content"`
		} `json:"aps"`
		Kind    string `json:"kind"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	// mutable-content is what lets a Notification Service Extension replace the generic
	// text with the decrypted content on-device; without it the placeholder is permanent.
	if decoded.Aps.MutableContent != 1 {
		t.Errorf("mutable-content = %d, want 1", decoded.Aps.MutableContent)
	}
	if decoded.Kind != "mention" {
		t.Errorf("kind = %q, want mention", decoded.Kind)
	}
	if decoded.Payload != "opaque-ciphertext" {
		t.Errorf("payload = %q, want the opaque ciphertext forwarded untouched", decoded.Payload)
	}
	if strings.Contains(body, "opaque-ciphertext\"") && strings.Count(body, "opaque-ciphertext") != 1 {
		t.Errorf("ciphertext appears more than once in the payload:\n%s", body)
	}
}

// A security alert must surface on a locked device like a message does, with its own fixed text.
func TestSendSecurityKindUsesAlertPush(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindSecurity, Payload: "cipher"}})

	n := fc.got[0]
	if n.Topic != "com.example.app" || n.PushType != apns2.PushTypeAlert || n.Priority != apns2.PriorityHigh {
		t.Fatalf("security push = topic %q type %q priority %d, want a high-priority alert on the bundle id", n.Topic, n.PushType, n.Priority)
	}
	body, err := json.Marshal(n.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "New sign-in to your account") {
		t.Errorf("security payload should carry its fixed alert text: %s", body)
	}
}

// A voice notice and an admin alert each surface with their own fixed, content-free line.
func TestSendVoiceAndAdminAlertKindsHaveTheirOwnText(t *testing.T) {
	for kind, want := range map[push.Kind]string{
		push.KindVoice:      "Voice channel activity",
		push.KindAdminAlert: "Server alert",
	} {
		fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
		s := &Sender{client: fc, bundleID: "com.example.app"}
		s.Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: "cipher"}})

		n := fc.got[0]
		if n.PushType != apns2.PushTypeAlert {
			t.Fatalf("%s push type = %q, want an alert", kind, n.PushType)
		}
		body, err := json.Marshal(n.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), want) {
			t.Errorf("%s payload should carry %q: %s", kind, want, body)
		}
	}
}

// A call_end stops a ring, so it is a silent background push on the plain topic, never a VoIP one:
// iOS kills an app that takes a VoIP push without reporting a new call.
func TestSendCallEndKindIsSilentAndNotVoip(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindCallEnd, Payload: "cipher"}})

	n := fc.got[0]
	if n.Topic != "com.example.app" || n.PushType != apns2.PushTypeBackground || n.Priority != apns2.PriorityLow {
		t.Fatalf("call_end push = topic %q type %q priority %d, want a low-priority background push on the bundle id", n.Topic, n.PushType, n.Priority)
	}
}

// A read must never show anything: a low-priority background wake on the plain topic.
func TestSendReadKindIsSilentBackgroundWake(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindRead, Payload: "cipher"}})

	n := fc.got[0]
	if n.Topic != "com.example.app" || n.PushType != apns2.PushTypeBackground || n.Priority != apns2.PriorityLow {
		t.Fatalf("read push = topic %q type %q priority %d, want a low-priority background push on the bundle id", n.Topic, n.PushType, n.Priority)
	}
	raw, err := json.Marshal(n.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"alert"`) || strings.Contains(string(raw), `"badge"`) || strings.Contains(string(raw), `"sound"`) {
		t.Errorf("read payload %s must carry no alert, badge or sound", raw)
	}
}

// Only call signals expire with the ring; anything else keeps APNs' default store-and-forward.
func TestSendExpiresOnlyCallSignals(t *testing.T) {
	for _, kind := range []push.Kind{push.KindMessage, push.KindMention, push.KindCall, push.KindCallEnd, push.KindSecurity, push.KindWake, push.KindVoice, push.KindAdminAlert} {
		t.Run(string(kind), func(t *testing.T) {
			fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
			s := &Sender{client: fc, bundleID: "com.example.app"}
			before := time.Now()
			s.Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: "cipher"}})

			exp := fc.got[0].Expiration
			if !kind.IsCallSignal() {
				if !exp.IsZero() {
					t.Errorf("expiration = %v, want unset for a non-call kind", exp)
				}
				return
			}
			if exp.Before(before.Add(push.CallSignalTTL)) || exp.After(time.Now().Add(push.CallSignalTTL)) {
				t.Errorf("expiration = %v, want now + %v", exp, push.CallSignalTTL)
			}
		})
	}
}

// The token is spliced into the request path, so characters with meaning there must not
// reach it unescaped.
func TestSendEscapesTheDeviceTokenForTheRequestPath(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "ab/cd#1?x", Kind: push.KindWake, Payload: "cipher"}})

	if len(fc.got) != 1 || fc.got[0].DeviceToken != "ab%2Fcd%231%3Fx" {
		t.Fatalf("device token on the wire = %+v, want it path-escaped", fc.got)
	}
}

// A dead provider credential fails every message of a request the same way, and dispatch
// sends them one at a time, so it must log once per request scope instead of once per message.
func TestCredentialDeathLogsOncePerRequest(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	fc := &fakeClient{resp: &apns2.Response{StatusCode: 403, Reason: apns2.ReasonInvalidProviderToken}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	for request := 0; request < 2; request++ {
		ctx := push.WithRequestScope(context.Background())
		for i := 0; i < 100; i++ {
			s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "cipher"}})
		}
	}

	if got := strings.Count(buf.String(), "provider credential"); got != 2 {
		t.Errorf("logged %d credential lines across 2 requests of 100 sends, want 2", got)
	}
}
