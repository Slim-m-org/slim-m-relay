// SPDX-License-Identifier: Apache-2.0

package apns

import (
	"context"
	"encoding/json"
	"errors"
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
		{"other rejection", &apns2.Response{StatusCode: 403, Reason: apns2.ReasonForbidden}, nil, push.StatusError},
		{"transport error", nil, errors.New("boom"), push.StatusError},
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

// Only call signals expire with the ring; anything else keeps APNs' default store-and-forward.
func TestSendExpiresOnlyCallSignals(t *testing.T) {
	for _, kind := range []push.Kind{push.KindMessage, push.KindMention, push.KindCall, push.KindCallEnd, push.KindSecurity, push.KindWake} {
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
