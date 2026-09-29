// SPDX-License-Identifier: Apache-2.0

package fcm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// testSender points a Sender at a fake FCM so Send can be exercised without credentials.
func testSender(endpoint string) *Sender {
	return &Sender{
		tokens:    oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}),
		projectID: "slim-m-relay-test",
		http:      &http.Client{Timeout: 5 * time.Second},
		endpoint:  endpoint,
	}
}

// blockingTokenSource models oauth2.TokenSource.Token() the way a blackholed OAuth token
// endpoint would: it never returns within any reasonable time and, matching the real
// interface, takes no context - so nothing about the call itself can be interrupted from
// the outside.
type blockingTokenSource struct{ unblock <-chan struct{} }

func (b blockingTokenSource) Token() (*oauth2.Token, error) {
	<-b.unblock
	return &oauth2.Token{AccessToken: "too-late"}, nil
}

// Send's caller-supplied context must bound the token fetch even though
// oauth2.TokenSource.Token() itself takes none: without that, a blackholed token endpoint
// holds the request open indefinitely regardless of any deadline the caller set up around
// this call, which is the exact pathology a per-request deadline exists to prevent.
func TestSendBoundsTokenFetchByContext(t *testing.T) {
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) }) // let the abandoned fetch goroutine finish and exit

	s := &Sender{
		tokens:    blockingTokenSource{unblock: unblock},
		projectID: "slim-m-relay-test",
		http:      &http.Client{Timeout: 5 * time.Second},
		endpoint:  "http://127.0.0.1:0", // never reached; the token fetch is what must block
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	results := s.Send(ctx, []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "c"}})
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("Send took %v to return, want close to the 30ms context deadline, not blocked on "+
			"a token fetch that never returns on its own", elapsed)
	}
	if len(results) != 1 || results[0].Status != push.StatusError {
		t.Errorf("results = %+v, want a single StatusError (the token fetch never completed in time)", results)
	}
}

func TestErrorCode(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"unregistered", `{"error":{"code":404,"status":"NOT_FOUND","details":[
			{"errorCode":"UNREGISTERED"}]}}`, "UNREGISTERED"},
		{"falls back to status", `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, "UNAUTHENTICATED"},
		{"not json", `<html>502</html>`, ""},
		{"empty", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorCode([]byte(tt.body)); got != tt.want {
				t.Errorf("errorCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// malformedTokenBody is the exact live FCM v1 response body observed for a malformed or
// corrupt registration token: HTTP 400, errorCode INVALID_ARGUMENT, and a BadRequest field
// violation naming "message.token".
const malformedTokenBody = `{"error":{"code":400,"message":"The registration token is not a valid FCM registration token","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"},{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"The registration token is not a valid FCM registration token"}]}]}}`

// malformedTokenBodyPrettyPrinted is the exact live FCM v1 response body for the same
// malformed-token error, byte for byte including FCM's default pretty-printed indentation
// (571 bytes). A minified fixture like malformedTokenBody above would pass sendOne's error
// classification even with the truncating-at-512-bytes bug present, since it fits under the
// old cap whole; this one does not, which is precisely how that bug slipped through the
// first time.
const malformedTokenBodyPrettyPrinted = `{
  "error": {
    "code": 400,
    "message": "The registration token is not a valid FCM registration token",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
        "errorCode": "INVALID_ARGUMENT"
      },
      {
        "@type": "type.googleapis.com/google.rpc.BadRequest",
        "fieldViolations": [
          {
            "field": "message.token",
            "description": "The registration token is not a valid FCM registration token"
          }
        ]
      }
    ]
  }
}`

// Send must map each FCM response to the right per-token status, in input order, so the
// caller can prune exactly the dead tokens.
func TestSendMapsPerTokenStatus(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), "dead"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`))
		case strings.Contains(string(body), "malformed"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(malformedTokenBody))
		case strings.Contains(string(body), "badpayload"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[
				{"errorCode":"INVALID_ARGUMENT"},
				{"fieldViolations":[{"field":"message.data","description":"bad data"}]}]}}`))
		case strings.Contains(string(body), "boom"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"status":"INTERNAL"}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer fcm.Close()

	s := testSender(fcm.URL)
	results := s.Send(context.Background(), []push.Message{
		{Token: "good", Kind: push.KindMessage, Payload: "cipher-good"},
		{Token: "dead", Kind: push.KindMessage, Payload: "cipher-dead"},
		{Token: "malformed", Kind: push.KindMessage, Payload: "cipher-malformed"},
		{Token: "badpayload", Kind: push.KindMessage, Payload: "cipher-badpayload"},
		{Token: "boom", Kind: push.KindMessage, Payload: "cipher-boom"},
	})

	want := []push.Result{
		{Token: "good", Status: push.StatusDelivered},
		{Token: "dead", Status: push.StatusUnregistered},
		// A 400 whose field violation names message.token is a dead token, not a retryable
		// error - see the live fixture in malformedTokenBody.
		{Token: "malformed", Status: push.StatusUnregistered},
		// A 400 whose field violation names something other than message.token is a genuine
		// bad request (a server bug) and must stay loud as StatusError, never swallowed into
		// StatusUnregistered.
		{Token: "badpayload", Status: push.StatusError},
		{Token: "boom", Status: push.StatusError},
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i := range want {
		if results[i] != want[i] {
			t.Errorf("result %d = %+v, want %+v", i, results[i], want[i])
		}
	}
}

// TestSendClassifiesPrettyPrintedMalformedTokenAsUnregistered pins the read cap at
// sendOne's HTTP boundary against the exact 571-byte pretty-printed live fixture. A cap
// that truncates the body mid-document breaks json.Unmarshal, which makes
// tokenFieldViolation return false, which misclassifies this as StatusError (retried
// forever) instead of StatusUnregistered - so this must go through Send end to end, not
// just call tokenFieldViolation directly, or a truncation bug in the read itself would
// slip past a unit test of the parsing logic alone.
func TestSendClassifiesPrettyPrintedMalformedTokenAsUnregistered(t *testing.T) {
	if got := len(malformedTokenBodyPrettyPrinted); got != 571 {
		t.Fatalf("fixture is %d bytes, want exactly 571 (the live captured body's length)", got)
	}

	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(malformedTokenBodyPrettyPrinted))
	}))
	defer fcm.Close()

	s := testSender(fcm.URL)
	results := s.Send(context.Background(), []push.Message{
		{Token: "malformed", Kind: push.KindMessage, Payload: "cipher-malformed"},
	})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Status != push.StatusUnregistered {
		t.Errorf("status = %v, want StatusUnregistered (a read cap that truncates this 571-byte "+
			"pretty-printed body mid-document yields StatusError instead)", results[0].Status)
	}
}

// TestTokenFieldViolation exercises the field-violation check directly against the exact
// live fixture and its near neighbours, so the malformed-token path is pinned independent
// of the HTTP status-code gate in sendOne.
func TestTokenFieldViolation(t *testing.T) {
	tests := []struct {
		name, body string
		want       bool
	}{
		{"live malformed-token fixture", malformedTokenBody, true},
		{"field violation on a different field", `{"error":{"details":[
			{"fieldViolations":[{"field":"message.data","description":"bad"}]}]}}`, false},
		{"no field violations at all", `{"error":{"status":"INTERNAL"}}`, false},
		{"not json", `<html>400</html>`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenFieldViolation([]byte(tt.body)); got != tt.want {
				t.Errorf("tokenFieldViolation() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The message is data-only: FCM should never receive a "notification" field, since that
// would require plaintext title/body the relay must never construct or hold.
func TestSendNeverSendsNotificationField(t *testing.T) {
	var gotBody string
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fcm.Close()

	s := testSender(fcm.URL)
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "opaque-ciphertext"}})

	if strings.Contains(gotBody, "notification") {
		t.Errorf("request body should never contain a notification field:\n%s", gotBody)
	}
	if !strings.Contains(gotBody, "opaque-ciphertext") {
		t.Errorf("payload should travel as opaque data:\n%s", gotBody)
	}
}

// A push's opaque payload must never reach the logs, whatever FCM answers.
func TestSendNeverLogsContent(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"status":"INTERNAL"}}`))
	}))
	defer fcm.Close()

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := testSender(fcm.URL)
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindMessage, Payload: "top-secret-ciphertext"}})

	for _, secret := range []string{"top-secret-ciphertext", "tok"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("log leaked %q:\n%s", secret, buf.String())
		}
	}
}

// A call signal carries a TTL matching the ring timeout, and nothing else does.
func TestSendSetsTTLOnlyForCallSignals(t *testing.T) {
	for _, kind := range []push.Kind{push.KindMessage, push.KindMention, push.KindCall, push.KindCallEnd, push.KindSecurity, push.KindWake} {
		t.Run(string(kind), func(t *testing.T) {
			var got struct {
				Message struct {
					Android map[string]any `json:"android"`
				} `json:"message"`
			}
			fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &got)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer fcm.Close()

			testSender(fcm.URL).Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: "p"}})

			if got.Message.Android["priority"] != "high" {
				t.Errorf("priority = %v, want high", got.Message.Android["priority"])
			}
			ttl, hasTTL := got.Message.Android["ttl"]
			if kind.IsCallSignal() != hasTTL {
				t.Fatalf("ttl present = %v, want %v", hasTTL, kind.IsCallSignal())
			}
			if hasTTL && ttl != "30s" {
				t.Errorf("ttl = %v, want 30s", ttl)
			}
		})
	}
}
