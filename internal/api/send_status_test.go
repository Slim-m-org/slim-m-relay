// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// silentSender models a provider client that returns no result for a message.
type silentSender struct{}

func (silentSender) Send(context.Context, []push.Message) []push.Result { return nil }

func decodeResults(t *testing.T, rr *httptest.ResponseRecorder) []push.Result {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Results
}

// slim-m's server reads "error" as "this relay may predate the kind" and downgrades voice
// and admin alerts for an hour, so a relay that knows the kinds must never answer it: each
// failure is permanent (rejected) or worth trying again (retry).
func TestSendSplitsPermanentFromTransientAndNeverAnswersError(t *testing.T) {
	cfg := defaultCfg()
	cfg.CallSendPerMinute = 1
	cfg.CallSendBurst = 1
	srv, _, _, store := newTestServer(t, cfg)
	srv.android = silentSender{}
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"windows-phone","token":"a","kind":"message","payload":"c"},
		{"platform":"ios","token":"b","kind":"not-a-real-kind","payload":"c"},
		{"platform":"ios","token":"x/y","kind":"message","payload":"c"},
		{"platform":"ios","token":"c","kind":"message","payload":"` + strings.Repeat("x", maxPayloadBytes+1) + `"},
		{"platform":"ios","token":"call-1","kind":"call","payload":"c"},
		{"platform":"ios","token":"call-2","kind":"call","payload":"c"},
		{"platform":"android","token":"d","kind":"voice","payload":"c"}
	]}`
	got := decodeResults(t, do(srv.Router(), http.MethodPost, "/v1/send", body, key))

	want := []push.Status{
		push.StatusRejected, push.StatusRejected, push.StatusRejected, push.StatusRejected,
		push.StatusDelivered, push.StatusRetry, push.StatusRetry,
	}
	if len(got) != len(want) {
		t.Fatalf("results = %+v, want %d", got, len(want))
	}
	for i, r := range got {
		if r.Status != want[i] {
			t.Errorf("result %d = %q, want %q", i, r.Status, want[i])
		}
		if r.Status == "error" {
			t.Errorf("result %d answered the legacy %q status", i, r.Status)
		}
	}
}

// closeOnRead closes the key store the first time the handler reads the body, which is after
// the key was verified and before any token is bound: a database that fails mid-request.
type closeOnRead struct {
	body  io.Reader
	close func()
	done  bool
}

func (c *closeOnRead) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		c.close()
	}
	return c.body.Read(p)
}

func TestSendAnswersRetryWhenTheBindingStoreFails(t *testing.T) {
	rig := newTokenRig(t, defaultCfg())
	plain := rig.newKey(t)
	body := `{"messages":[{"platform":"android","token":"tok-a","kind":"wake"},{"platform":"android","token":"tok-b","kind":"wake"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/send", &closeOnRead{
		body:  strings.NewReader(body),
		close: func() { _ = rig.store.Close() },
	})
	req.Header.Set("Authorization", "Bearer "+plain)
	rr := httptest.NewRecorder()
	rig.srv.Router().ServeHTTP(rr, req)

	got := decodeResults(t, rr)
	if len(got) != 2 || got[0].Status != push.StatusRetry || got[1].Status != push.StatusRetry {
		t.Fatalf("results = %+v, want retry for both: the messages are fine, the relay's store is not", got)
	}
	if len(rig.android.got) != 0 {
		t.Errorf("messages reached the provider without a binding: %+v", rig.android.got)
	}
}

func TestSendTooManyRequestsTellsTheCallerWhenToRetry(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendBurst = 1
	cfg.SendPerMinute = 1
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"c"}]}`

	do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second send = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60: one token per minute refills in a minute", got)
	}
}

func TestRegisterTooManyRequestsTellsTheCallerWhenToRetry(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterBurst = 1
	cfg.RegisterPerHour = 2
	srv, _, _, _ := newTestServer(t, cfg)

	do(srv.Router(), http.MethodPost, "/v1/register", `{}`, "")
	rr := do(srv.Router(), http.MethodPost, "/v1/register", `{}`, "")

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second register = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "1800" {
		t.Errorf("Retry-After = %q, want 1800: two tokens an hour refill one in half an hour", got)
	}
}

// A full token refuses one message and the rest of the batch still goes through, because
// every binding is decided in one transaction but each token keeps its own outcome.
func TestSendBatchRefusesOneFullTokenAndDeliversTheRest(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxKeysPerToken = 1
	rig := newTokenRig(t, cfg)
	owner, other := rig.newKey(t), rig.newKey(t)
	if res := rig.send(t, owner, "android", "shared"); res[0].Status != push.StatusDelivered {
		t.Fatalf("owner send = %+v", res)
	}

	got := rig.send(t, other, "android", "mine-1", "shared", "mine-2")

	want := []push.Status{push.StatusDelivered, push.StatusForbidden, push.StatusDelivered}
	for i, r := range got {
		if r.Status != want[i] {
			t.Errorf("result %d = %q, want %q", i, r.Status, want[i])
		}
	}
	if _, err := rig.store.Verify(context.Background(), other); err != nil {
		t.Fatalf("key unexpectedly unusable: %v", err)
	}
}

func TestSendRetryAfterCoversTheWholeShortfallOfABatch(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendMessagesBurst = 10
	cfg.SendMessagesPerMinute = 60
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	batch := func(n int) string {
		msgs := make([]string, n)
		for i := range msgs {
			msgs[i] = fmt.Sprintf(`{"platform":"ios","token":"%064x","kind":"wake","payload":"c"}`, i+1)
		}
		return `{"messages":[` + strings.Join(msgs, ",") + `]}`
	}

	if rr := do(srv.Router(), http.MethodPost, "/v1/send", batch(10), key); rr.Code != http.StatusOK {
		t.Fatalf("first batch = %d, want 200", rr.Code)
	}
	rr := do(srv.Router(), http.MethodPost, "/v1/send", batch(5), key)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second batch = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want 5: five messages at one a second", got)
	}
}
