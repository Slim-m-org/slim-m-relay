// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
	"github.com/nc1107/slim-m-relay/internal/ratelimit"
)

func iosBatch(n int) string {
	msgs := make([]string, n)
	for i := range msgs {
		msgs[i] = fmt.Sprintf(`{"platform":"ios","token":"%064x","kind":"wake","payload":"c"}`, i+1)
	}
	return `{"messages":[` + strings.Join(msgs, ",") + `]}`
}

func TestSendRefusesABatchPastThePerKeyMessageBudgetAndSaysSo(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendMessagesBurst = 3
	cfg.SendMessagesPerMinute = 60
	srv, ios, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", iosBatch(3), key); rr.Code != http.StatusOK {
		t.Fatalf("first batch = %d, want 200", rr.Code)
	}
	delivered := len(ios.got)

	rr := do(srv.Router(), http.MethodPost, "/v1/send", iosBatch(2), key)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second batch = %d, want 429", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), errRateLimited) {
		t.Errorf("body = %s, want %q", rr.Body, errRateLimited)
	}
	if got := rr.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2: two messages at one a second", got)
	}
	if len(ios.got) != delivered {
		t.Errorf("a refused batch still reached the provider: %d messages", len(ios.got)-delivered)
	}
}

func TestSendRefusesWhenTheRelayWideProviderBudgetIsSpentAndReturnsTheKeysCharge(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendMessagesBurst = 10
	cfg.SendMessagesPerMinute = 60
	cfg.ProviderCallsBurst = 2
	cfg.ProviderCallsPerMinute = 60
	srv, ios, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", iosBatch(2), key); rr.Code != http.StatusOK {
		t.Fatalf("first batch = %d, want 200", rr.Code)
	}
	delivered := len(ios.got)

	rr := do(srv.Router(), http.MethodPost, "/v1/send", iosBatch(3), key)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second batch = %d, want 429", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "relay is busy") {
		t.Errorf("body = %s, want the relay-busy message", rr.Body)
	}
	if got := rr.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2: three wanted but the charge clamps to the burst of 2, one a second", got)
	}
	if len(ios.got) != delivered {
		t.Errorf("a refused batch still reached the provider: %d messages", len(ios.got)-delivered)
	}
	k, err := store.Verify(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !srv.msgLim.AllowN(strconv.FormatInt(k.ID, 10), 8) {
		t.Error("the key's 3 units were not returned: 10 minus the 2 delivered should leave 8")
	}
}

func TestWriteRateLimitedNFallsBackToOneTokenWhenTheKeyAlreadyHoldsTheCharge(t *testing.T) {
	lim := ratelimit.New(60, 5)
	rr := httptest.NewRecorder()

	writeRateLimitedN(rr, lim, "unseen", 3, errRateLimited)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1: the next-token wait when there is no shortfall to compute", got)
	}
}

func TestWriteRateLimitedNOmitsRetryAfterWhenTheLimiterNeverRefills(t *testing.T) {
	rr := httptest.NewRecorder()

	writeRateLimitedN(rr, ratelimit.New(0, 1), "k", 1, errRateLimited)

	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q, want none: waiting never helps", got)
	}
}

// blockingSender holds each send until the request deadline fires, like a provider that hangs.
type blockingSender struct{}

func (blockingSender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	<-ctx.Done()
	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: push.StatusRetry}
	}
	return out
}

func TestSendMarksWhatTheDeadlineCutOffAsNotAttempted(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendConcurrency = 1
	cfg.SendTimeoutSeconds = 1
	store, err := keys.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key, _ := store.Issue(context.Background(), "", 0)
	srv := New(cfg, blockingSender{}, &fakeSender{}, store)

	rr := do(srv.Router(), http.MethodPost, "/v1/send", iosBatch(20), key)

	got := decodeResults(t, rr)
	if len(got) != 20 {
		t.Fatalf("results = %d, want 20", len(got))
	}
	for i, r := range got {
		if r.Status != push.StatusNotAttempted {
			t.Errorf("result %d = %q, want not_attempted: the deadline fired before it was delivered", i, r.Status)
		}
	}
}

// closingDeadSender reports every token unregistered and takes the key store down mid-send.
type closingDeadSender struct{ store *keys.Store }

func (c closingDeadSender) Send(_ context.Context, msgs []push.Message) []push.Result {
	_ = c.store.Close()
	return deadSender{}.Send(context.Background(), msgs)
}

func TestSendStillAnswersWhenDroppingADeadTokensBindingFails(t *testing.T) {
	store, err := keys.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key, _ := store.Issue(context.Background(), "", 0)
	srv := New(defaultCfg(), &fakeSender{}, closingDeadSender{store}, store)
	fake := "dVx3_k-Q9:APA91b" + strings.Repeat("Ab_-9", 40)

	res := sendTokens(t, srv, key, "android", fake)

	if res[0].Status != push.StatusUnregistered {
		t.Errorf("status = %q, want unregistered: a failed unbind must not change what the caller is told", res[0].Status)
	}
}
