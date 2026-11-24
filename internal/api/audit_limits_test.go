// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/push"
)

func batchBody(n int, platform string) string {
	var parts []string
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`{"platform":%q,"token":"tok%d","kind":"wake"}`, platform, i))
	}
	return `{"messages":[` + strings.Join(parts, ",") + `]}`
}

func TestSendChargesTheKeyBudgetPerMessage(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendMessagesPerMinute = 1
	cfg.SendMessagesBurst = 10
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	h := srv.Router()

	if rr := do(h, http.MethodPost, "/v1/send", batchBody(6, "ios"), key); rr.Code != http.StatusOK {
		t.Fatalf("first batch = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batchBody(6, "ios"), key); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second batch of 6 = %d, want 429 once 6 of 10 units are spent", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batchBody(4, "ios"), key); rr.Code != http.StatusOK {
		t.Fatalf("batch of 4 = %d, want 200 with 4 units left", rr.Code)
	}
}

func TestSendRefundsMessagesThatNeverReachedAProvider(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendMessagesPerMinute = 1
	cfg.SendMessagesBurst = 10
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	h := srv.Router()
	for i := 0; i < 5; i++ {
		rr := do(h, http.MethodPost, "/v1/send", batchBody(8, "carrier-pigeon"), key)
		if rr.Code != http.StatusOK {
			t.Fatalf("invalid batch %d = %d, want 200: rejected messages cost nothing", i, rr.Code)
		}
	}
}

func TestSendSharesOneRelayWideBudgetAcrossKeys(t *testing.T) {
	cfg := defaultCfg()
	cfg.ProviderCallsPerMinute = 1
	cfg.ProviderCallsBurst = 6
	srv, _, _, store := newTestServer(t, cfg)
	a, _ := store.Issue(context.Background(), "", 0)
	b, _ := store.Issue(context.Background(), "", 0)
	h := srv.Router()
	if rr := do(h, http.MethodPost, "/v1/send", batchBody(5, "ios"), a); rr.Code != http.StatusOK {
		t.Fatalf("first key = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batchBody(5, "ios"), b); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second key = %d, want 429 from the relay-wide budget", rr.Code)
	}
}

func TestSendBindsNoMoreThanTheRelayWideTokenCap(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxTokensTotal = 2
	srv, plain, path := openTokenTestServer(t, cfg)
	res := sendTokens(t, srv, plain, "android", "tok0", "tok1", "tok2")
	want := []push.Status{push.StatusDelivered, push.StatusDelivered, push.StatusRejected}
	for i, r := range res {
		if r.Status != want[i] {
			t.Errorf("token %d status = %q, want %q", i, r.Status, want[i])
		}
	}
	if n := countBoundTokens(t, path); n != 2 {
		t.Fatalf("tokens rows = %d, want 2", n)
	}
}

func TestHealthzFloodQueriesTheDatabaseOnce(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	var pings atomic.Int64
	srv.health.ping = func(context.Context) error { pings.Add(1); return nil }
	h := srv.Router()
	for i := 0; i < 50; i++ {
		if rr := do(h, http.MethodGet, "/healthz", "", ""); rr.Code != http.StatusOK {
			t.Fatalf("healthz = %d, want 200", rr.Code)
		}
	}
	if n := pings.Load(); n != 1 {
		t.Fatalf("50 probes ran %d database pings, want 1", n)
	}
}
