// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

// fakeSender records what it was asked to send and reports every token delivered, standing
// in for either platform's real provider client in tests. The worker pool in dispatch can
// call Send concurrently for the same platform - the way the real FCM and APNs senders
// already permit, since their own shared state (an oauth2.ReuseTokenSource and an apns2
// token.Token respectively) is mutex-guarded - so got needs the same protection here.
type fakeSender struct {
	mu  sync.Mutex
	got []push.Message
}

func (f *fakeSender) Send(_ context.Context, msgs []push.Message) []push.Result {
	f.mu.Lock()
	f.got = append(f.got, msgs...)
	f.mu.Unlock()
	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: push.StatusDelivered}
	}
	return out
}

func newTestServer(t *testing.T, cfg config.Config) (*Server, *fakeSender, *fakeSender, *keys.Store) {
	t.Helper()
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ios, android := &fakeSender{}, &fakeSender{}
	srv := New(cfg, ios, android, store)
	return srv, ios, android, store
}

// defaultCfg sets limits high enough not to interfere with tests that aren't about limits.
func defaultCfg() config.Config {
	return config.Config{
		MaxMessages:        500,
		RegisterPerHour:    1000,
		RegisterBurst:      1000,
		SendAdmitPerMinute: 100000,
		SendAdmitBurst:     100000,
		SendPerMinute:      100000,
		SendBurst:          100000,
		SendConcurrency:    8,
		SendTimeoutSeconds: 20,
		MaxRegistrations:   1000000,
		CallSendPerMinute:  100000,
		CallSendBurst:      100000,
	}
}

// slowSender stands in for a provider whose HTTP round trip takes a while, so tests can
// observe how many sends the worker pool runs at once and how it behaves when a deadline
// cuts a send off mid-flight. It honors ctx cancellation the way a real *http.Client would.
type slowSender struct {
	delay time.Duration

	mu            sync.Mutex
	inFlight      int
	maxConcurrent int
}

func (s *slowSender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	s.mu.Lock()
	s.inFlight++
	if s.inFlight > s.maxConcurrent {
		s.maxConcurrent = s.inFlight
	}
	s.mu.Unlock()

	status := push.StatusDelivered
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		status = push.StatusError
	}

	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()

	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: status}
	}
	return out
}

func do(h http.Handler, method, target, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRegisterIssuesKey(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	rr := do(srv.Router(), http.MethodPost, "/v1/register", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp registerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Key, "smr_") {
		t.Fatalf("key %q lacks smr_ prefix", resp.Key)
	}
	k, err := store.Verify(context.Background(), resp.Key)
	if err != nil {
		t.Fatalf("issued key does not verify: %v", err)
	}
	if k.Label != "" {
		t.Errorf("a register with no publicUrl should have an empty label, got %q", k.Label)
	}
}

func TestRegisterRateLimited(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterBurst = 1
	cfg.RegisterPerHour = 1
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()

	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second register = %d, want 429", rr.Code)
	}
}

// By default the relay must not trust X-Forwarded-For at all: every proxy the README
// documents (Caddy, Traefik, nginx) appends its view of the peer, so the leftmost entry is
// always whatever the client itself sent, and trusting it lets an attacker fabricate an
// unlimited number of distinct rate-limit identities.
func TestClientIPIgnoresXFFByDefault(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	req := httptest.NewRequest(http.MethodPost, "/v1/register", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := srv.clientIP(req); got != "203.0.113.9" {
		t.Errorf("clientIP = %q, want the socket address (XFF must be ignored without RELAY_TRUST_PROXY)", got)
	}
}

// With RELAY_TRUST_PROXY enabled, clientIP must trust only the rightmost entry - the hop a
// trusted proxy itself appended - never the leftmost, attacker-controlled one.
func TestClientIPTrustsRightmostXFFWhenConfigured(t *testing.T) {
	cfg := defaultCfg()
	cfg.TrustProxy = true
	srv, _, _, _ := newTestServer(t, cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/register", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-For", "attacker-spoofed, 198.51.100.7")
	if got := srv.clientIP(req); got != "198.51.100.7" {
		t.Errorf("clientIP = %q, want the rightmost (proxy-appended) entry, not the attacker-supplied leftmost one", got)
	}
}

// The core of the finding: without RELAY_TRUST_PROXY, an attacker varying
// X-Forwarded-For must not be able to spin up a fresh rate-limit bucket per request and
// burn the per-IP registration limiter down to nothing for everyone else.
func TestRegisterRateLimitIsNotBypassedBySpoofedXFF(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterBurst = 1
	cfg.RegisterPerHour = 1
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()

	req1 := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(""))
	req1.RemoteAddr = "203.0.113.9:1"
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(""))
	req2.RemoteAddr = "203.0.113.9:2" // same real peer, only the source port differs
	req2.Header.Set("X-Forwarded-For", "2.2.2.2")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second register with a spoofed X-Forwarded-For = %d, want 429 "+
			"(the limiter must key on the real peer, not the attacker-controlled header)", rr2.Code)
	}
}

func TestRegisterStoresClaimedURLAsLabel(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	body, _ := json.Marshal(registerReq{PublicURL: "https://alpha.example.com"})
	rr := do(srv.Router(), http.MethodPost, "/v1/register", string(body), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp registerResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	k, err := store.Verify(context.Background(), resp.Key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Label != "https://alpha.example.com" {
		t.Errorf("label = %q, want the claimed public URL recorded", k.Label)
	}
}

// Once the global registration ceiling is reached, /v1/register must refuse to mint another
// key rather than growing the key table without bound.
func TestRegisterEnforcesGlobalCeiling(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxRegistrations = 2
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()

	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("register 1/2 = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("register 2/2 = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("register past the ceiling = %d, want 403 (body %s)", rr.Code, rr.Body)
	}
}

// A "call" kind push has its own, tighter per-key budget: once spent, further call pushes
// from the same key come back as errors even though the general send rate limit (checked
// once for the whole request) still has room, and even though a non-call push in the same
// batch still goes through.
func TestSendCallKindHasTighterPerKeyLimit(t *testing.T) {
	cfg := defaultCfg()
	cfg.CallSendPerMinute = 1
	cfg.CallSendBurst = 1
	srv, ios, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"ios","token":"call-1","kind":"call","payload":"c"},
		{"platform":"ios","token":"call-2","kind":"call","payload":"c"},
		{"platform":"ios","token":"wake-1","kind":"wake","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("results = %+v, want 3", resp.Results)
	}
	if resp.Results[0].Status != push.StatusDelivered {
		t.Errorf("first call = %+v, want delivered (within the call burst of 1)", resp.Results[0])
	}
	if resp.Results[1].Status != push.StatusError {
		t.Errorf("second call = %+v, want error (call burst spent)", resp.Results[1])
	}
	if resp.Results[2].Status != push.StatusDelivered {
		t.Errorf("wake = %+v, want delivered (a non-call kind is unaffected by the call limiter)", resp.Results[2])
	}
	if len(ios.got) != 2 {
		t.Errorf("provider saw %d messages, want exactly 2 (the delivered call and the wake, not the rate-limited call)", len(ios.got))
	}
}

func TestSendRequiresBearer(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", `{"messages":[]}`, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("send without bearer = %d, want 401", rr.Code)
	}
}

func TestSendRejectsUnknownKey(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	rr := do(srv.Router(), http.MethodPost, "/v1/send", `{"messages":[{"platform":"ios","token":"t","kind":"wake","payload":"c"}]}`, "smr_nope")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("send with unknown key = %d, want 401", rr.Code)
	}
}

func TestSendDispatchesByPlatform(t *testing.T) {
	srv, ios, android, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"ios","token":"a","kind":"message","payload":"cipher-a"},
		{"platform":"android","token":"b","kind":"mention","payload":"cipher-b"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results = %+v, want 2", resp.Results)
	}
	for _, r := range resp.Results {
		if r.Status != push.StatusDelivered {
			t.Errorf("result %+v, want delivered", r)
		}
	}
	if len(ios.got) != 1 || ios.got[0].Token != "a" {
		t.Errorf("iOS sender got %+v, want exactly token a", ios.got)
	}
	if len(android.got) != 1 || android.got[0].Token != "b" {
		t.Errorf("Android sender got %+v, want exactly token b", android.got)
	}
}

func TestSendRejectsUnknownPlatformAndKind(t *testing.T) {
	srv, ios, android, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"windows-phone","token":"a","kind":"message","payload":"c"},
		{"platform":"ios","token":"b","kind":"not-a-real-kind","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Results) != 2 {
		t.Fatalf("results = %+v, want 2", resp.Results)
	}
	for _, r := range resp.Results {
		if r.Status != push.StatusError {
			t.Errorf("result %+v, want error", r)
		}
	}
	if len(ios.got) != 0 || len(android.got) != 0 {
		t.Error("neither provider should have been called for invalid platform/kind")
	}
}

func TestSendEnforcesTokenBinding(t *testing.T) {
	srv, ios, _, store := newTestServer(t, defaultCfg())
	keyA, _ := store.Issue(context.Background(), "server-a", 0)
	keyB, _ := store.Issue(context.Background(), "server-b", 0)
	h := srv.Router()

	// Server A claims the token first.
	bodyA := `{"messages":[{"platform":"ios","token":"shared-token","kind":"wake","payload":"a"}]}`
	rr := do(h, http.MethodPost, "/v1/send", bodyA, keyA)
	if rr.Code != http.StatusOK {
		t.Fatalf("A's send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var respA sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &respA)
	if len(respA.Results) != 1 || respA.Results[0].Status != push.StatusDelivered {
		t.Fatalf("A's result = %+v, want delivered", respA.Results)
	}

	// Server B tries to send to the same token: rejected, and never reaches the provider.
	bodyB := `{"messages":[{"platform":"ios","token":"shared-token","kind":"wake","payload":"b"}]}`
	rr = do(h, http.MethodPost, "/v1/send", bodyB, keyB)
	if rr.Code != http.StatusOK {
		t.Fatalf("B's send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var respB sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &respB)
	if len(respB.Results) != 1 || respB.Results[0].Status != push.StatusForbidden {
		t.Fatalf("B's result = %+v, want forbidden", respB.Results)
	}
	if len(ios.got) != 1 {
		t.Errorf("provider saw %d messages, want exactly 1 (A's, not B's)", len(ios.got))
	}
}

func TestSendRejectsOversizedBatch(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxMessages = 2
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"ios","token":"a","kind":"wake","payload":"c"},
		{"platform":"ios","token":"b","kind":"wake","payload":"c"},
		{"platform":"ios","token":"c","kind":"wake","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch = %d, want 400", rr.Code)
	}
}

func TestSendRejectsOversizedPayload(t *testing.T) {
	srv, ios, _, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "", 0)

	huge := strings.Repeat("x", maxPayloadBytes+1)
	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"` + huge + `"}]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Results) != 1 || resp.Results[0].Status != push.StatusError {
		t.Fatalf("results = %+v, want a single error result", resp.Results)
	}
	if len(ios.got) != 0 {
		t.Error("an oversized payload must never reach the provider")
	}
}

// RELAY_SEND_TIMEOUT_SECONDS=0 must mean "no deadline", matching the "0 or negative
// disables it" convention every sibling ceiling in this config already documents - not a
// context.WithTimeout(ctx, 0) that is already expired before dispatch starts, which would
// turn every send into not_attempted even though nothing was actually slow.
func TestSendTimeoutZeroMeansNoDeadline(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendTimeoutSeconds = 0
	srv, ios, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"c"}]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != push.StatusDelivered {
		t.Fatalf("results = %+v, want delivered (a zero timeout must not pre-expire the context)", resp.Results)
	}
	if len(ios.got) != 1 {
		t.Errorf("provider saw %d messages, want exactly 1", len(ios.got))
	}
}

// A call-kind message the deadline cuts off before dispatch ever attempts it must not
// permanently spend the tighter per-key call budget: the caller is told to retry a
// not_attempted message, and that retry must not be silently refused by a budget that
// still reads as spent from an attempt that never happened.
func TestRefundNotAttemptedCallsReturnsTheToken(t *testing.T) {
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := defaultCfg()
	cfg.SendConcurrency = 1
	cfg.CallSendPerMinute = 1
	cfg.CallSendBurst = 1
	sender := &slowSender{delay: time.Second} // far longer than the deadline below
	srv := New(cfg, sender, sender, store)
	const keyID = int64(1)

	// Spend the call budget's sole token exactly like the parse loop in handleSend does,
	// before dispatch ever runs.
	if !srv.callLim.Allow(strconv.FormatInt(keyID, 10)) {
		t.Fatal("setup: the call budget's first Allow should succeed")
	}

	items := []dispatchItem{
		// Occupies the sole worker slot until the deadline cancels it, so the call below
		// never gets a turn at all - a real not_attempted, not merely a slow one.
		{resultIdx: 0, sender: sender, msg: push.Message{Token: "wake-1", Kind: push.KindWake, Payload: "c"}},
		{resultIdx: 1, sender: sender, msg: push.Message{Token: "call-1", Kind: push.KindCall, Payload: "c"}},
	}
	results := make([]push.Result, len(items))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	srv.dispatch(ctx, items, results)
	if results[1].Status != push.StatusNotAttempted {
		t.Fatalf("result[1] = %+v, want not_attempted (setup precondition: the call never got a worker turn)", results[1])
	}

	srv.refundNotAttemptedCalls(keyID, items, results)

	if !srv.callLim.Allow(strconv.FormatInt(keyID, 10)) {
		t.Error("call budget was not refunded: a retry of the not_attempted call is wrongly refused")
	}
}

func TestSendRateLimitedPerKey(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendBurst = 1
	cfg.SendPerMinute = 1
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	h := srv.Router()

	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"c"}]}`
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusOK {
		t.Fatalf("first send = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second send = %d, want 429", rr.Code)
	}
}

// The worker pool must never run more sends at once than RELAY_SEND_CONCURRENCY allows,
// however many messages the batch carries.
func TestSendBoundsWorkerConcurrency(t *testing.T) {
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := defaultCfg()
	cfg.SendConcurrency = 2
	sender := &slowSender{delay: 40 * time.Millisecond}
	srv := New(cfg, sender, sender, store)
	key, _ := store.Issue(context.Background(), "", 0)

	var msgs []string
	for i := 0; i < 6; i++ {
		msgs = append(msgs, fmt.Sprintf(`{"platform":"ios","token":"t%d","kind":"wake","payload":"c"}`, i))
	}
	body := `{"messages":[` + strings.Join(msgs, ",") + `]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}

	sender.mu.Lock()
	got := sender.maxConcurrent
	sender.mu.Unlock()
	if got > cfg.SendConcurrency {
		t.Errorf("max concurrent sends = %d, want at most %d", got, cfg.SendConcurrency)
	}
	if got < cfg.SendConcurrency {
		t.Errorf("max concurrent sends = %d, want exactly %d (6 messages, delay long enough to overlap)", got, cfg.SendConcurrency)
	}
}

// A message whose turn in the worker pool has not come by the per-request deadline must
// come back as StatusNotAttempted, not left pending or silently dropped, so the caller knows
// to retry only those.
func TestDispatchMarksUnattemptedAsNotAttempted(t *testing.T) {
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := defaultCfg()
	cfg.SendConcurrency = 1
	sender := &slowSender{delay: time.Second} // far longer than the deadline below
	srv := New(cfg, sender, sender, store)

	items := []dispatchItem{
		{resultIdx: 0, sender: sender, msg: push.Message{Token: "a", Kind: push.KindWake, Payload: "c"}},
		{resultIdx: 1, sender: sender, msg: push.Message{Token: "b", Kind: push.KindWake, Payload: "c"}},
		{resultIdx: 2, sender: sender, msg: push.Message{Token: "c", Kind: push.KindWake, Payload: "c"}},
	}
	results := make([]push.Result, len(items))

	// A deadline nearer than cfg.SendTimeoutSeconds still wins: WithTimeout takes the
	// sooner of the two, which lets this test stay fast without shrinking the real config
	// default.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	srv.dispatch(ctx, items, results)

	if results[0].Status == push.StatusNotAttempted || results[0].Status == "" {
		t.Errorf("result[0] = %+v, want a real attempted outcome (the sole worker's first pick)", results[0])
	}
	for i := 1; i < len(results); i++ {
		if results[i].Status != push.StatusNotAttempted {
			t.Errorf("result[%d] = %+v, want not_attempted (never reached before the deadline)", i, results[i])
		}
		if results[i].Token != items[i].msg.Token {
			t.Errorf("result[%d].Token = %q, want %q", i, results[i].Token, items[i].msg.Token)
		}
	}
}

// Results must correlate to the request by index even though the worker pool interleaves
// both platforms and runs several sends concurrently.
func TestSendPreservesResultOrderAcrossWorkers(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendConcurrency = 4
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)

	body := `{"messages":[
		{"platform":"ios","token":"i0","kind":"wake","payload":"c"},
		{"platform":"android","token":"a0","kind":"wake","payload":"c"},
		{"platform":"ios","token":"i1","kind":"wake","payload":"c"},
		{"platform":"android","token":"a1","kind":"wake","payload":"c"},
		{"platform":"ios","token":"i2","kind":"wake","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"i0", "a0", "i1", "a1", "i2"}
	if len(resp.Results) != len(want) {
		t.Fatalf("results = %+v, want %d entries", resp.Results, len(want))
	}
	for i, tok := range want {
		if resp.Results[i].Token != tok {
			t.Errorf("result[%d].Token = %q, want %q", i, resp.Results[i].Token, tok)
		}
	}
}

func TestAdminRevokeStopsDelivery(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = "admin-secret"
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "", 0)
	k, _ := store.Verify(context.Background(), key)
	h := srv.Router()

	body := `{"messages":[{"platform":"android","token":"a","kind":"wake","payload":"c"}]}`
	// A send works before revocation.
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusOK {
		t.Fatalf("pre-revoke send = %d, want 200", rr.Code)
	}
	// Admin needs the token.
	if rr := do(h, http.MethodGet, "/admin/keys", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d, want 401", rr.Code)
	}
	// Revoke with the token.
	revokePath := "/admin/keys/" + strconv.FormatInt(k.ID, 10) + "/revoke"
	if rr := do(h, http.MethodPost, revokePath, "", "admin-secret"); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	// The key no longer sends.
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke send = %d, want 401", rr.Code)
	}
}
