// SPDX-License-Identifier: Apache-2.0

// Coverage for the 2026-08-11 review fixes: the IP admission limit runs before
// the bearer key is verified, /v1/send tolerates additive fields where
// /v1/register stays strict, and /healthz asks the database instead of
// answering a static ok.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A caller with no bearer at all must meet the admission limit before anything
// else runs: the point of the fix is that unauthenticated garbage never reaches
// the single-connection key store.
func TestSendAdmissionLimitRunsBeforeAuth(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendAdmitPerMinute = 1
	cfg.SendAdmitBurst = 2
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()

	var last int
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/send", strings.NewReader(`{}`))
		req.RemoteAddr = "203.0.113.9:1234"
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("third bearer-less send = %d, want 429 from the admission limit", last)
	}
}

func TestSendAcceptsAdditiveUnknownFields(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	h := srv.Router()
	key, err := store.Issue(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}

	body := `{"messages":[],"future_field":true}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/send", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("send with an additive field = %d, want 200; the wire contract is additive-only", rec.Code)
	}
}

func TestRegisterStillRejectsUnknownFields(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	h := srv.Router()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/register", strings.NewReader(`{"publicUrl":"x","typo":1}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("register with an unknown field = %d, want 400; its body is operator-typed", rec.Code)
	}
}

func TestHealthzReportsDegradedOnceTheStoreIsGone(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	h := srv.Router()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz with a live store = %d, want 200", rec.Code)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with a closed store = %d, want 503", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["status"] != "degraded" {
		t.Fatalf("healthz body = %q, want status degraded", rec.Body.String())
	}
}
