// SPDX-License-Identifier: Apache-2.0

// Package api wires the relay's HTTP endpoints: self-serve key registration, the
// authenticated send fan-out that dispatches by platform to APNs or FCM, a health check,
// and a token-gated admin surface.
package api

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
	"github.com/nc1107/slim-m-relay/internal/ratelimit"
)

// Server holds dependencies shared by all handlers.
type Server struct {
	cfg         config.Config
	ios         push.Sender // APNs
	android     push.Sender // FCM
	keys        *keys.Store
	registerLim *ratelimit.Limiter
	// sendAdmitLim is IP-keyed and checked before the bearer key is verified, so an
	// unauthenticated flood cannot serialize the single-connection key store; sendLim is
	// the per-key budget behind it.
	sendAdmitLim *ratelimit.Limiter
	sendLim      *ratelimit.Limiter
	// callLim is a tighter, separate per-key budget for "call" kind messages specifically -
	// a call rings a device, making it the most abusable kind - on top of sendLim's general
	// per-key fan-out budget.
	callLim *ratelimit.Limiter
	// msgLim charges one unit per message to the sending key, and providerLim one unit per
	// message across every key; either is nil when its budget is disabled.
	msgLim      *ratelimit.Limiter
	providerLim *ratelimit.Limiter
	health      healthCache
	// adminLim is IP-keyed and charged only for admin requests that fail authentication.
	adminLim *ratelimit.Limiter
}

// New constructs a Server. ios and android are the platform senders /v1/send dispatches to
// by each message's declared platform; either may be a push.Unconfigured stub when the
// relay was started without that platform's credentials.
func New(cfg config.Config, ios, android push.Sender, store *keys.Store) *Server {
	srv := &Server{
		cfg:          cfg,
		ios:          ios,
		android:      android,
		keys:         store,
		registerLim:  ratelimit.New(float64(cfg.RegisterPerHour)/60.0, cfg.RegisterBurst),
		sendAdmitLim: ratelimit.New(float64(cfg.SendAdmitPerMinute), cfg.SendAdmitBurst),
		sendLim:      ratelimit.New(float64(cfg.SendPerMinute), cfg.SendBurst),
		callLim:      ratelimit.New(float64(cfg.CallSendPerMinute), cfg.CallSendBurst),
		adminLim:     ratelimit.New(adminFailuresPerMinute, adminFailureBurst),
		msgLim:       optionalLimiter(cfg.SendMessagesPerMinute, cfg.SendMessagesBurst),
		providerLim:  optionalLimiter(cfg.ProviderCallsPerMinute, cfg.ProviderCallsBurst),
	}
	srv.health.ping = store.Ping
	return srv
}

// optionalLimiter is nil unless both numbers are positive, so a zero value means no budget.
func optionalLimiter(perMinute, burst int) *ratelimit.Limiter {
	if perMinute <= 0 || burst <= 0 {
		return nil
	}
	return ratelimit.New(float64(perMinute), burst)
}

// Router builds the HTTP handler. Routing uses net/http's method+path patterns (Go 1.22+),
// keeping the relay free of a router dependency.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("POST /v1/send", s.handleSend)

	// Admin is only mounted when a long enough token is configured, and every request must carry it.
	if s.cfg.AdminEnabled() {
		mux.HandleFunc("GET /admin/keys", s.requireAdmin(s.handleAdminListKeys))
		mux.HandleFunc("POST /admin/keys/{id}/revoke", s.requireAdmin(s.handleAdminRevokeKey))
		mux.HandleFunc("POST /admin/keys/purge-unused", s.requireAdmin(s.handleAdminPurgeUnused))
	}
	return recoverer(mux)
}

// healthTTL is how long a health answer is reused, so a flood of probes costs the single
// database connection one query per interval instead of one per request.
const healthTTL = 2 * time.Second

type healthCache struct {
	mu    sync.Mutex
	ping  func(context.Context) error
	err   error
	until time.Time
}

// healthPingTimeout bounds one ping, which runs detached from the caller that triggered it.
const healthPingTimeout = 3 * time.Second

func (h *healthCache) check(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if now := time.Now(); now.Before(h.until) {
		return h.err
	}
	// Detached, so one prober hanging up cannot cache a cancellation as the answer for everyone.
	pingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthPingTimeout)
	defer cancel()
	h.err = h.ping(pingCtx)
	h.until = time.Now().Add(healthTTL)
	return h.err
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// A static ok kept reading green while the key store was unreadable and every
	// register and verify failed; asking the database is what makes this a health check.
	if err := s.health.check(r.Context()); err != nil {
		log.Printf("relay: health: key store unreachable: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
