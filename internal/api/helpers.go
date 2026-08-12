// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// writeJSON renders v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders a JSON {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a JSON body up to maxBytes into v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// decodeJSONAdditive is decodeJSON without the unknown-field rejection, for the one body
// the home server owns both sides of: the two repos release independently under an
// additive-only wire contract, so an operator running an older relay must not lose every
// push the day the server adds a field. Registration keeps the strict decoder - its body
// is operator-typed, where an unknown field is a typo worth refusing.
func decodeJSONAdditive(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(v)
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// clientIP is the caller's address used to key per-IP rate limiting. By default it is
// always the TCP peer address: every proxy this relay documents (Caddy, Traefik, nginx)
// appends its view of the peer to X-Forwarded-For, so the leftmost entry is whatever the
// client itself put there - fully attacker-controlled - and trusting it lets one caller
// spin up an unbounded number of distinct rate-limit buckets just by varying the header.
// Only when the operator opts in with RELAY_TRUST_PROXY is the header read at all, and even
// then it is the rightmost entry that is trusted, since that is the one hop a trusted
// proxy itself appended and an external caller cannot forge.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// recoverer turns a handler panic into a 500 instead of crashing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("relay: recovered from panic: %v", rec)
				writeErr(w, http.StatusInternalServerError, "server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// tally counts delivery outcomes for logging, without touching tokens or payload content.
func tally(results []push.Result) (delivered, unregistered, forbidden, notAttempted, failed int) {
	for _, r := range results {
		switch r.Status {
		case push.StatusDelivered:
			delivered++
		case push.StatusUnregistered:
			unregistered++
		case push.StatusForbidden:
			forbidden++
		case push.StatusNotAttempted:
			notAttempted++
		default:
			failed++
		}
	}
	return
}
