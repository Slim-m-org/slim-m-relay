// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/nc1107/slim-m-relay/internal/keys"
)

// adminFailuresPerMinute and adminFailureBurst throttle failed admin attempts per client; the token's
// 32-character floor is what stops guessing, and only a failure spends, so a correct token is never refused.
const (
	adminFailuresPerMinute = 10
	adminFailureBurst      = 5
)

// requireAdmin guards the admin handlers with a constant-time comparison against the
// configured admin token, supplied as "Authorization: Bearer <token>".
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	want := []byte(s.cfg.AdminToken)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(bearerToken(r))
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			next(w, r)
			return
		}
		if !s.adminLim.Allow(s.clientIP(r)) {
			writeRateLimited(w, s.adminLim, errRateLimited)
			return
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	}
}

// handleAdminListKeys lists every issued key (metadata only; never the secret or its hash).
func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.keys.List(r.Context())
	if err != nil {
		log.Printf("relay: list keys: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if list == nil {
		list = []keys.Key{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": list})
}

// handleAdminRevokeKey revokes a key by id so a misbehaving server can be cut off.
func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.keys.Revoke(r.Context(), id); err != nil {
		if err == keys.ErrNotFound {
			writeErr(w, http.StatusNotFound, "no such key")
			return
		}
		log.Printf("relay: revoke key: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxPurgeAgeDays keeps the age in days from overflowing a time.Duration.
const maxPurgeAgeDays = 36500

// handleAdminPurgeUnused deletes keys that never bound a device token and are older than older_than_days,
// freeing registration slots squatted by keys nobody uses. The age is required and at least
// a day, so a call can never wipe keys a server has only just been given.
func (s *Server) handleAdminPurgeUnused(w http.ResponseWriter, r *http.Request) {
	days, err := strconv.Atoi(r.URL.Query().Get("older_than_days"))
	if err != nil || days < 1 || days > maxPurgeAgeDays {
		writeErr(w, http.StatusBadRequest, "older_than_days must be a whole number of days, 1 or more")
		return
	}
	n, err := s.keys.PurgeUnused(r.Context(), time.Duration(days)*24*time.Hour)
	if err != nil {
		log.Printf("relay: purge unused keys: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	log.Printf("relay: purged %d keys with no bound token and older than %d days", n, days)
	writeJSON(w, http.StatusOK, map[string]int64{"purged": n})
}
