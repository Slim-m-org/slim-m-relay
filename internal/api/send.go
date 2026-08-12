// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

type sendReq struct {
	Messages []sendMessage `json:"messages"`
}

// sendMessage is content-free by construction: it carries only what routes and wakes a
// device, never anything the relay could read. Payload is the home server's
// already-encrypted blob, forwarded untouched.
type sendMessage struct {
	Platform string `json:"platform"` // "ios" or "android"
	Token    string `json:"token"`
	Kind     string `json:"kind"`    // "message", "mention", "call", or "wake"
	Payload  string `json:"payload"` // opaque, already-encrypted; the relay never inspects it
}

type sendResp struct {
	Results []push.Result `json:"results"`
}

// maxPayloadBytes bounds one message's opaque payload. 4096 matches APNs' own remote
// notification payload ceiling, the tighter of the two providers' limits.
const maxPayloadBytes = 4096

// dispatchItem is one message ready to send, paired with the platform sender it must go
// through and the slot in results it belongs in, so a single bounded worker pool can drain
// both platforms' pending messages together and still scatter each outcome back into the
// caller's original order.
type dispatchItem struct {
	resultIdx int
	sender    push.Sender
	msg       push.Message
}

// handleSend forwards a batch of notifications to APNs or FCM, per message, on behalf of a
// registered server. The caller authenticates with its registration key, is rate-limited
// per key, and gets back one result per token so it can prune tokens the provider reports
// as dead. Every device token is bound to whichever key first sends to it (see
// internal/keys); a send for someone else's token is rejected rather than forwarded. The
// relay never logs tokens or payload content - only counts and the key id.
//
// Because each provider does one HTTP round trip per token, dispatch runs the batch through
// a bounded worker pool under a hard per-request deadline (both from config), so a large
// batch can neither serialize into a multi-minute request nor hang it indefinitely; whatever
// has not been attempted by the deadline comes back as push.StatusNotAttempted so the caller
// retries only those.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if !s.sendAdmitLim.Allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	plain := bearerToken(r)
	if plain == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer key")
		return
	}
	k, err := s.keys.Verify(r.Context(), plain)
	if err != nil {
		if err == keys.ErrNotFound {
			writeErr(w, http.StatusUnauthorized, "invalid or revoked key")
			return
		}
		log.Printf("relay: verify key: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if !s.sendLim.Allow(strconv.FormatInt(k.ID, 10)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var req sendReq
	if err := decodeJSONAdditive(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Messages) > s.cfg.MaxMessages {
		writeErr(w, http.StatusBadRequest, "too many messages in one request")
		return
	}

	results := make([]push.Result, 0, len(req.Messages))
	var items []dispatchItem

	for _, m := range req.Messages {
		if m.Token == "" {
			continue
		}
		if len(m.Payload) > maxPayloadBytes {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		platform, ok := parsePlatform(m.Platform)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		kind, ok := parseKind(m.Kind)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		if kind == push.KindCall && !s.callLim.Allow(strconv.FormatInt(k.ID, 10)) {
			// A call rings a device, making it the most abusable kind, so it has its own,
			// tighter per-key budget under the general send rate limit checked above.
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		retention := time.Duration(s.cfg.TokenRetentionDays) * 24 * time.Hour
		owner, err := s.keys.BindToken(r.Context(), k.ID, string(platform), m.Token, retention)
		if err != nil {
			log.Printf("relay: bind token: %v", err)
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		if owner != k.ID {
			// Harassment-hardening: this token belongs to a different registered server.
			results = append(results, push.Result{Token: m.Token, Status: push.StatusForbidden})
			continue
		}

		sender := s.android
		if platform == push.PlatformIOS {
			sender = s.ios
		}
		idx := len(results)
		results = append(results, push.Result{}) // filled in by dispatch below
		items = append(items, dispatchItem{
			resultIdx: idx,
			sender:    sender,
			msg:       push.Message{Token: m.Token, Kind: kind, Payload: m.Payload},
		})
	}

	s.dispatch(r.Context(), items, results)
	// A call-kind message that never got attempted before the deadline must not have
	// permanently spent its slice of the tighter per-key call budget: the caller is told to
	// retry a not_attempted message, and that retry must not be silently refused because an
	// attempt that never happened already paid for it.
	s.refundNotAttemptedCalls(k.ID, items, results)

	delivered, unregistered, forbidden, notAttempted, failed := tally(results)
	log.Printf("relay: send key=%d n=%d delivered=%d unregistered=%d forbidden=%d not_attempted=%d error=%d",
		k.ID, len(results), delivered, unregistered, forbidden, notAttempted, failed)
	writeJSON(w, http.StatusOK, sendResp{Results: results})
}

// dispatch drains items through a bounded worker pool (concurrency from config) under a
// hard per-request deadline (also from config), and scatters each outcome back into its
// original slot in results. Bounding concurrency caps how many provider round trips are ever
// in flight at once; the deadline bounds the total wall time regardless of batch size. A
// message whose turn has not come when the deadline fires is left as push.StatusNotAttempted
// rather than as a zero value, so the caller can tell "never tried" apart from every real
// outcome and retry only those.
//
// Once the deadline fires, the feed loop below stops handing out new work, but a worker
// already partway through an item's Send call is always let finish and report its real
// outcome rather than being raced against the same deadline and abandoned - a message whose
// turn already came deserves a real answer, not a coin-flip between that and not_attempted.
// This is safe specifically because every Sender this dispatches to must itself honour ctx:
// APNs' client and FCM's HTTP send already do via http.NewRequestWithContext, and FCM's
// oauth2 token fetch - the one call in this codebase that used to be uncancellable, since
// oauth2.TokenSource.Token() takes no context of its own - is now bounded by ctx too (see
// fcm.Sender.token). So "already started" only ever means "already respecting ctx.Done()",
// and finishing it takes microseconds past the deadline, not indefinitely.
func (s *Server) dispatch(ctx context.Context, items []dispatchItem, results []push.Result) {
	if len(items) == 0 {
		return
	}
	if s.cfg.SendTimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.cfg.SendTimeoutSeconds)*time.Second)
		defer cancel()
	}
	// Lets every push.Unconfigured.Send call below share one dedupe map, so a stub sender
	// logs its rejection at most once for this request regardless of how many messages it is
	// asked to reject one at a time.
	ctx = push.WithRequestScope(ctx)

	workers := s.cfg.SendConcurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}

	work := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				item := items[idx]
				out := item.sender.Send(ctx, []push.Message{item.msg})
				status := push.StatusError
				if len(out) > 0 {
					status = out[0].Status
				}
				results[item.resultIdx] = push.Result{Token: item.msg.Token, Status: status}
			}
		}()
	}

feed:
	for idx := range items {
		select {
		case work <- idx:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()

	// Anything the pool never got to before the deadline is still its zero value; mark it
	// not-attempted rather than leaving an empty status in the response.
	for _, item := range items {
		if results[item.resultIdx].Status == "" {
			results[item.resultIdx] = push.Result{Token: item.msg.Token, Status: push.StatusNotAttempted}
		}
	}
}

// refundNotAttemptedCalls returns the tighter per-key call budget's token for every
// call-kind message dispatch never actually attempted before the deadline. That budget is
// spent in the parse loop above, before dispatch runs, so a call the deadline later cuts off
// has already paid for an attempt that never happened; without the refund, retrying that
// same not_attempted message can be wrongly refused by a budget that still reads as spent.
func (s *Server) refundNotAttemptedCalls(keyID int64, items []dispatchItem, results []push.Result) {
	for _, item := range items {
		if item.msg.Kind == push.KindCall && results[item.resultIdx].Status == push.StatusNotAttempted {
			s.callLim.Return(strconv.FormatInt(keyID, 10))
		}
	}
}

func parsePlatform(s string) (push.Platform, bool) {
	switch push.Platform(s) {
	case push.PlatformIOS, push.PlatformAndroid:
		return push.Platform(s), true
	default:
		return "", false
	}
}

func parseKind(s string) (push.Kind, bool) {
	switch push.Kind(s) {
	case push.KindMessage, push.KindMention, push.KindCall, push.KindWake:
		return push.Kind(s), true
	default:
		return "", false
	}
}
