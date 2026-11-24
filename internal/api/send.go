// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
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
	Kind     string `json:"kind"`    // see parseKind for the accepted names
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
	platform  push.Platform
	// token is the token exactly as the caller sent it, which is what its result must echo
	// so the caller can prune by it; msg.Token is the canonical form that goes to the provider.
	token  string
	sender push.Sender
	msg    push.Message
}

// pendingMessage is a message that passed validation and waits on its token binding. token
// is the canonical form that goes to the provider, sent is the message as the caller wrote it.
type pendingMessage struct {
	resultIdx int
	platform  push.Platform
	token     string
	kind      push.Kind
	sent      sendMessage
}

// handleSend forwards a batch of notifications to APNs or FCM, per message, on behalf of a
// registered server. The caller authenticates with its registration key, is rate-limited
// per key, and gets back one result per token so it can prune tokens the provider reports
// as dead. Every device token is bound per key (see internal/keys): any key may bind a
// token it knows, until MaxKeysPerToken keys hold it, so a token's secrecy is the only gate
// on pushing to it. The relay never logs tokens or payload content - only counts and the key id.
//
// Because each provider does one HTTP round trip per token, dispatch runs the batch through
// a bounded worker pool under a hard per-request deadline (both from config), so a large
// batch can neither serialize into a multi-minute request nor hang it indefinitely; whatever
// has not been attempted by the deadline comes back as push.StatusNotAttempted so the caller
// retries only those.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if !s.sendAdmitLim.Allow(s.clientIP(r)) {
		writeRateLimited(w, s.sendAdmitLim, errRateLimited)
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
		writeRateLimited(w, s.sendLim, errRateLimited)
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

	charged := countTokened(req.Messages)
	if !s.chargeMessages(w, k.ID, charged) {
		return
	}

	ctx, cancel := s.sendContext(r.Context())
	defer cancel()

	results := make([]push.Result, 0, len(req.Messages))
	var pending []pendingMessage
	var refs []keys.TokenRef

	for _, m := range req.Messages {
		if m.Token == "" {
			continue
		}
		platform, ok := parsePlatform(m.Platform)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRejected})
			continue
		}
		token, ok := canonicalToken(platform, m.Token)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRejected})
			continue
		}
		if len(m.Payload) > maxPayloadBytes {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRejected})
			continue
		}
		kind, ok := parseKind(m.Kind)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRejected})
			continue
		}
		if kind == push.KindCall && !s.callLim.Allow(strconv.FormatInt(k.ID, 10)) {
			// A call rings a device, making it the most abusable kind, so it has its own,
			// tighter per-key budget under the general send rate limit checked above.
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRetry})
			continue
		}
		pending = append(pending, pendingMessage{
			resultIdx: len(results), platform: platform, token: token, kind: kind, sent: m,
		})
		results = append(results, push.Result{}) // filled in once the binding is decided
		refs = append(refs, keys.TokenRef{Platform: string(platform), Token: token})
	}

	outcomes, err := s.keys.BindTokens(ctx, k.ID, refs, s.bindLimits())
	if errors.Is(err, keys.ErrNotFound) {
		// Revoked after Verify; nothing was bound or dispatched, so refuse the whole batch.
		writeErr(w, http.StatusUnauthorized, "invalid or revoked key")
		return
	}
	if err != nil {
		log.Printf("relay: bind tokens: %v", err)
		outcomes = make([]error, len(refs))
		for i := range outcomes {
			outcomes[i] = err
		}
	}

	var items []dispatchItem
	for i, p := range pending {
		switch bindErr := outcomes[i]; {
		case bindErr == nil:
			sender := s.android
			if p.platform == push.PlatformIOS {
				sender = s.ios
			}
			items = append(items, dispatchItem{
				resultIdx: p.resultIdx,
				platform:  p.platform,
				token:     p.sent.Token,
				sender:    sender,
				msg:       push.Message{Token: p.token, Kind: p.kind, Payload: p.sent.Payload},
			})
		case errors.Is(bindErr, keys.ErrTokenKeyLimit):
			// Too many other servers already hold this token; refused like a stranger's.
			results[p.resultIdx] = push.Result{Token: p.sent.Token, Status: push.StatusForbidden}
		case errors.Is(bindErr, keys.ErrTokenLimit), errors.Is(bindErr, keys.ErrRelayTokenLimit):
			results[p.resultIdx] = push.Result{Token: p.sent.Token, Status: push.StatusRejected}
		default:
			results[p.resultIdx] = push.Result{Token: p.sent.Token, Status: push.StatusRetry}
		}
	}

	s.dispatch(ctx, items, results)
	s.unbindDead(ctx, k.ID, items, results)
	// A call-kind message that never got attempted before the deadline must not have
	// permanently spent its slice of the tighter per-key call budget: the caller is told to
	// retry a not_attempted message, and that retry must not be silently refused because an
	// attempt that never happened already paid for it.
	s.refundNotAttemptedCalls(k.ID, items, results)
	s.refundMessages(k.ID, charged, items, results)

	n := tally(results)
	log.Printf("relay: send key=%d n=%d delivered=%d unregistered=%d forbidden=%d not_attempted=%d rejected=%d retry=%d",
		k.ID, len(results), n[push.StatusDelivered], n[push.StatusUnregistered], n[push.StatusForbidden],
		n[push.StatusNotAttempted], n[push.StatusRejected], n[push.StatusRetry])
	writeJSON(w, http.StatusOK, sendResp{Results: results})
}

func countTokened(msgs []sendMessage) int {
	n := 0
	for _, m := range msgs {
		if m.Token != "" {
			n++
		}
	}
	return n
}

// unbindDead drops the bindings of tokens a provider reported unregistered, so tokens that
// never existed do not count against the relay-wide cap until the retention prune.
func (s *Server) unbindDead(ctx context.Context, keyID int64, items []dispatchItem, results []push.Result) {
	var dead []keys.TokenRef
	for _, item := range items {
		if results[item.resultIdx].Status == push.StatusUnregistered {
			dead = append(dead, keys.TokenRef{Platform: string(item.platform), Token: item.msg.Token})
		}
	}
	if err := s.keys.Unbind(context.WithoutCancel(ctx), keyID, dead); err != nil {
		log.Printf("relay: unbind dead tokens: %v", err)
	}
}

// chargeMessages spends n units of the key's per-message budget and of the relay-wide one,
// answering 429 itself when either is empty. The relay-wide charge is returned if the key's
// own budget refuses.
func (s *Server) chargeMessages(w http.ResponseWriter, keyID int64, n int) bool {
	if n == 0 {
		return true
	}
	id := strconv.FormatInt(keyID, 10)
	if s.msgLim != nil && !s.msgLim.AllowN(id, n) {
		writeRateLimitedN(w, s.msgLim, id, n, errRateLimited)
		return false
	}
	if s.providerLim != nil && !s.providerLim.AllowN(providerBudgetKey, n) {
		if s.msgLim != nil {
			s.msgLim.ReturnN(id, n)
		}
		writeRateLimitedN(w, s.providerLim, providerBudgetKey, n, "relay is busy, retry later")
		return false
	}
	return true
}

// providerBudgetKey is the single bucket the relay-wide budget draws from.
const providerBudgetKey = "relay"

// refundMessages gives back the units of every message that never reached a provider: invalid
// ones, refused bindings and anything the deadline cut, so only attempted sends stay charged.
func (s *Server) refundMessages(keyID int64, charged int, items []dispatchItem, results []push.Result) {
	attempted := 0
	for _, item := range items {
		if results[item.resultIdx].Status != push.StatusNotAttempted {
			attempted++
		}
	}
	unused := charged - attempted
	if s.msgLim != nil {
		s.msgLim.ReturnN(strconv.FormatInt(keyID, 10), unused)
	}
	if s.providerLim != nil {
		s.providerLim.ReturnN(providerBudgetKey, unused)
	}
}

// sendContext bounds one request's token binding and provider dispatch by the configured
// deadline, so the one budget covers everything the caller waits on. A deadline of zero or
// less leaves ctx unbounded.
func (s *Server) sendContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.cfg.SendTimeoutSeconds <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Duration(s.cfg.SendTimeoutSeconds)*time.Second)
}

// bindLimits is the token-binding policy from config.
func (s *Server) bindLimits() keys.BindLimits {
	day := 24 * time.Hour
	return keys.BindLimits{
		Retention:       time.Duration(s.cfg.TokenRetentionDays) * day,
		MaxPerKey:       s.cfg.MaxTokensPerKey,
		MaxTotal:        s.cfg.MaxTokensTotal,
		MaxKeysPerToken: s.cfg.MaxKeysPerToken,
		BindingIdle:     time.Duration(s.cfg.BindingIdleDays) * day,
	}
}

// dispatch drains items through a bounded worker pool (concurrency from config) under the
// request's deadline (see sendContext), and scatters each outcome back into its original
// slot in results. Bounding concurrency caps how many provider round trips are ever
// in flight at once; the deadline bounds the total wall time regardless of batch size. A
// message whose turn has not come when the deadline fires is left as push.StatusNotAttempted
// rather than as a zero value, so the caller can tell "never tried" apart from every real
// outcome and retry only those.
//
// Once the deadline fires, the feed loop stops handing out new work and a worker skips any
// item it picked up too late. Every Sender honours ctx (APNs and FCM through
// http.NewRequestWithContext, FCM's token fetch through its gate), so a send in flight at the
// deadline is cut and returns promptly. A send that comes back retry after the deadline never
// got a provider answer, so it is reported as not_attempted like an item that was never sent.
func (s *Server) dispatch(ctx context.Context, items []dispatchItem, results []push.Result) {
	if len(items) == 0 {
		return
	}
	// Lets every sender share one dedupe map (see push.LogOncePerRequest), so a failure every
	// message hits is logged once for this request, however many are sent one at a time.
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
				if ctx.Err() != nil {
					results[item.resultIdx] = push.Result{Token: item.token, Status: push.StatusNotAttempted}
					continue
				}
				out := item.sender.Send(ctx, []push.Message{item.msg})
				status := push.StatusRetry
				if len(out) > 0 {
					status = out[0].Status
				}
				if status == push.StatusRetry && ctx.Err() != nil {
					status = push.StatusNotAttempted
				}
				results[item.resultIdx] = push.Result{Token: item.token, Status: status}
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
			results[item.resultIdx] = push.Result{Token: item.token, Status: push.StatusNotAttempted}
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
	case push.KindMessage, push.KindMention, push.KindCall, push.KindCallEnd, push.KindSecurity, push.KindWake,
		push.KindVoice, push.KindAdminAlert:
		return push.Kind(s), true
	default:
		return "", false
	}
}
