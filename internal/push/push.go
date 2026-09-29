// SPDX-License-Identifier: Apache-2.0

// Package push defines the vocabulary the relay's two provider clients (internal/fcm and
// internal/apns) share, so /v1/send can dispatch a message to whichever platform it
// declares through one interface, without either provider package importing the other or
// the API package importing both concrete types.
package push

import (
	"context"
	"log"
	"sync"
	"time"
)

// Platform selects which provider a message is forwarded through.
type Platform string

const (
	// PlatformIOS routes a message to Apple Push Notification service.
	PlatformIOS Platform = "ios"
	// PlatformAndroid routes a message to Firebase Cloud Messaging.
	PlatformAndroid Platform = "android"
)

// Kind is the coarse, content-free notification category the home server declares. The
// relay never looks inside Payload, so Kind is the only signal it forwards about what
// happened - just enough for a device to decide how urgently to wake and what to fetch.
type Kind string

const (
	KindMessage Kind = "message"
	KindMention Kind = "mention"
	KindCall    Kind = "call"
	KindWake    Kind = "wake"
	// KindCallEnd tells a device a ring it may still be showing has ended, so it can stop.
	KindCallEnd Kind = "call_end"
	// KindSecurity is an account security alert, such as a sign-in from a new device.
	KindSecurity Kind = "security"
)

// CallSignalTTL bounds how long a provider may hold a call or call_end push for an
// unreachable device; it matches the home server's ring timeout, past which the ring is over.
const CallSignalTTL = 30 * time.Second

// IsCallSignal reports whether a push only means anything while its ring is live.
func (k Kind) IsCallSignal() bool { return k == KindCall || k == KindCallEnd }

// Message is one push bound for one device token. Payload is an opaque blob the home
// server already encrypted before it ever reached the relay; the relay forwards it
// untouched, never decrypts it, and never logs it.
type Message struct {
	Token   string
	Kind    Kind
	Payload string
}

// Status is the delivery outcome for one token.
type Status string

const (
	// StatusDelivered means the provider accepted the message.
	StatusDelivered Status = "delivered"
	// StatusUnregistered means the provider reports the token as no longer valid; the
	// caller should delete it from its own store.
	StatusUnregistered Status = "unregistered"
	// StatusForbidden means the token is bound to a different key (see internal/keys) and
	// this send was refused, so one self-hosted server cannot harass another's devices.
	StatusForbidden Status = "forbidden"
	// StatusError means the send failed for some other reason and may be worth a retry.
	StatusError Status = "error"
	// StatusNotAttempted means the request's per-request deadline was reached before this
	// message's turn in the worker pool; the provider was never contacted. The caller should
	// retry only these, not the whole batch, since everything else already has a real outcome.
	StatusNotAttempted Status = "not_attempted"
)

// Result pairs an input token with its delivery outcome.
type Result struct {
	Token  string `json:"token"`
	Status Status `json:"status"`
}

// Sender is implemented by both internal/fcm and internal/apns, so the API layer can
// dispatch a send by platform through one interface.
type Sender interface {
	Send(ctx context.Context, msgs []Message) []Result
}

// Unconfigured returns a Sender that rejects every message with StatusError, logging why
// at most once per request (see WithRequestScope). main wires this in for whichever
// platform is missing its credentials, so the relay can start and serve every other
// endpoint - registration, sending on the other platform, admin, health - without secrets
// it was never given.
func Unconfigured(platform string) Sender { return unconfigured{platform: platform} }

type unconfigured struct{ platform string }

// requestScopeKey is the context key WithRequestScope stores its dedupe map under.
type requestScopeKey struct{}

// WithRequestScope returns a context that lets every Unconfigured.Send call made while
// handling one /v1/send request share a single dedupe map, so a stub sender logs its
// rejection at most once per request no matter how many messages it is asked to reject.
// dispatch calls Send once per message rather than once per batch, so without this a large
// batch against an unconfigured provider - a supported configuration, since a relay started
// without one platform's credentials is explicitly non-fatal - writes one log line per
// token: attacker-driven disk amplification against an otherwise ordinary deployment.
func WithRequestScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestScopeKey{}, &sync.Map{})
}

func (u unconfigured) Send(ctx context.Context, msgs []Message) []Result {
	if len(msgs) > 0 {
		u.logRejection(ctx)
	}
	out := make([]Result, len(msgs))
	for i, m := range msgs {
		out[i] = Result{Token: m.Token, Status: StatusError}
	}
	return out
}

// logRejection logs that this platform is unconfigured at most once per request scope (see
// WithRequestScope), keyed by platform so an iOS and an Android rejection in the same
// request each still get their own line. A call made outside any request scope - direct use
// in a test, say - logs every time, matching the old unconditional behaviour.
func (u unconfigured) logRejection(ctx context.Context) {
	scope, ok := ctx.Value(requestScopeKey{}).(*sync.Map)
	if !ok {
		log.Printf("relay: %s not configured; rejecting message(s)", u.platform)
		return
	}
	if _, alreadyLogged := scope.LoadOrStore(u.platform, struct{}{}); !alreadyLogged {
		log.Printf("relay: %s not configured; rejecting message(s) for this request", u.platform)
	}
}
