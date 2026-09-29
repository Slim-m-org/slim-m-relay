// SPDX-License-Identifier: Apache-2.0

// Package apns forwards content-free pushes to Apple Push Notification service (APNs) for
// iOS devices, using token-based (.p8 key) authentication via github.com/sideshow/apns2,
// the standard Go APNs client.
//
// Every notification it sends is content-free. Kinds that should surface something on a
// locked device carry a fixed generic alert ("New message"), identical for every sender and
// channel, so APNs and its logs still never see plaintext; the rest are silent
// content-available wakes. The home server's already-encrypted payload and the coarse kind travel as
// custom top-level fields; the device wakes and decrypts locally to decide how, or whether,
// to surface a notification. push.KindCall is the one exception to "background wake": it
// goes to the app's separate PushKit topic (the bundle id plus ".voip") as a
// PushTypeVOIP/high-priority push, so a call rings promptly; every other kind stays a
// low-priority PushTypeBackground wake on the plain bundle id topic.
package apns

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// client is the slice of *apns2.Client this package depends on, named as an interface so
// tests can substitute a fake gateway.
type client interface {
	PushWithContext(ctx apns2.Context, n *apns2.Notification) (*apns2.Response, error)
}

// voipTopicSuffix is Apple's fixed convention for a VoIP-capable app's PushKit topic: the
// bundle id with ".voip" appended. Deriving it from the one configured bundle id at send
// time, rather than taking a second operator-supplied value, means the two topics can never
// drift apart.
const voipTopicSuffix = ".voip"

// genericAlert maps the kinds that should surface something on a locked device to the
// fixed text shown for them. The text is deliberately identical for every sender, channel
// and message: it names nothing, so it is still content-free. A kind absent from this map
// stays a silent background wake, which is what "wake" is for.
var genericAlert = map[push.Kind]string{
	push.KindMessage:  "New message",
	push.KindMention:  "You were mentioned",
	push.KindSecurity: "New sign-in to your account",
}

// Sender holds the APNs token client and posts notifications to the gateway.
type Sender struct {
	client   client
	bundleID string
}

// Config is the token-based (.p8) credential set required to reach APNs.
type Config struct {
	// KeyPath is the path to the .p8 private key downloaded from the Apple Developer portal.
	KeyPath string
	// KeyID is the 10-character key identifier for that .p8 key.
	KeyID string
	// TeamID is the 10-character Apple Developer Team ID.
	TeamID string
	// BundleID is the app's bundle identifier; used as the APNs topic.
	BundleID string
	// Production selects APNs' production gateway. false uses the sandbox gateway, which
	// is what devices running a debug/development build register against.
	Production bool
}

// New builds a Sender from a .p8 token key. Callers only reach this once all four
// credential fields are non-empty (see cmd/relay); an incomplete or absent configuration is
// the caller's decision to route to push.Unconfigured instead, not an error this
// constructor raises. Once here, a credential that is present but unusable (a bad .p8 file,
// for instance) is a real misconfiguration and is returned as an error.
func New(cfg Config) (*Sender, error) {
	authKey, err := token.AuthKeyFromFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("apns: read .p8 key: %w", err)
	}
	tok := &token.Token{AuthKey: authKey, KeyID: cfg.KeyID, TeamID: cfg.TeamID}
	c := apns2.NewTokenClient(tok)
	if cfg.Production {
		c = c.Production()
	} else {
		c = c.Development()
	}
	return &Sender{client: c, bundleID: cfg.BundleID}, nil
}

// Send posts every message to APNs and returns one push.Result per input in the same
// order. It never logs the token or the payload; the caller decides what to record from the
// returned statuses.
func (s *Sender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	results := make([]push.Result, len(msgs))
	for i, m := range msgs {
		results[i] = push.Result{Token: m.Token, Status: s.sendOne(ctx, m)}
	}
	return results
}

func (s *Sender) sendOne(ctx context.Context, m push.Message) push.Status {
	p := payload.NewPayload().MutableContent()
	p.Custom("kind", string(m.Kind))
	p.Custom("payload", m.Payload)

	n := &apns2.Notification{
		DeviceToken: m.Token,
		Topic:       s.bundleID,
		PushType:    apns2.PushTypeBackground,
		// A content-available-only push must use low priority; APNs rejects high priority
		// (10) unless the payload also triggers a user-visible alert, sound, or badge.
		Priority: apns2.PriorityLow,
		Payload:  p,
	}
	if alert, ok := genericAlert[m.Kind]; ok {
		// A fixed string, identical for every message from every sender, so APNs still
		// learns nothing beyond the coarse kind it already sees. Without an alert the
		// push is silent, and a device with no Notification Service Extension yet would
		// show the user nothing at all. mutable-content stays set so that extension can
		// later decrypt the payload and replace this placeholder in place.
		p.Alert(alert).Sound("default")
		n.PushType = apns2.PushTypeAlert
		n.Priority = apns2.PriorityHigh
	} else {
		p.ContentAvailable()
	}
	if m.Kind == push.KindCall {
		// A call must ring the device promptly, so it takes PushKit's separate VoIP topic,
		// push type, and high priority instead of the plain background wake every other kind
		// uses.
		n.Topic = s.bundleID + voipTopicSuffix
		n.PushType = apns2.PushTypeVOIP
		n.Priority = apns2.PriorityHigh
	}
	if m.Kind.IsCallSignal() {
		// A ring held past its own timeout would ring for a call that is already over.
		n.Expiration = time.Now().Add(push.CallSignalTTL)
	}
	resp, err := s.client.PushWithContext(ctx, n)
	if err != nil {
		return push.StatusError
	}
	if resp.Sent() {
		return push.StatusDelivered
	}
	switch resp.Reason {
	case apns2.ReasonUnregistered, apns2.ReasonBadDeviceToken, apns2.ReasonExpiredToken:
		return push.StatusUnregistered
	case apns2.ReasonExpiredProviderToken, apns2.ReasonInvalidProviderToken,
		apns2.ReasonMissingProviderToken, apns2.ReasonForbidden:
		// Whole-pipeline credential death, not per-token noise: every send through this
		// relay fails until the operator fixes the APNs key, so it must not log like a
		// stale device token (which is to say, not at all).
		log.Printf("relay: apns rejected the provider credential (reason=%s); every ios send will fail until the key is fixed", resp.Reason)
		return push.StatusError
	default:
		return push.StatusError
	}
}
