// SPDX-License-Identifier: Apache-2.0

// Package config loads the relay's runtime settings from the environment, so the service
// stays a single self-contained binary that is easy to run under Docker.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// DefaultSendTimeoutSeconds is the send deadline when RELAY_SEND_TIMEOUT_SECONDS is unset.
// It stays under the 10 seconds slim-m's server waits for a send (RELAY_TIMEOUT in
// slimm-server's push/relay.rs), so a slow provider still gets the server per-token answers,
// with not_attempted for what the deadline cut, instead of a request it gave up on.
const DefaultSendTimeoutSeconds = 8

// writeHeadroom is what the HTTP write timeout allows beyond the send deadline, for reading
// the body, binding tokens and writing the response.
const writeHeadroom = 30 * time.Second

// MinAdminTokenChars is the shortest RELAY_ADMIN_TOKEN the admin endpoints will run with,
// the same floor slim-m applies to its own listener secret.
const MinAdminTokenChars = 32

// Config holds all runtime configuration for the relay.
type Config struct {
	// Port is the TCP port the relay listens on.
	Port int
	// DBPath is the SQLite file that stores hashed keys and device-token bindings.
	DBPath string
	// AdminToken guards the /admin endpoints (list and revoke keys). Empty, or shorter than
	// MinAdminTokenChars, disables them.
	AdminToken string

	// FCMCredentialsFile points to the Firebase service-account JSON used to send Android
	// pushes. Empty is not fatal: Android sends fail clearly instead of the relay refusing
	// to start. A path that is set but unreadable is.
	FCMCredentialsFile string

	// APNsKeyPath, APNsKeyID, APNsTeamID and APNsBundleID are the token-based (.p8)
	// credentials used to send iOS pushes. All four are required together; if any is
	// empty, iOS sends fail clearly instead of the relay refusing to start.
	APNsKeyPath  string
	APNsKeyID    string
	APNsTeamID   string
	APNsBundleID string
	// APNsProduction selects APNs' production gateway. false uses the sandbox gateway,
	// which is what devices running a debug/development build register against.
	APNsProduction bool

	// TrustProxy controls whether clientIP reads X-Forwarded-For at all. Every hop a proxy
	// like Caddy, Traefik, or nginx sets that header at is *appended* to it, so the leftmost
	// entry is always whatever the client itself sent - fully attacker-controlled - and only
	// the rightmost entry is the one hop an external caller cannot forge (the trusted proxy's
	// own view of the peer). False (the default) ignores the header entirely and uses the TCP
	// peer address, which is correct with no proxy in front and safe-by-default behind one
	// that strips or ignores incoming X-Forwarded-For. Enabling this without a real proxy
	// that sets X-Forwarded-For in front of the relay makes every IP-keyed limit trivially
	// spoofable by any caller who sets the header itself.
	TrustProxy bool
	// TrustProxyHops is how many proxies sit in front of the relay when TrustProxy is on:
	// the client address is the entry that many places from the right of X-Forwarded-For.
	TrustProxyHops int

	// RegisterPerHour and RegisterBurst bound how often one IP may mint new keys.
	RegisterPerHour int
	RegisterBurst   int
	// MaxRegistrations is the total number of live keys the relay holds, across every IP
	// (a revoked key frees its slot), so /v1/register cannot be used to grow the key
	// table without bound. Zero or negative disables the ceiling.
	MaxRegistrations int
	// SendAdmitPerMinute and SendAdmitBurst bound how often one IP may reach /v1/send at
	// all, checked before the bearer key is looked up: the key store is a single-connection
	// SQLite handle, so unauthenticated garbage tokens would otherwise serialize every
	// legitimate Verify behind their own lookups. Sized well above any honest server's
	// send rate so only a flood ever meets it.
	SendAdmitPerMinute int
	SendAdmitBurst     int
	// SendPerMinute and SendBurst bound how often one key may fan out notifications.
	SendPerMinute int
	SendBurst     int
	// CallSendPerMinute and CallSendBurst are a tighter, separate cap on one key's "call"
	// kind pushes specifically: a call rings a device, making it the most abusable kind, so
	// it gets its own ceiling under the general SendPerMinute/SendBurst budget.
	CallSendPerMinute int
	CallSendBurst     int
	// SendMessagesPerMinute and SendMessagesBurst bound how many messages one key may have
	// dispatched, charged per message rather than per request, since every message is a
	// provider call on credentials all deployments share.
	SendMessagesPerMinute int
	SendMessagesBurst     int
	// ProviderCallsPerMinute and ProviderCallsBurst are the relay-wide budget on messages
	// across every key, kept under the FCM project quota. Zero or negative disables it.
	ProviderCallsPerMinute int
	ProviderCallsBurst     int
	// MaxMessages caps how many device tokens a single /v1/send request may carry.
	MaxMessages int
	// SendConcurrency bounds how many provider sends run at once for one /v1/send request,
	// since each is its own HTTP round trip to APNs or FCM.
	SendConcurrency int
	// SendTimeoutSeconds is the hard wall-clock deadline for one /v1/send request's provider
	// dispatch and the token binding before it. A message whose turn has not come by then is
	// returned as "not_attempted" instead of holding the request open. Zero or negative
	// disables the deadline entirely, matching the "0 or negative disables it" convention the
	// other ceilings in this struct already use, rather than the instantly-expired context a
	// literal zero-second timeout would otherwise produce. HTTPWriteTimeout follows it.
	SendTimeoutSeconds int

	// TokenRetentionDays bounds how long a device-token binding may go untouched before it
	// is pruned from the store. Every send touches the token it targets, so an actively used
	// token's clock keeps resetting; only a token nobody has sent to within the window - most
	// often because the provider already reported it unregistered and the caller stopped
	// sending, but also reachable by an attacker registering a key and sending to arbitrary
	// unseen tokens - is ever removed. Zero or negative disables pruning, leaving the tokens
	// table to grow without bound.
	TokenRetentionDays int

	// MaxTokensPerKey caps how many device-token bindings one key may hold, so a registered
	// key cannot grow the store without bound. A real deployment binds roughly one token per
	// device of its members. Zero or negative disables the cap.
	MaxTokensPerKey int
	// MaxTokensTotal caps token bindings across the whole relay; a new binding past it comes
	// back as rejected. Zero or negative disables the cap.
	MaxTokensTotal int
	// MaxKeysPerToken caps how many distinct keys may deliver to one device token, which is
	// what lets a phone signed in to several servers receive pushes from each. A key past it
	// gets `forbidden` unless a binding on that token has been idle for BindingIdleDays.
	MaxKeysPerToken int
	// BindingIdleDays is how long a binding on a full token must be unused before a new key
	// may replace it.
	BindingIdleDays int
}

// Load reads configuration from the environment, applying defaults that suit a single
// maintainer-run relay. A variable that is set but cannot be parsed is an error naming it,
// never a silent fallback to the default: RELAY_TRUST_PROXY=yes quietly meaning false
// would key every client on the proxy's address.
func Load() (Config, error) {
	p := &parser{}
	cfg := Config{
		Port:                   p.int("RELAY_PORT", 8090),
		DBPath:                 getenv("RELAY_DB_PATH", "/data/relay.db"),
		AdminToken:             getenv("RELAY_ADMIN_TOKEN", ""),
		FCMCredentialsFile:     getenv("RELAY_FCM_CREDENTIALS_FILE", ""),
		APNsKeyPath:            getenv("RELAY_APNS_KEY_PATH", ""),
		APNsKeyID:              getenv("RELAY_APNS_KEY_ID", ""),
		APNsTeamID:             getenv("RELAY_APNS_TEAM_ID", ""),
		APNsBundleID:           getenv("RELAY_APNS_BUNDLE_ID", ""),
		APNsProduction:         p.bool("RELAY_APNS_PRODUCTION", true),
		TrustProxy:             p.bool("RELAY_TRUST_PROXY", false),
		TrustProxyHops:         p.int("RELAY_TRUST_PROXY_HOPS", 1),
		RegisterPerHour:        p.int("RELAY_REGISTER_PER_HOUR", 5),
		RegisterBurst:          p.int("RELAY_REGISTER_BURST", 3),
		MaxRegistrations:       p.int("RELAY_MAX_REGISTRATIONS", 10000),
		SendAdmitPerMinute:     p.int("RELAY_SEND_ADMIT_PER_MINUTE", 600),
		SendAdmitBurst:         p.int("RELAY_SEND_ADMIT_BURST", 120),
		SendPerMinute:          p.int("RELAY_SEND_PER_MINUTE", 120),
		SendBurst:              p.int("RELAY_SEND_BURST", 60),
		CallSendPerMinute:      p.int("RELAY_CALL_SEND_PER_MINUTE", 10),
		CallSendBurst:          p.int("RELAY_CALL_SEND_BURST", 5),
		SendMessagesPerMinute:  p.int("RELAY_SEND_MESSAGES_PER_MINUTE", 6000),
		SendMessagesBurst:      p.int("RELAY_SEND_MESSAGES_BURST", 2000),
		ProviderCallsPerMinute: p.int("RELAY_PROVIDER_CALLS_PER_MINUTE", 60000),
		ProviderCallsBurst:     p.int("RELAY_PROVIDER_CALLS_BURST", 5000),
		MaxTokensTotal:         p.int("RELAY_MAX_TOKENS_TOTAL", 500000),
		MaxMessages:            p.int("RELAY_MAX_MESSAGES", 500),
		SendConcurrency:        p.int("RELAY_SEND_CONCURRENCY", 8),
		SendTimeoutSeconds:     p.int("RELAY_SEND_TIMEOUT_SECONDS", DefaultSendTimeoutSeconds),
		TokenRetentionDays:     p.int("RELAY_TOKEN_RETENTION_DAYS", 90),
		MaxTokensPerKey:        p.int("RELAY_MAX_TOKENS_PER_KEY", 20000),
		MaxKeysPerToken:        p.int("RELAY_MAX_KEYS_PER_TOKEN", 8),
		BindingIdleDays:        p.int("RELAY_BINDING_IDLE_DAYS", 14),
	}
	return cfg, p.err
}

type namedInt struct {
	name  string
	value int
}

// HTTPWriteTimeout is how long the HTTP server may spend answering one request. It follows
// the send deadline so a slow batch's response is never cut off first; with the deadline
// disabled there is nothing to follow and the write timeout is off with it.
func (c Config) HTTPWriteTimeout() time.Duration {
	if c.SendTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(c.SendTimeoutSeconds)*time.Second + writeHeadroom
}

// AdminEnabled reports whether the admin endpoints are mounted: a token is set and long
// enough that guessing it over the network is not realistic.
func (c Config) AdminEnabled() bool { return len(c.AdminToken) >= MinAdminTokenChars }

// Validate rejects numbers that parse but break the relay, naming each variable. A zero
// burst or rate leaves a limiter that admits one call and then denies that caller forever,
// and a zero RELAY_MAX_MESSAGES refuses every non-empty send. The knobs documented as
// "zero or negative disables" are deliberately not checked. The proxy hop count only matters
// once the proxy header is trusted.
func (c Config) Validate() error {
	atLeastOne := []namedInt{
		{"RELAY_REGISTER_PER_HOUR", c.RegisterPerHour},
		{"RELAY_REGISTER_BURST", c.RegisterBurst},
		{"RELAY_SEND_ADMIT_PER_MINUTE", c.SendAdmitPerMinute},
		{"RELAY_SEND_ADMIT_BURST", c.SendAdmitBurst},
		{"RELAY_SEND_PER_MINUTE", c.SendPerMinute},
		{"RELAY_SEND_BURST", c.SendBurst},
		{"RELAY_CALL_SEND_PER_MINUTE", c.CallSendPerMinute},
		{"RELAY_CALL_SEND_BURST", c.CallSendBurst},
		{"RELAY_MAX_MESSAGES", c.MaxMessages},
	}
	if c.TrustProxy {
		atLeastOne = append(atLeastOne, namedInt{"RELAY_TRUST_PROXY_HOPS", c.TrustProxyHops})
	}
	var errs []error
	for _, f := range atLeastOne {
		if f.value < 1 {
			errs = append(errs, fmt.Errorf("%s=%d must be at least 1", f.name, f.value))
		}
	}
	return errors.Join(errs...)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parser reads typed variables and remembers the first one that was set but malformed.
type parser struct{ err error }

func (p *parser) fail(key, v, want string, cause error) {
	if p.err == nil {
		p.err = fmt.Errorf("%s=%q is not %s: %w", key, v, want, cause)
	}
}

func (p *parser) int(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		p.fail(key, v, "an integer", err)
		return def
	}
	return n
}

func (p *parser) bool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.fail(key, v, "a boolean (true, false, 1, 0)", err)
		return def
	}
	return b
}
