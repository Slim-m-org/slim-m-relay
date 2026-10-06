// SPDX-License-Identifier: Apache-2.0

// Package config loads the relay's runtime settings from the environment, so the service
// stays a single self-contained binary that is easy to run under Docker.
package config

import (
	"os"
	"strconv"
)

// Config holds all runtime configuration for the relay.
type Config struct {
	// Port is the TCP port the relay listens on.
	Port int
	// DBPath is the SQLite file that stores hashed keys and device-token bindings.
	DBPath string
	// AdminToken guards the /admin endpoints (list and revoke keys). Empty disables them.
	AdminToken string

	// FCMCredentialsFile points to the Firebase service-account JSON used to send Android
	// pushes. Empty is not fatal: Android sends fail clearly instead of the relay refusing
	// to start.
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

	// RegisterPerHour and RegisterBurst bound how often one IP may mint new keys.
	RegisterPerHour int
	RegisterBurst   int
	// MaxRegistrations is the total number of keys the relay will ever mint, across every IP
	// and forever (revoked keys still count), so /v1/register cannot be used to grow the key
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
	// MaxMessages caps how many device tokens a single /v1/send request may carry.
	MaxMessages int
	// SendConcurrency bounds how many provider sends run at once for one /v1/send request,
	// since each is its own HTTP round trip to APNs or FCM.
	SendConcurrency int
	// SendTimeoutSeconds is the hard wall-clock deadline for one /v1/send request's provider
	// dispatch. A message whose turn has not come by then is returned as "not_attempted"
	// instead of holding the request open. Zero or negative disables the deadline entirely,
	// matching the "0 or negative disables it" convention the other ceilings in this struct
	// already use, rather than the instantly-expired context a literal zero-second timeout
	// would otherwise produce.
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
}

// Load reads configuration from the environment, applying defaults that suit a single
// maintainer-run relay.
func Load() Config {
	return Config{
		Port:               getint("RELAY_PORT", 8090),
		DBPath:             getenv("RELAY_DB_PATH", "/data/relay.db"),
		AdminToken:         getenv("RELAY_ADMIN_TOKEN", ""),
		FCMCredentialsFile: getenv("RELAY_FCM_CREDENTIALS_FILE", ""),
		APNsKeyPath:        getenv("RELAY_APNS_KEY_PATH", ""),
		APNsKeyID:          getenv("RELAY_APNS_KEY_ID", ""),
		APNsTeamID:         getenv("RELAY_APNS_TEAM_ID", ""),
		APNsBundleID:       getenv("RELAY_APNS_BUNDLE_ID", ""),
		APNsProduction:     getbool("RELAY_APNS_PRODUCTION", true),
		TrustProxy:         getbool("RELAY_TRUST_PROXY", false),
		RegisterPerHour:    getint("RELAY_REGISTER_PER_HOUR", 5),
		RegisterBurst:      getint("RELAY_REGISTER_BURST", 3),
		MaxRegistrations:   getint("RELAY_MAX_REGISTRATIONS", 10000),
		SendAdmitPerMinute: getint("RELAY_SEND_ADMIT_PER_MINUTE", 600),
		SendAdmitBurst:     getint("RELAY_SEND_ADMIT_BURST", 120),
		SendPerMinute:      getint("RELAY_SEND_PER_MINUTE", 120),
		SendBurst:          getint("RELAY_SEND_BURST", 60),
		CallSendPerMinute:  getint("RELAY_CALL_SEND_PER_MINUTE", 10),
		CallSendBurst:      getint("RELAY_CALL_SEND_BURST", 5),
		MaxMessages:        getint("RELAY_MAX_MESSAGES", 500),
		SendConcurrency:    getint("RELAY_SEND_CONCURRENCY", 8),
		SendTimeoutSeconds: getint("RELAY_SEND_TIMEOUT_SECONDS", 20),
		TokenRetentionDays: getint("RELAY_TOKEN_RETENTION_DAYS", 90),
		MaxTokensPerKey:    getint("RELAY_MAX_TOKENS_PER_KEY", 20000),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getbool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
