// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load with an empty environment: %v", err)
	}
	if c.Port != 8090 || c.DBPath != "/data/relay.db" {
		t.Errorf("port/db = %d %q, want 8090 /data/relay.db", c.Port, c.DBPath)
	}
	if c.TrustProxy {
		t.Error("TrustProxy must default to false: trusting X-Forwarded-For without a proxy makes IP limits spoofable")
	}
	if c.AdminToken != "" {
		t.Errorf("AdminToken = %q, want empty (admin disabled)", c.AdminToken)
	}
	if !c.APNsProduction {
		t.Error("APNsProduction must default to true")
	}
	if c.TokenRetentionDays != 90 || c.MaxTokensPerKey != 20000 || c.MaxRegistrations != 10000 {
		t.Errorf("retention/tokens/registrations = %d %d %d, want 90 20000 10000", c.TokenRetentionDays, c.MaxTokensPerKey, c.MaxRegistrations)
	}
	if c.RegisterPerHour != 5 || c.RegisterBurst != 3 || c.SendPerMinute != 120 || c.SendBurst != 60 {
		t.Errorf("limits = %d %d %d %d, want 5 3 120 60", c.RegisterPerHour, c.RegisterBurst, c.SendPerMinute, c.SendBurst)
	}
	if c.CallSendPerMinute != 10 || c.CallSendBurst != 5 || c.MaxMessages != 500 || c.SendConcurrency != 8 || c.SendTimeoutSeconds != 20 {
		t.Errorf("call/message limits = %+v", c)
	}
	if c.SendAdmitPerMinute != 600 || c.SendAdmitBurst != 120 {
		t.Errorf("admit = %d %d, want 600 120", c.SendAdmitPerMinute, c.SendAdmitBurst)
	}
}

func TestLoadReadsOverrides(t *testing.T) {
	t.Setenv("RELAY_PORT", "9000")
	t.Setenv("RELAY_ADMIN_TOKEN", "secret")
	t.Setenv("RELAY_TRUST_PROXY", "true")
	t.Setenv("RELAY_APNS_PRODUCTION", "0")
	t.Setenv("RELAY_TOKEN_RETENTION_DAYS", "0")
	t.Setenv("RELAY_FCM_CREDENTIALS_FILE", "/run/fcm.json")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 9000 || c.AdminToken != "secret" || !c.TrustProxy || c.APNsProduction || c.TokenRetentionDays != 0 || c.FCMCredentialsFile != "/run/fcm.json" {
		t.Errorf("overrides not applied: %+v", c)
	}
}

func TestLoadRejectsAMalformedValue(t *testing.T) {
	cases := []struct{ name, value string }{
		{"RELAY_TRUST_PROXY", "yes"},
		{"RELAY_APNS_PRODUCTION", "prod"},
		{"RELAY_SEND_PER_MINUTE", "12O"},
		{"RELAY_PORT", "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q loaded without an error", tc.name, tc.value)
			}
			if !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), tc.value) {
				t.Errorf("error %q must name the variable and the value", err)
			}
		})
	}
}
