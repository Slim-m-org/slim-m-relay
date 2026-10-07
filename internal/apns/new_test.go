// SPDX-License-Identifier: Apache-2.0

package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/sideshow/apns2"
)

func writeP8(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "AuthKey.p8")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewPicksTheGatewayFromProduction(t *testing.T) {
	path := writeP8(t)
	for _, tc := range []struct {
		production bool
		host       string
	}{
		{true, apns2.HostProduction},
		{false, apns2.HostDevelopment},
	} {
		s, err := New(Config{KeyPath: path, KeyID: "ABC123DEFG", TeamID: "TEAM123456", BundleID: "app.slim", Production: tc.production})
		if err != nil {
			t.Fatalf("production=%v: %v", tc.production, err)
		}
		c, ok := s.client.(*apns2.Client)
		if !ok {
			t.Fatalf("client is %T, want *apns2.Client", s.client)
		}
		if c.Host != tc.host {
			t.Errorf("production=%v host = %q, want %q", tc.production, c.Host, tc.host)
		}
		if s.bundleID != "app.slim" {
			t.Errorf("bundleID = %q", s.bundleID)
		}
	}
}

func TestNewRejectsAnUnusableKey(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "bad.p8")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"garbage": garbage, "missing": filepath.Join(t.TempDir(), "nope.p8")} {
		if _, err := New(Config{KeyPath: path, KeyID: "k", TeamID: "t", BundleID: "b", Production: true}); err == nil {
			t.Errorf("%s key: want an error", name)
		}
	}
}
