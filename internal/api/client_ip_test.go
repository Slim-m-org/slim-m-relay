// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func ipFor(t *testing.T, trust bool, hops int, remote, xff string) string {
	t.Helper()
	cfg := defaultCfg()
	cfg.TrustProxy = trust
	cfg.TrustProxyHops = hops
	srv, _, _, _ := newTestServer(t, cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/register", nil)
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return srv.clientIP(req)
}

func TestClientIPSharesOneBucketPerIPv6Slash64(t *testing.T) {
	a := ipFor(t, false, 0, "[2001:db8:1:2::1]:1", "")
	b := ipFor(t, false, 0, "[2001:db8:1:2:ffff:ffff:ffff:ffff]:2", "")
	other := ipFor(t, false, 0, "[2001:db8:1:3::1]:3", "")
	if a != b {
		t.Errorf("two addresses in one /64 got %q and %q, want one bucket", a, b)
	}
	if a == other {
		t.Errorf("a different /64 must not share the bucket, both %q", a)
	}
}

func TestClientIPKeepsIPv4PerAddressAndUnmapsMappedIPv6(t *testing.T) {
	if a, b := ipFor(t, false, 0, "203.0.113.9:1", ""), ipFor(t, false, 0, "203.0.113.10:1", ""); a == b {
		t.Errorf("distinct IPv4 addresses shared a bucket: %q", a)
	}
	if got := ipFor(t, false, 0, "[::ffff:203.0.113.9]:1", ""); got != "203.0.113.9" {
		t.Errorf("mapped address = %q, want 203.0.113.9", got)
	}
}

func TestClientIPMasksIPv6FromTheProxyHeaderToo(t *testing.T) {
	a := ipFor(t, true, 1, "203.0.113.9:1", "2001:db8:aa:bb::1")
	b := ipFor(t, true, 1, "203.0.113.9:1", "2001:db8:aa:bb::2")
	if a != b {
		t.Errorf("header addresses in one /64 got %q and %q", a, b)
	}
}

func TestClientIPTrustProxyHopsPicksTheNthFromTheRight(t *testing.T) {
	xff := "6.6.6.6, 198.51.100.7, 192.0.2.1"
	if got := ipFor(t, true, 2, "203.0.113.9:1", xff); got != "198.51.100.7" {
		t.Errorf("hops=2 = %q, want the second entry from the right", got)
	}
	if got := ipFor(t, true, 1, "203.0.113.9:1", xff); got != "192.0.2.1" {
		t.Errorf("hops=1 = %q, want the rightmost entry", got)
	}
	if got := ipFor(t, true, 0, "203.0.113.9:1", xff); got != "192.0.2.1" {
		t.Errorf("unset hops = %q, want the rightmost entry", got)
	}
}

func TestClientIPFallsBackToThePeerWhenTheHeaderIsShorterThanTheHops(t *testing.T) {
	if got := ipFor(t, true, 3, "203.0.113.9:1", "198.51.100.7"); got != "203.0.113.9" {
		t.Errorf("short header = %q, want the peer", got)
	}
}
