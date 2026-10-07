// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/push"
)

func statusFor(t *testing.T, srv *Server, key, token string) push.Status {
	t.Helper()
	res := sendTokens(t, srv, key, "ios", token)
	if len(res) != 1 {
		t.Fatalf("results = %+v, want one", res)
	}
	return res[0].Status
}

// A revoked key can never send again, so the devices it owned must be free to move to
// another key (a phone that left server A for server B, or a server that re-registered).
func TestRevokedOwnerReleasesItsTokens(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	ctx := context.Background()
	a, _ := store.Issue(ctx, "server-a", 0)
	b, _ := store.Issue(ctx, "server-b", 0)

	if got := statusFor(t, srv, a, "phone-token"); got != push.StatusDelivered {
		t.Fatalf("A first send = %s, want delivered", got)
	}
	if got := statusFor(t, srv, b, "phone-token"); got != push.StatusForbidden {
		t.Fatalf("B while A is live = %s, want forbidden (by design)", got)
	}
	ka, _ := store.Verify(ctx, a)
	if err := store.Revoke(ctx, ka.ID); err != nil {
		t.Fatal(err)
	}
	if got := statusFor(t, srv, b, "phone-token"); got != push.StatusDelivered {
		t.Fatalf("B after A was revoked = %s, want delivered", got)
	}
}
