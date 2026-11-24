// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRevokingAKeyFreesItsRegistrationSlot(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, err := s.Issue(ctx, "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(ctx, "b", 1); !errors.Is(err, ErrRegistrationCeiling) {
		t.Fatalf("issue at the ceiling = %v, want ErrRegistrationCeiling", err)
	}
	k, _ := s.Verify(ctx, plain)
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(ctx, "b", 1); err != nil {
		t.Fatalf("issue after a revoke = %v, want the slot freed", err)
	}
}

func TestPurgeUnusedRemovesKeysThatOnlyAuthenticated(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	squat, _ := s.Issue(ctx, "squatter", 0)
	real, _ := s.Issue(ctx, "real", 0)
	sk, _ := s.Verify(ctx, squat)
	rk, _ := s.Verify(ctx, real)
	if _, err := s.BindTokens(ctx, sk.ID, nil, BindLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindTokens(ctx, rk.ID, refs("ios", "t1"), BindLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE keys SET created_at = 1`); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgeUnused(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v; want exactly the key that never bound a token", n, err)
	}
	if _, err := s.Verify(ctx, squat); !errors.Is(err, ErrNotFound) {
		t.Errorf("squatting key survived the purge: %v", err)
	}
	if _, err := s.Verify(ctx, real); err != nil {
		t.Errorf("key with a bound token was purged: %v", err)
	}
}

func TestBindTokensStopsAtTheRelayWideCap(t *testing.T) {
	s := openTemp(t)
	a, b := twoKeys(t, s)
	ctx := context.Background()
	lim := BindLimits{MaxTotal: 3}
	got, err := s.BindTokens(ctx, a, refs("ios", "t1", "t2"), lim)
	if err != nil || got[0] != nil || got[1] != nil {
		t.Fatalf("first batch = %v, %v", got, err)
	}
	got, err = s.BindTokens(ctx, b, refs("ios", "t3", "t4", "t1"), lim)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != nil || !errors.Is(got[1], ErrRelayTokenLimit) || !errors.Is(got[2], ErrRelayTokenLimit) {
		t.Fatalf("second batch = %v, want ok then relay limit for the new bindings", got)
	}
	got, err = s.BindTokens(ctx, a, refs("ios", "t1"), lim)
	if err != nil || got[0] != nil {
		t.Fatalf("an existing binding must keep working at the cap: %v, %v", got, err)
	}
}

// The key's bound count is read once per transaction and tracked in memory afterwards, so a
// batch of new tokens does not run a COUNT over the key's whole index for each of them.
func TestBindCountsAreReadOncePerTransaction(t *testing.T) {
	s := openTemp(t)
	a, _ := twoKeys(t, s)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	lim := BindLimits{MaxPerKey: 3, MaxTotal: 100}
	counts := &bindCounts{}
	if err := insertBinding(ctx, tx, a, TokenRef{"ios", "t1"}, 1, lim, counts); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"x1", "x2", "x3"} {
		if _, err := tx.Exec(`INSERT INTO tokens (platform, token, key_id, created_at, last_seen_at) VALUES ('ios', ?, ?, 1, 1)`, tok, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := insertBinding(ctx, tx, a, TokenRef{"ios", "t2"}, 1, lim, counts); err != nil {
		t.Fatalf("second insert re-counted the table: %v", err)
	}
	if err := insertBinding(ctx, tx, a, TokenRef{"ios", "t3"}, 1, lim, counts); err != nil {
		t.Fatalf("third insert re-counted the table: %v", err)
	}
	if err := insertBinding(ctx, tx, a, TokenRef{"ios", "t4"}, 1, lim, counts); !errors.Is(err, ErrTokenLimit) {
		t.Fatalf("fourth insert = %v, want the in-memory count to hit the per-key cap", err)
	}
}
