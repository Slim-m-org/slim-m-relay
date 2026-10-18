// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIssueThenVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, err := s.Issue(ctx, "https://alpha.example.com", 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(plain, keyPrefix) {
		t.Errorf("issued key %q lacks the %q prefix", plain, keyPrefix)
	}
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Label != "https://alpha.example.com" {
		t.Errorf("got label=%q", k.Label)
	}
	if k.LastUsedAt == nil {
		t.Error("verify should stamp last-used")
	}
}

// TestIssueEnforcesRegistrationCeiling exercises the global mint ceiling: once max keys
// have been issued, further Issue calls fail with ErrRegistrationCeiling, and revoking a
// key does not free up a slot, since the ceiling bounds keys ever minted, not keys currently
// active.
func TestIssueEnforcesRegistrationCeiling(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	first, err := s.Issue(ctx, "first", 2)
	if err != nil {
		t.Fatalf("issue 1/2: %v", err)
	}
	if _, err := s.Issue(ctx, "second", 2); err != nil {
		t.Fatalf("issue 2/2: %v", err)
	}
	if _, err := s.Issue(ctx, "third", 2); err != ErrRegistrationCeiling {
		t.Fatalf("issue past the ceiling: got %v, want ErrRegistrationCeiling", err)
	}

	k, err := s.Verify(ctx, first)
	if err != nil {
		t.Fatalf("verify first: %v", err)
	}
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Issue(ctx, "fourth", 2); err != ErrRegistrationCeiling {
		t.Fatalf("issue after revoking one: got %v, want ErrRegistrationCeiling (the ceiling counts keys ever minted)", err)
	}
}

// A zero or negative max disables the ceiling entirely.
func TestIssueZeroMaxDisablesCeiling(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.Issue(ctx, "", 0); err != nil {
			t.Fatalf("issue %d with max=0: %v", i, err)
		}
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Verify(context.Background(), "smr_not-a-real-key"); err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokeBlocksVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, _ := s.Issue(ctx, "", 0)
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify before revoke: %v", err)
	}
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Verify(ctx, plain); err != ErrNotFound {
		t.Errorf("a revoked key should verify as ErrNotFound, got %v", err)
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	s := openTemp(t)
	if err := s.Revoke(context.Background(), 9999); err != ErrNotFound {
		t.Errorf("want ErrNotFound revoking a missing key, got %v", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	_, _ = s.Issue(ctx, "first", 0)
	_, _ = s.Issue(ctx, "second", 0)

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 keys, got %d", len(list))
	}
	if list[0].Label != "second" {
		t.Errorf("want newest (second) first, got %q", list[0].Label)
	}
}

func TestDistinctKeysHashDistinctly(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	a, _ := s.Issue(ctx, "", 0)
	b, _ := s.Issue(ctx, "", 0)
	if a == b {
		t.Fatal("two issued keys must differ")
	}
	ka, _ := s.Verify(ctx, a)
	kb, _ := s.Verify(ctx, b)
	if ka.ID == kb.ID {
		t.Error("distinct keys must map to distinct rows")
	}
}

func bindOK(t *testing.T, s *Store, keyID int64, platform, tok string, lim BindLimits) {
	t.Helper()
	if err := s.BindToken(context.Background(), keyID, platform, tok, lim); err != nil {
		t.Fatalf("bind %s for key %d: %v", tok, keyID, err)
	}
}

func twoKeys(t *testing.T, s *Store) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	a, _ := s.Issue(ctx, "", 0)
	b, _ := s.Issue(ctx, "", 0)
	ka, _ := s.Verify(ctx, a)
	kb, _ := s.Verify(ctx, b)
	return ka.ID, kb.ID
}

func TestTwoKeysShareOneToken(t *testing.T) {
	s := openTemp(t)
	a, b := twoKeys(t, s)
	lim := BindLimits{MaxKeysPerToken: 8}
	bindOK(t, s, a, "ios", "device-token-1", lim)
	bindOK(t, s, b, "ios", "device-token-1", lim)
	bindOK(t, s, a, "ios", "device-token-1", lim)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token = 'device-token-1'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("bindings = %d (%v), want one per key", n, err)
	}
}

func TestBindTokenPlatformsAreSeparate(t *testing.T) {
	s := openTemp(t)
	a, b := twoKeys(t, s)
	lim := BindLimits{MaxKeysPerToken: 1}
	bindOK(t, s, a, "ios", "tok", lim)
	bindOK(t, s, b, "android", "tok", lim)
}

func TestTokenKeyCapRefusesAnotherKey(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	lim := BindLimits{MaxKeysPerToken: 2}
	var ids []int64
	for i := 0; i < 3; i++ {
		k, _ := s.Issue(ctx, "", 0)
		kk, _ := s.Verify(ctx, k)
		ids = append(ids, kk.ID)
	}
	bindOK(t, s, ids[0], "ios", "tok", lim)
	bindOK(t, s, ids[1], "ios", "tok", lim)
	if err := s.BindToken(ctx, ids[2], "ios", "tok", lim); !errors.Is(err, ErrTokenKeyLimit) {
		t.Fatalf("third key = %v, want ErrTokenKeyLimit", err)
	}
	bindOK(t, s, ids[0], "ios", "tok", lim)
}

// A hostile server that fills a token's slots must not lock real servers out for good.
func TestFullTokenAdmitsKeyOnlyByReplacingIdleBinding(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	lim := BindLimits{MaxKeysPerToken: 2, BindingIdle: 24 * time.Hour}
	var ids []int64
	for i := 0; i < 3; i++ {
		k, _ := s.Issue(ctx, "", 0)
		kk, _ := s.Verify(ctx, k)
		ids = append(ids, kk.ID)
	}
	bindOK(t, s, ids[0], "ios", "tok", lim)
	bindOK(t, s, ids[1], "ios", "tok", lim)
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := s.db.Exec(`UPDATE tokens SET last_seen_at = ? WHERE key_id = ?`, old, ids[0]); err != nil {
		t.Fatal(err)
	}
	bindOK(t, s, ids[2], "ios", "tok", lim)
	if err := s.BindToken(ctx, ids[0], "ios", "tok", lim); !errors.Is(err, ErrTokenKeyLimit) {
		t.Fatalf("the evicted key = %v, want ErrTokenKeyLimit while the others stay active", err)
	}
}

func TestOldSingleKeyBindingsSurviveTheUpgradeAndCanBeShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT NOT NULL, token TEXT NOT NULL,
	key_id INTEGER NOT NULL REFERENCES keys(id), created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0, UNIQUE(platform, token));
INSERT INTO keys (id, key_hash, created_at) VALUES (1, 'a', 1), (2, 'b', 1);
INSERT INTO tokens (platform, token, key_id, created_at, last_seen_at) VALUES ('ios', 'dev', 1, 1, 5);`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open after upgrade: %v", err)
	}
	defer func() { _ = s.Close() }()
	lim := BindLimits{MaxKeysPerToken: 8}
	bindOK(t, s, 1, "ios", "dev", lim)
	bindOK(t, s, 2, "ios", "dev", lim)
}

// TestBindTokenPrunesTokensStaleBeyondRetention exercises the fix for the tokens table
// growing without bound: a binding nobody has sent to within the retention window is
// deleted by BindToken's lazy sweep, while one actively touched by its owning key survives
// regardless of how old it is.
func TestBindTokenPrunesTokensStaleBeyondRetention(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	keyA, _ := s.Issue(ctx, "", 0)
	ka, _ := s.Verify(ctx, keyA)

	if err := s.BindToken(ctx, ka.ID, "ios", "stale-token", BindLimits{Retention: time.Hour}); err != nil {
		t.Fatalf("bind stale token: %v", err)
	}
	// Age the binding far past a 24h retention window, as if nobody had sent to it since.
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := s.db.Exec(`UPDATE tokens SET last_seen_at = ? WHERE token = ?`, old, "stale-token"); err != nil {
		t.Fatalf("age stale token: %v", err)
	}
	// Force the lazy sweep to be due on the next BindToken call, regardless of pruneInterval.
	s.pruneMu.Lock()
	s.lastPrune = time.Now().Add(-2 * pruneInterval)
	s.pruneMu.Unlock()

	// Binding an unrelated fresh token is what triggers the sweep.
	if err := s.BindToken(ctx, ka.ID, "ios", "fresh-token", BindLimits{Retention: 24 * time.Hour}); err != nil {
		t.Fatalf("bind fresh token: %v", err)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token = ?`, "stale-token").Scan(&count); err != nil {
		t.Fatalf("count stale-token: %v", err)
	}
	if count != 0 {
		t.Errorf("stale-token rows = %d, want 0 (a binding untouched for 48h must be pruned under a 24h retention)", count)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token = ?`, "fresh-token").Scan(&count); err != nil {
		t.Fatalf("count fresh-token: %v", err)
	}
	if count != 1 {
		t.Errorf("fresh-token rows = %d, want 1 (a token must survive its own bind)", count)
	}
}

// A retention of zero or negative disables pruning entirely, matching the same convention
// as MaxRegistrations, so an operator who has not set RELAY_TOKEN_RETENTION_DAYS explicitly
// never has bindings disappear underneath them.
func TestBindTokenZeroRetentionDisablesPruning(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	keyA, _ := s.Issue(ctx, "", 0)
	ka, _ := s.Verify(ctx, keyA)

	if err := s.BindToken(ctx, ka.ID, "ios", "ancient-token", BindLimits{}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	old := time.Now().Add(-24 * 365 * time.Hour).Unix() // a year stale
	if _, err := s.db.Exec(`UPDATE tokens SET last_seen_at = ? WHERE token = ?`, old, "ancient-token"); err != nil {
		t.Fatalf("age token: %v", err)
	}
	s.pruneMu.Lock()
	s.lastPrune = time.Now().Add(-2 * pruneInterval)
	s.pruneMu.Unlock()

	if err := s.BindToken(ctx, ka.ID, "ios", "another-token", BindLimits{}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token = ?`, "ancient-token").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Error("a year-stale token must survive when retention is disabled (0)")
	}
}

// An upgrade must not delete the token bindings an already-running relay depends on.
// Adding last_seen_at backfills existing rows, and if that backfill lands at 0 every
// pre-existing row looks infinitely stale, so the first prune wipes the table and with it
// the binding that stops one key pushing to another key's device.
func TestUpgradeFromSchemaWithoutLastSeenDoesNotPruneExistingTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")

	// Build the pre-upgrade schema by hand: tokens without last_seen_at.
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
);
CREATE TABLE tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        platform TEXT NOT NULL,
        token TEXT NOT NULL,
        key_id INTEGER NOT NULL REFERENCES keys(id),
        created_at INTEGER NOT NULL,
        UNIQUE(platform, token)
);
INSERT INTO keys (id, hash, label, created_at) VALUES (1, 'deadbeef', '', 1);
INSERT INTO tokens (platform, token, key_id, created_at) VALUES ('ios', 'established-token', 1, 1);`); err != nil {
		t.Fatalf("seed old schema: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// Opening runs the migration that adds last_seen_at.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open after upgrade: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Force the prune to be due, then drive it through a bind by an unrelated key.
	s.lastPrune = time.Time{}
	ctx := context.Background()
	if err := s.BindToken(ctx, 1, "ios", "some-other-token", BindLimits{Retention: 24 * time.Hour}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	var owner int64
	err = s.db.QueryRow(
		`SELECT key_id FROM tokens WHERE platform = 'ios' AND token = 'established-token'`,
	).Scan(&owner)
	if err != nil {
		t.Fatalf("the pre-existing binding was pruned by the upgrade: %v", err)
	}
	if owner != 1 {
		t.Fatalf("binding owner = %d, want 1", owner)
	}
}

func TestBindTokenCapsNewBindingsPerKey(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	keyA, _ := s.Issue(ctx, "", 0)
	ka, _ := s.Verify(ctx, keyA)
	keyB, _ := s.Issue(ctx, "", 0)
	kb, _ := s.Verify(ctx, keyB)

	lim := BindLimits{MaxPerKey: 2}
	for _, tok := range []string{"t1", "t2"} {
		bindOK(t, s, ka.ID, "ios", tok, lim)
	}
	if err := s.BindToken(ctx, ka.ID, "ios", "t3", lim); !errors.Is(err, ErrTokenLimit) {
		t.Fatalf("third bind = %v, want ErrTokenLimit", err)
	}
	bindOK(t, s, ka.ID, "ios", "t1", lim)
	bindOK(t, s, kb.ID, "ios", "t3", lim)
	bindOK(t, s, ka.ID, "ios", "t4", BindLimits{})
}
