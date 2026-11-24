// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"testing"
)

func mustExec(t *testing.T, s *Store, q string) {
	t.Helper()
	if _, err := s.db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestUnbindWithNothingToRemoveTouchesNothing(t *testing.T) {
	s := openTemp(t)
	a, _ := twoKeys(t, s)
	before := totalChanges(t, s)
	if err := s.Unbind(context.Background(), a, nil); err != nil {
		t.Fatalf("Unbind(nil) = %v, want nil", err)
	}
	if after := totalChanges(t, s); after != before {
		t.Errorf("an empty Unbind wrote %d rows", after-before)
	}
}

func TestUnbindReportsADatabaseThatCannotBeUsed(t *testing.T) {
	s := openTemp(t)
	a, _ := twoKeys(t, s)
	ctx := context.Background()
	if _, err := s.BindTokens(ctx, a, refs("ios", "t1"), BindLimits{}); err != nil {
		t.Fatal(err)
	}

	mustExec(t, s, `DROP TABLE tokens`)
	if err := s.Unbind(ctx, a, refs("ios", "t1")); err == nil {
		t.Error("Unbind on a store whose tokens table is gone returned nil, want the failure")
	}

	_ = s.db.Close()
	if err := s.Unbind(ctx, a, refs("ios", "t1")); err == nil {
		t.Error("Unbind on a closed store returned nil, want the failure")
	}
}

func TestBindTokensReportsADatabaseThatCannotBeUsed(t *testing.T) {
	ctx := context.Background()

	t.Run("closed store", func(t *testing.T) {
		s := openTemp(t)
		a, _ := twoKeys(t, s)
		_ = s.db.Close()
		if out, err := s.BindTokens(ctx, a, refs("ios", "t1"), BindLimits{}); err == nil || out != nil {
			t.Errorf("BindTokens = %v, %v; want a failure and no outcomes", out, err)
		}
	})

	t.Run("missing last_bound_at stamp", func(t *testing.T) {
		s := openTemp(t)
		a, _ := twoKeys(t, s)
		mustExec(t, s, `ALTER TABLE keys DROP COLUMN last_bound_at`)
		if out, err := s.BindTokens(ctx, a, refs("ios", "t1"), BindLimits{}); err == nil || out != nil {
			t.Errorf("BindTokens = %v, %v; want a failure and no outcomes", out, err)
		}
	})

	t.Run("insert refused by the database", func(t *testing.T) {
		s := openTemp(t)
		a, _ := twoKeys(t, s)
		mustExec(t, s, `DROP TABLE tokens`)
		mustExec(t, s, `CREATE VIEW tokens AS SELECT 0 AS id, '' AS platform, '' AS token, 0 AS key_id, 0 AS created_at, 0 AS last_seen_at WHERE 0`)
		if out, err := s.BindTokens(ctx, a, refs("ios", "t1"), BindLimits{}); err == nil || out != nil {
			t.Errorf("BindTokens = %v, %v; want the insert failure to abandon the batch", out, err)
		}
	})

	t.Run("tokens table gone", func(t *testing.T) {
		s := openTemp(t)
		a, _ := twoKeys(t, s)
		mustExec(t, s, `DROP TABLE tokens`)
		if _, err := s.BindTokens(ctx, a, refs("ios", "t1"), BindLimits{}); err == nil {
			t.Error("BindTokens with no tokens table returned nil, want the failure")
		}
	})
}

func TestMigrateReportsAKeysTableItCannotAlter(t *testing.T) {
	s := openTemp(t)
	mustExec(t, s, `PRAGMA foreign_keys = OFF`)
	mustExec(t, s, `DROP TABLE tokens`)
	mustExec(t, s, `DROP TABLE keys`)
	mustExec(t, s, `CREATE VIEW keys AS SELECT 1 AS id`)
	if err := s.migrate(); err == nil {
		t.Error("migrate over a keys table it cannot alter returned nil, want the failure")
	}
}

func TestAddLastBoundAtReportsAClosedStore(t *testing.T) {
	s := openTemp(t)
	_ = s.db.Close()
	if err := s.addLastBoundAt(); err == nil {
		t.Error("addLastBoundAt on a closed store returned nil, want the failure")
	}
}
