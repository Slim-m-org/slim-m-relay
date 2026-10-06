// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"testing"
	"time"
)

func TestAllowsUpToBurstThenDenies(t *testing.T) {
	// No refill worth mentioning within the test's runtime, so the burst is the whole budget.
	l := New(0, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("call %d should have been allowed within the burst of 3", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("a 4th call should be denied once the burst is spent")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(0, 1)
	if !l.Allow("a") {
		t.Fatal("first key should be allowed")
	}
	if !l.Allow("b") {
		t.Fatal("a different key has its own bucket and should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("the first key's bucket is spent")
	}
}

// Every keyed limiter (per-IP registration, per-key send, per-key call) is built from this
// same Limiter, so its idle sweep is what keeps all of them from growing without bound as
// distinct IPs and keys come and go.
func TestEvictsIdleBuckets(t *testing.T) {
	l := New(60, 1)
	if !l.Allow("stale-a") || !l.Allow("stale-b") {
		t.Fatal("setup: both keys should be allowed on their first call")
	}

	l.mu.Lock()
	if len(l.buckets) != 2 {
		t.Fatalf("setup: want 2 buckets before eviction, got %d", len(l.buckets))
	}
	// Age both buckets past evictIdle's 10-minute cutoff, and force the next Allow to treat
	// evictInterval as elapsed, so the sweep runs deterministically instead of waiting on
	// real wall-clock time.
	old := time.Now().Add(-11 * time.Minute)
	l.buckets["stale-a"].last = old
	l.buckets["stale-b"].last = old
	l.lastEvict = time.Now().Add(-2 * evictInterval)
	l.mu.Unlock()

	if !l.Allow("fresh") {
		t.Fatal("a new key should be allowed regardless of the sweep")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets["stale-a"]; ok {
		t.Error("stale-a should have been evicted as idle")
	}
	if _, ok := l.buckets["stale-b"]; ok {
		t.Error("stale-b should have been evicted as idle")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Error("fresh should still be present; eviction must not remove active buckets")
	}
	if len(l.buckets) != 1 {
		t.Errorf("want exactly 1 bucket after eviction, got %d", len(l.buckets))
	}
}

// Return undoes a prior Allow, so a caller that consumed a token for work it turns out
// never happened - a not_attempted call-kind send, for instance - can give it back rather
// than leaving a subsequent legitimate retry wrongly refused.
func TestReturnGivesBackAToken(t *testing.T) {
	l := New(0, 1)
	if !l.Allow("k") {
		t.Fatal("first call should be allowed within the burst of 1")
	}
	if l.Allow("k") {
		t.Fatal("second call should be denied: the burst is spent")
	}
	l.Return("k")
	if !l.Allow("k") {
		t.Fatal("after Return, a call should be allowed again")
	}
}

// Return must never push a bucket's tokens above its burst ceiling.
func TestReturnDoesNotExceedBurst(t *testing.T) {
	l := New(0, 1)
	l.Return("never-called-allow") // no bucket yet: must be a harmless no-op
	if !l.Allow("never-called-allow") {
		t.Fatal("first call for a key with no prior bucket should still be allowed")
	}

	l.mu.Lock()
	l.buckets["k"] = &bucket{tokens: 1, last: time.Now()}
	l.mu.Unlock()
	l.Return("k")
	l.Return("k")
	l.mu.Lock()
	got := l.buckets["k"].tokens
	l.mu.Unlock()
	if got != 1 {
		t.Errorf("tokens = %v after returning past a full bucket, want capped at burst (1)", got)
	}
}

func TestRefillsOverTime(t *testing.T) {
	// 60/min = 1/sec. Spend the single-token burst, then hand the bucket a second of
	// elapsed time by moving its last-seen back, and it should allow again.
	l := New(60, 1)
	if !l.Allow("k") {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("k") {
		t.Fatal("second immediate call should be denied")
	}
	l.mu.Lock()
	l.buckets["k"].last = l.buckets["k"].last.Add(-2 * time.Second)
	l.mu.Unlock()
	if !l.Allow("k") {
		t.Fatal("after ~2s of refill the call should be allowed again")
	}
}

// A 5 per hour burst 3 limiter needs 36 minutes to refill, so an 11 minute idle sweep must not reset it.
func TestEvictionDoesNotResetASlowLimiter(t *testing.T) {
	l := New(5.0/60.0, 3) // same construction as api.New for RELAY_REGISTER_PER_HOUR=5, BURST=3
	for i := 0; i < 3; i++ {
		if !l.Allow("ip") {
			t.Fatalf("burst call %d denied", i+1)
		}
	}
	if l.Allow("ip") {
		t.Fatal("4th immediate call should be denied")
	}

	l.mu.Lock()
	l.buckets["ip"].last = time.Now().Add(-11 * time.Minute)
	l.lastEvict = time.Now().Add(-2 * evictInterval)
	l.mu.Unlock()

	// 11 minutes at 5/hour is about 0.9 tokens, so still under one: must be denied.
	if l.Allow("ip") {
		t.Fatal("allowed after 11 idle minutes: eviction handed back a full burst, only ~0.9 token would have refilled")
	}
}
