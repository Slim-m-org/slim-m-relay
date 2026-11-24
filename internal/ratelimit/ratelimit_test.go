// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

// ageBucket makes key look last used d ago, keeping the usage order the sweep relies on.
func ageBucket(l *Limiter, key string, d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el := l.buckets[key]
	el.Value.(*bucket).last = time.Now().Add(-d)
	l.order.MoveToBack(el)
}

func bucketCount(l *Limiter) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

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

	if got := bucketCount(l); got != 2 {
		t.Fatalf("setup: want 2 buckets before eviction, got %d", got)
	}
	// Age both buckets past the 10-minute idle cutoff so the next call sweeps them.
	ageBucket(l, "stale-a", 11*time.Minute)
	ageBucket(l, "stale-b", 11*time.Minute)

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

	l.Allow("k")
	l.Return("k")
	l.Return("k")
	l.mu.Lock()
	got := l.buckets["k"].Value.(*bucket).tokens
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
	ageBucket(l, "k", 2*time.Second)
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

	ageBucket(l, "ip", 11*time.Minute)

	// 11 minutes at 5/hour is about 0.9 tokens, so still under one: must be denied.
	if l.Allow("ip") {
		t.Fatal("allowed after 11 idle minutes: eviction handed back a full burst, only ~0.9 token would have refilled")
	}
}

func TestTheBucketCountNeverPassesTheCap(t *testing.T) {
	l := New(0, 1)
	l.maxBuckets = 5
	for i := 0; i < 50; i++ {
		l.Allow(fmt.Sprintf("ip-%d", i))
	}
	if got := bucketCount(l); got != 5 {
		t.Fatalf("buckets = %d after 50 distinct keys, want the cap of 5", got)
	}
}

// A flood of distinct addresses shares one bucket past the cap and never resets a tracked
// key's spent budget to make room.
func TestKeysPastTheCapShareOneOverflowBucketAndTrackedKeysAreUntouched(t *testing.T) {
	l := New(0, 1)
	l.maxBuckets = 2
	if !l.Allow("a") || !l.Allow("b") {
		t.Fatal("setup: the two tracked keys should each get their burst")
	}
	if !l.Allow("c") {
		t.Fatal("the first key past the cap should draw the overflow bucket's burst")
	}
	if l.Allow("d") {
		t.Error("a second new key past the cap should find the shared overflow bucket spent")
	}
	if l.Allow("a") {
		t.Error("a tracked key's spent budget was reset to make room for a newcomer")
	}
}

func TestTheCapIsRelievedOnceBucketsGoIdle(t *testing.T) {
	l := New(0, 1)
	l.maxBuckets = 2
	l.Allow("a")
	l.Allow("b")
	ageBucket(l, "a", 11*time.Minute)
	ageBucket(l, "b", 11*time.Minute)

	if !l.Allow("c") || !l.Allow("d") {
		t.Fatal("with room freed by the idle sweep, each new key should get its own bucket")
	}
	if l.Allow("c") {
		t.Error("c should be tracked on its own after the sweep, not share an overflow bucket")
	}
}

func TestOneCallSweepsAtMostAChunkSoTheLockIsNeverHeldForAFullPass(t *testing.T) {
	l := New(60, 1)
	const n = 1000
	for i := 0; i < n; i++ {
		l.Allow(fmt.Sprintf("ip-%d", i))
	}
	for i := 0; i < n; i++ {
		ageBucket(l, fmt.Sprintf("ip-%d", i), 11*time.Minute)
	}
	l.Allow("trigger")
	if got, want := bucketCount(l), n-sweepChunk+1; got != want {
		t.Fatalf("buckets after one call = %d, want %d (one chunk swept, one added)", got, want)
	}
	for i := 0; i < n/sweepChunk+1; i++ {
		l.Allow("trigger")
	}
	if got := bucketCount(l); got != 1 {
		t.Errorf("buckets after repeated calls = %d, want only the live one", got)
	}
}

func TestRetryAfterIsTheTimeOneTokenTakesToRefill(t *testing.T) {
	for _, c := range []struct {
		perMinute float64
		want      time.Duration
	}{
		{60, time.Second},
		{120, time.Second},
		{1, time.Minute},
		{10, 6 * time.Second},
		{5.0 / 60, 12 * time.Minute},
		{0, 0},
	} {
		if got := New(c.perMinute, 1).RetryAfter(); got != c.want {
			t.Errorf("%v per minute: RetryAfter = %v, want %v", c.perMinute, got, c.want)
		}
	}
}

func TestRetryAfterNNeverWaitsOnALimiterThatDoesNotRefill(t *testing.T) {
	l := New(0, 2)
	l.AllowN("k", 2)
	if got := l.RetryAfterN("k", 2); got != 0 {
		t.Errorf("RetryAfterN on a non-refilling limiter = %v, want 0", got)
	}
}

func TestRetryAfterNIsZeroForAKeyWithNoBucketOrEnoughTokens(t *testing.T) {
	l := New(60, 10)
	if got := l.RetryAfterN("unseen", 5); got != 0 {
		t.Errorf("RetryAfterN for an unseen key = %v, want 0", got)
	}
	l.AllowN("k", 2)
	if got := l.RetryAfterN("k", 5); got != 0 {
		t.Errorf("RetryAfterN with 8 of 10 tokens left and a cost of 5 = %v, want 0", got)
	}
}

func TestRetryAfterNCoversTheWholeShortfall(t *testing.T) {
	l := New(60, 10) // one token a second
	if !l.AllowN("k", 10) {
		t.Fatal("a full bucket should allow its whole burst")
	}
	if got := l.RetryAfterN("k", 5); got != 5*time.Second {
		t.Errorf("RetryAfterN(5) from empty = %v, want 5s", got)
	}
	if got := l.RetryAfterN("k", 1); got != time.Second {
		t.Errorf("RetryAfterN(1) from empty = %v, want 1s", got)
	}
}

func TestRetryAfterNClampsACostAboveTheBurstAndBelowOne(t *testing.T) {
	l := New(60, 4)
	l.AllowN("k", 4)
	if got := l.RetryAfterN("k", 100); got != 4*time.Second {
		t.Errorf("RetryAfterN(100) = %v, want 4s: the cost clamps to the burst", got)
	}
	if got := l.RetryAfterN("k", 0); got != time.Second {
		t.Errorf("RetryAfterN(0) = %v, want 1s: a zero cost is charged as one", got)
	}
}

func TestAllowNChargesAtLeastOneToken(t *testing.T) {
	l := New(0, 2)
	if !l.AllowN("k", 0) || !l.AllowN("k", -3) {
		t.Fatal("the first two charges should fit the burst")
	}
	if l.AllowN("k", 0) {
		t.Error("a zero cost must still spend one token, so a third charge is refused")
	}
}

func TestReturnNGivesTokensBackUpToTheBurst(t *testing.T) {
	l := New(0, 5)
	l.AllowN("k", 5)
	l.ReturnN("k", 3)
	if !l.AllowN("k", 3) {
		t.Error("3 returned tokens should be spendable")
	}
	if l.Allow("k") {
		t.Error("only the 3 returned tokens should have come back")
	}
	l.ReturnN("k", 100)
	if !l.AllowN("k", 5) {
		t.Error("returning more than the burst should refill to the burst")
	}
	if l.Allow("k") {
		t.Error("a return must never lift the bucket above the burst")
	}
}

func TestReturnNIgnoresNonPositiveCountsAndUnknownKeys(t *testing.T) {
	l := New(0, 2)
	l.AllowN("k", 2)
	l.ReturnN("k", 0)
	l.ReturnN("k", -4)
	if l.Allow("k") {
		t.Error("a non-positive return must not give tokens back")
	}
	l.ReturnN("never-seen", 5)
	if got := bucketCount(l); got != 1 {
		t.Errorf("buckets = %d, want 1: returning to an unseen key must not create one", got)
	}
}
