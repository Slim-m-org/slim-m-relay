// SPDX-License-Identifier: Apache-2.0

// Package ratelimit is a tiny in-memory token bucket keyed by an arbitrary string (client
// IP for registration, key id for sending). It is sufficient for a single-instance relay;
// a multi-instance deployment would move this to a shared store.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// Limiter refills each bucket at a fixed rate up to a burst ceiling. It tracks at most
// maxBuckets keys: keys past that share one overflow bucket rather than growing the map, so
// a flood of distinct client addresses cannot grow the relay's memory without bound.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*list.Element // value is a *bucket
	// order runs from the most to the least recently used bucket, so idle ones are always at
	// the back and a sweep never has to walk the whole map.
	order    *list.List
	overflow *bucket
	rate     float64 // tokens per second
	burst    float64
	// idleAfter is how long a bucket must sit unused to be full again, so dropping it and
	// creating a fresh one behave the same.
	idleAfter  time.Duration
	maxBuckets int
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// defaultMaxBuckets bounds the tracked keys per limiter; one bucket is a few hundred bytes.
const defaultMaxBuckets = 200_000

// sweepChunk bounds how many idle buckets one call drops, so the lock is never held for a
// pass over the whole map; the sweep is amortised across calls instead.
const sweepChunk = 128

// minIdleBeforeEvict is the shortest idle time before a bucket is dropped, however fast it refills.
const minIdleBeforeEvict = 10 * time.Minute

// New builds a Limiter that refills perMinute tokens per minute, up to burst.
func New(perMinute float64, burst int) *Limiter {
	l := &Limiter{
		buckets:    make(map[string]*list.Element),
		order:      list.New(),
		rate:       perMinute / 60.0,
		burst:      float64(burst),
		idleAfter:  minIdleBeforeEvict,
		maxBuckets: defaultMaxBuckets,
	}
	if l.rate > 0 {
		if refill := time.Duration(l.burst / l.rate * float64(time.Second)); refill > l.idleAfter {
			l.idleAfter = refill
		}
	}
	return l
}

// RetryAfter is how long a refused caller should wait for one token to refill, rounded up
// to whole seconds for a Retry-After header. Zero when the limiter never refills.
func (l *Limiter) RetryAfter() time.Duration {
	if l.rate <= 0 {
		return 0
	}
	// The epsilon keeps float error in rate = perMinute/60 from rounding 720.0000000001 up a second.
	return time.Duration(math.Ceil(1/l.rate-1e-6)) * time.Second
}

// Allow reports whether an action for key may proceed, consuming one token if so.
func (l *Limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// AllowN consumes n tokens for key, all or nothing. A cost above the burst is clamped to it,
// so an oversized request is charged the whole bucket rather than refused forever.
func (l *Limiter) AllowN(key string, n int) bool {
	cost := math.Min(float64(n), l.burst)
	if cost < 1 {
		cost = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.evictIdle(now)
	b, fresh := l.bucketFor(key, now, cost)
	if fresh {
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= cost {
		b.tokens -= cost
		return true
	}
	return false
}

// bucketFor returns key's bucket, moved to the front of the usage order. A key seen for the
// first time gets a bucket with its first token already spent and fresh set, so the caller
// allows it without refilling. When the map is full of buckets that are all still in use, the
// key falls back to the shared overflow bucket instead of adding an entry. cost is what the
// first call spends from a new bucket.
func (l *Limiter) bucketFor(key string, now time.Time, cost float64) (b *bucket, fresh bool) {
	if el, ok := l.buckets[key]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*bucket), false
	}
	if len(l.buckets) >= l.maxBuckets {
		if l.overflow == nil {
			l.overflow = &bucket{tokens: l.burst, last: now}
		}
		return l.overflow, false
	}
	b = &bucket{key: key, tokens: l.burst - cost, last: now}
	l.buckets[key] = l.order.PushFront(b)
	return b, true
}

// Return gives back one token to key's bucket, undoing a prior Allow that turned out not to
// be needed - for example a message that consumed a tighter per-key budget (like the call
// kind's) but was then never attempted before the request's deadline fired. It is a no-op
// for a key with no bucket yet, since that means Allow was never called for it.
func (l *Limiter) Return(key string) { l.ReturnN(key, 1) }

// ReturnN gives back n tokens, undoing an AllowN whose work was not all done.
func (l *Limiter) ReturnN(key string, n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.buckets[key]
	if !ok {
		return
	}
	b := el.Value.(*bucket)
	b.tokens += float64(n)
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
}

// evictIdle drops up to sweepChunk buckets from the idle end of the usage order. Must be
// called with l.mu held.
func (l *Limiter) evictIdle(now time.Time) {
	cutoff := now.Add(-l.idleAfter)
	for i := 0; i < sweepChunk; i++ {
		el := l.order.Back()
		if el == nil {
			return
		}
		b := el.Value.(*bucket)
		if !b.last.Before(cutoff) {
			return
		}
		l.order.Remove(el)
		delete(l.buckets, b.key)
	}
}
