package middleware

import (
	"hash/fnv"
	"net/http"
	"sync"
	"time"
)

// shardCount is the number of independent lock/map shards IPRateLimiter
// splits its per-IP state across. A single global mutex protecting one
// big map serializes every request through one lock purely to check its
// own IP's bucket, regardless of how many distinct IPs are actually in
// flight concurrently — under load from many different clients, that
// lock itself becomes the bottleneck, not the token-bucket arithmetic
// behind it. Sharding by a hash of the IP spreads that contention across
// shardCount independent locks: two requests from different IPs only
// contend with each other if they happen to hash into the same shard,
// which is 1/shardCount as likely as always contending on one shared
// lock. 16 is a reasonable default for typical instance sizes — large
// enough to meaningfully cut contention, small enough that the fixed
// per-shard bookkeeping (a map, a mutex, a last-sweep timestamp) stays
// cheap.
const shardCount = 16

// IPRateLimiter is an in-memory per-IP token bucket.
//
// Deviation from the framework guide: §6.6/§7.6 specify
// golang.org/x/time/rate backed by Redis for multi-instance consistency.
// This build environment cannot fetch either the module or a Redis client
// library, so this is a hand-rolled, single-instance-only stand-in.
// Swap for the Redis-backed limiter before running more than one replica —
// today, each instance enforces its own independent budget, so the
// effective cluster-wide limit is (per-instance limit × replica count).
type IPRateLimiter struct {
	shards [shardCount]*rateLimiterShard
	rps    float64
	burst  float64
}

type rateLimiterShard struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	lastSwep time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func NewIPRateLimiter(rps int) *IPRateLimiter {
	if rps <= 0 {
		rps = 20
	}
	l := &IPRateLimiter{rps: float64(rps), burst: float64(rps) * 2}
	now := time.Now()
	for i := range l.shards {
		l.shards[i] = &rateLimiterShard{buckets: make(map[string]*bucket), lastSwep: now}
	}
	return l
}

func (l *IPRateLimiter) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIPFrom(r.Context())
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !l.allow(ip) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (l *IPRateLimiter) shardFor(key string) *rateLimiterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // fnv.Write never returns an error
	return l.shards[h.Sum32()%shardCount]
}

func (l *IPRateLimiter) allow(key string) bool {
	shard := l.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	shard.sweepLocked(now)

	b, ok := shard.buckets[key]
	if !ok {
		shard.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked evicts buckets untouched for a while so a long-lived
// process doesn't accumulate an unbounded map of stale per-IP entries.
// Each shard sweeps independently on its own timer, so the cost of a
// sweep (a full scan of that shard's buckets) is spread out rather than
// happening as one large pause across every IP the process has ever
// seen. Caller must hold shard.mu.
func (s *rateLimiterShard) sweepLocked(now time.Time) {
	if now.Sub(s.lastSwep) < 5*time.Minute {
		return
	}
	for key, b := range s.buckets {
		if now.Sub(b.lastSeen) > 10*time.Minute {
			delete(s.buckets, key)
		}
	}
	s.lastSwep = now
}
