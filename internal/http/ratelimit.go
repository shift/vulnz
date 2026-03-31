package http

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-host rate limiting using token bucket algorithm
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	rps      int
	mu       sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with the specified requests per second per host
func NewRateLimiter(rps int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
	}
}

// Wait blocks until the request can proceed for the given host
func (rl *RateLimiter) Wait(ctx context.Context, host string) error {
	limiter := rl.getLimiter(host)
	return limiter.Wait(ctx)
}

// Allow checks if the request can proceed immediately for the given host
func (rl *RateLimiter) Allow(host string) bool {
	limiter := rl.getLimiter(host)
	return limiter.Allow()
}

// getLimiter retrieves or creates a rate limiter for the given host
func (rl *RateLimiter) getLimiter(host string) *rate.Limiter {
	// Fast path: read lock
	rl.mu.RLock()
	limiter, exists := rl.limiters[host]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	// Slow path: write lock and create
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rl.limiters[host]; exists {
		return limiter
	}

	// Create new limiter with token bucket algorithm
	// rate.Limit(rps) sets tokens per second
	// rps is the burst size (allows burst up to RPS requests)
	limiter = rate.NewLimiter(rate.Limit(rl.rps), rl.rps)
	rl.limiters[host] = limiter

	return limiter
}
