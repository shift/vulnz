package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// hostPool manages connection pool for a specific host
type hostPool struct {
	client *http.Client
	mu     sync.Mutex
}

// poolManager manages per-host connection pools
type poolManager struct {
	pools           map[string]*hostPool
	mu              sync.RWMutex
	maxConnsPerHost int
}

// newPoolManager creates a new pool manager with the specified max connections per host
func newPoolManager(maxConnsPerHost int) *poolManager {
	return &poolManager{
		pools:           make(map[string]*hostPool),
		maxConnsPerHost: maxConnsPerHost,
	}
}

// getPool retrieves or creates a connection pool for the given host
func (pm *poolManager) getPool(host string) *hostPool {
	// Fast path: read lock
	pm.mu.RLock()
	pool, exists := pm.pools[host]
	pm.mu.RUnlock()

	if exists {
		return pool
	}

	// Slow path: write lock and create
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Double-check after acquiring write lock
	if pool, exists := pm.pools[host]; exists {
		return pool
	}

	// Create new pool with dedicated transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          pm.maxConnsPerHost,
		MaxIdleConnsPerHost:   pm.maxConnsPerHost,
		MaxConnsPerHost:       pm.maxConnsPerHost * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Transport: transport,
		// Timeout is set per-request in Client.Get
	}

	pool = &hostPool{
		client: client,
	}

	pm.pools[host] = pool
	return pool
}
