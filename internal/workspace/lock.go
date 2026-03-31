package workspace

import (
	"sync"
)

// Locker provides workspace-level file locking to prevent concurrent access
// to the same provider workspace. This is an in-process lock using
// buffered channels as binary semaphores. Safe to call Unlock without
// a matching Lock (no panic).
type Locker struct {
	locks map[string]chan struct{}
	mu    sync.RWMutex
}

// NewLocker creates a new workspace locker.
func NewLocker() *Locker {
	return &Locker{
		locks: make(map[string]chan struct{}),
	}
}

// Lock acquires an exclusive lock for the given provider workspace.
// This blocks until the lock is acquired.
func (l *Locker) Lock(providerName string) {
	l.mu.Lock()
	sem, exists := l.locks[providerName]
	if !exists {
		sem = make(chan struct{}, 1)
		l.locks[providerName] = sem
	}
	l.mu.Unlock()

	sem <- struct{}{}
}

// Unlock releases the lock for the given provider workspace.
// If the lock is not currently held, this is a no-op.
func (l *Locker) Unlock(providerName string) {
	l.mu.RLock()
	sem, exists := l.locks[providerName]
	l.mu.RUnlock()

	if !exists {
		return
	}

	select {
	case <-sem:
	default:
	}
}

// TryLock attempts to acquire a lock without blocking.
// Returns true if the lock was acquired, false otherwise.
func (l *Locker) TryLock(providerName string) bool {
	l.mu.Lock()
	sem, exists := l.locks[providerName]
	if !exists {
		sem = make(chan struct{}, 1)
		l.locks[providerName] = sem
	}
	l.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}
