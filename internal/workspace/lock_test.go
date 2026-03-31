package workspace

import (
	"sync"
	"testing"
	"time"
)

func TestLocker_LockUnlock(t *testing.T) {
	locker := NewLocker()
	providerName := "alpine"

	// Lock should not block
	locker.Lock(providerName)

	// Unlock
	locker.Unlock(providerName)

	// Lock again should work
	locker.Lock(providerName)
	locker.Unlock(providerName)
}

func TestLocker_TryLock(t *testing.T) {
	locker := NewLocker()
	providerName := "alpine"

	// First TryLock should succeed
	if !locker.TryLock(providerName) {
		t.Error("First TryLock should succeed")
	}

	// Second TryLock should fail (already locked)
	if locker.TryLock(providerName) {
		t.Error("Second TryLock should fail when already locked")
	}

	// Unlock
	locker.Unlock(providerName)

	// TryLock should succeed again
	if !locker.TryLock(providerName) {
		t.Error("TryLock should succeed after unlock")
	}
	locker.Unlock(providerName)
}

func TestLocker_MultipleProviders(t *testing.T) {
	locker := NewLocker()

	// Lock different providers
	locker.Lock("alpine")
	locker.Lock("ubuntu")
	locker.Lock("debian")

	// All should be locked independently
	if locker.TryLock("alpine") {
		t.Error("alpine should be locked")
	}
	if locker.TryLock("ubuntu") {
		t.Error("ubuntu should be locked")
	}
	if locker.TryLock("debian") {
		t.Error("debian should be locked")
	}

	// Unlock one
	locker.Unlock("alpine")

	// alpine should be available, others still locked
	if !locker.TryLock("alpine") {
		t.Error("alpine should be unlocked")
	}
	locker.Unlock("alpine")

	if locker.TryLock("ubuntu") {
		t.Error("ubuntu should still be locked")
	}

	// Unlock remaining
	locker.Unlock("ubuntu")
	locker.Unlock("debian")
}

func TestLocker_ConcurrentAccess(t *testing.T) {
	locker := NewLocker()
	providerName := "alpine"
	counter := 0
	numGoroutines := 10
	incrementsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch goroutines that increment counter
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				locker.Lock(providerName)
				counter++
				locker.Unlock(providerName)
			}
		}()
	}

	wg.Wait()

	expected := numGoroutines * incrementsPerGoroutine
	if counter != expected {
		t.Errorf("Counter mismatch: got %d, want %d (race condition detected)", counter, expected)
	}
}

func TestLocker_DifferentProvidersParallel(t *testing.T) {
	locker := NewLocker()
	providers := []string{"alpine", "ubuntu", "debian"}
	counters := make(map[string]int)
	var mu sync.Mutex

	var wg sync.WaitGroup

	// Launch goroutines for each provider
	for _, provider := range providers {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				locker.Lock(p)
				mu.Lock()
				counters[p]++
				mu.Unlock()
				locker.Unlock(p)
			}
		}(provider)
	}

	wg.Wait()

	// Verify each provider's counter
	for _, provider := range providers {
		if counters[provider] != 100 {
			t.Errorf("Counter for %s: got %d, want 100", provider, counters[provider])
		}
	}
}

func TestLocker_BlockingBehavior(t *testing.T) {
	locker := NewLocker()
	providerName := "alpine"

	// Lock in main goroutine
	locker.Lock(providerName)

	blocked := make(chan bool, 1)
	unblocked := make(chan bool, 1)

	// Try to lock in another goroutine
	go func() {
		blocked <- true
		locker.Lock(providerName) // This should block
		unblocked <- true
		locker.Unlock(providerName)
	}()

	// Wait for goroutine to reach the lock
	<-blocked
	time.Sleep(50 * time.Millisecond)

	// Verify it's still blocked
	select {
	case <-unblocked:
		t.Error("Goroutine should be blocked")
	default:
		// Good, it's blocked
	}

	// Unlock
	locker.Unlock(providerName)

	// Verify it unblocks
	select {
	case <-unblocked:
		// Good, it unblocked
	case <-time.After(1 * time.Second):
		t.Error("Goroutine did not unblock after unlock")
	}
}

func TestLocker_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	locker := NewLocker()
	providerName := "alpine"
	numGoroutines := 50
	operationsPerGoroutine := 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				if j%2 == 0 {
					locker.Lock(providerName)
					// Simulate some work
					time.Sleep(time.Microsecond)
					locker.Unlock(providerName)
				} else {
					if locker.TryLock(providerName) {
						time.Sleep(time.Microsecond)
						locker.Unlock(providerName)
					}
				}
			}
		}()
	}

	wg.Wait()
}

func TestLocker_UnlockWithoutLock(t *testing.T) {
	locker := NewLocker()
	providerName := "alpine"

	// This should not panic or cause issues
	locker.Unlock(providerName)

	// Lock and unlock should still work
	locker.Lock(providerName)
	locker.Unlock(providerName)
}

func TestLocker_MultipleLockers(t *testing.T) {
	// Create two separate lockers
	locker1 := NewLocker()
	locker2 := NewLocker()
	providerName := "alpine"

	// Lock with first locker
	locker1.Lock(providerName)

	// Second locker should be independent
	if !locker2.TryLock(providerName) {
		t.Error("Second locker should be independent")
	}

	locker1.Unlock(providerName)
	locker2.Unlock(providerName)
}
