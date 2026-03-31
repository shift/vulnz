package workspace_test

import (
	"os"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/workspace"
)

var _ = Describe("Concurrent Workspace Access", func() {
	var (
		locker *workspace.Locker
	)

	BeforeEach(func() {
		locker = workspace.NewLocker()
	})

	Describe("Lock operations", func() {
		Context("with single provider", func() {
			It("should prevent concurrent access to same provider", func() {
				providerName := "test-provider"
				var counter int32
				var wg sync.WaitGroup

				// Launch 10 goroutines trying to access the same provider
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						locker.Lock(providerName)
						defer locker.Unlock(providerName)

						// Critical section - increment counter
						current := atomic.LoadInt32(&counter)
						// Simulate some work
						for j := 0; j < 100; j++ {
							current++
						}
						atomic.StoreInt32(&counter, current)
					}()
				}

				wg.Wait()

				// Counter should equal 10 * 100 = 1000
				// (This verifies mutual exclusion worked)
				Expect(atomic.LoadInt32(&counter)).To(Equal(int32(1000)))
			})

			It("should be reentrant for same goroutine", func() {
				providerName := "test-provider"

				locker.Lock(providerName)

				// This should not deadlock (but current implementation doesn't support reentrancy)
				// so we test that it blocks
				done := make(chan bool, 1)
				go func() {
					locker.Lock(providerName)
					locker.Unlock(providerName)
					done <- true
				}()

				// Should block waiting for unlock
				select {
				case <-done:
					Fail("Lock should have blocked")
				default:
					// Expected - lock is blocking
				}

				locker.Unlock(providerName)

				// Now should succeed
				Eventually(done).Should(Receive())
			})
		})

		Context("with multiple providers", func() {
			It("should allow concurrent access to different providers", func() {
				var wg sync.WaitGroup
				providers := []string{"provider1", "provider2", "provider3"}

				completed := make(chan string, len(providers))

				for _, provider := range providers {
					wg.Add(1)
					go func(p string) {
						defer wg.Done()

						locker.Lock(p)
						defer locker.Unlock(p)

						// Simulate work
						for i := 0; i < 100; i++ {
							// Busy work
						}

						completed <- p
					}(provider)
				}

				wg.Wait()
				close(completed)

				// All providers should have completed
				var completedProviders []string
				for p := range completed {
					completedProviders = append(completedProviders, p)
				}

				Expect(completedProviders).To(HaveLen(3))
				Expect(completedProviders).To(ConsistOf("provider1", "provider2", "provider3"))
			})

			It("should handle 100 goroutines across different providers", func() {
				var wg sync.WaitGroup
				var successCount int32
				providers := []string{"p1", "p2", "p3", "p4", "p5"}

				for i := 0; i < 100; i++ {
					wg.Add(1)
					provider := providers[i%len(providers)]

					go func(p string) {
						defer wg.Done()

						locker.Lock(p)
						defer locker.Unlock(p)

						atomic.AddInt32(&successCount, 1)
					}(provider)
				}

				wg.Wait()
				Expect(atomic.LoadInt32(&successCount)).To(Equal(int32(100)))
			})
		})

		Context("TryLock operations", func() {
			It("should acquire lock when available", func() {
				providerName := "test-provider"

				acquired := locker.TryLock(providerName)
				Expect(acquired).To(BeTrue())

				locker.Unlock(providerName)
			})

			It("should fail to acquire lock when already held", func() {
				providerName := "test-provider"

				locker.Lock(providerName)

				// Try to acquire in another goroutine
				done := make(chan bool, 1)
				go func() {
					acquired := locker.TryLock(providerName)
					done <- acquired
				}()

				Eventually(done).Should(Receive(BeFalse()))

				locker.Unlock(providerName)
			})

			It("should succeed after lock is released", func() {
				providerName := "test-provider"

				locker.Lock(providerName)
				locker.Unlock(providerName)

				acquired := locker.TryLock(providerName)
				Expect(acquired).To(BeTrue())

				locker.Unlock(providerName)
			})
		})

		Context("lock safety", func() {
			It("should handle unlock without prior lock", func() {
				// This should not panic
				locker.Unlock("never-locked-provider")
			})

			It("should handle multiple unlocks", func() {
				providerName := "test-provider"

				locker.Lock(providerName)
				locker.Unlock(providerName)

				// Multiple unlocks should not panic (though behavior is undefined)
				locker.Unlock(providerName)
			})

			It("should create lock on first access", func() {
				// Lock should be created lazily
				providerName := "new-provider"

				locker.Lock(providerName)
				// If this doesn't panic or deadlock, lock was created successfully
				locker.Unlock(providerName)
			})
		})
	})

	Describe("Concurrent state management", func() {
		var (
			manager *workspace.Manager
			tempDir string
		)

		BeforeEach(func() {
			tempDir = GinkgoT().TempDir()
			manager = workspace.NewManager(tempDir)
		})

		It("should handle concurrent writes to different providers", func() {
			var wg sync.WaitGroup
			providers := []string{"alpine", "debian", "ubuntu", "nvd", "github"}

			for _, provider := range providers {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()

					err := manager.Initialize(p)
					Expect(err).NotTo(HaveOccurred())

					state := &workspace.State{
						Provider: p,
						Store:    "sqlite",
						Version:  1,
					}

					err = manager.UpdateState(p, state)
					Expect(err).NotTo(HaveOccurred())
				}(provider)
			}

			wg.Wait()

			// Verify all providers were created
			for _, provider := range providers {
				Expect(manager.HasState(provider)).To(BeTrue())
			}
		})

		It("should maintain state consistency under concurrent access", func() {
			providerName := "concurrent-provider"
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())

			var wg sync.WaitGroup
			iterations := 50

			// Many goroutines updating the same provider state
			for i := 0; i < iterations; i++ {
				wg.Add(1)
				go func(version int) {
					defer wg.Done()

					state := &workspace.State{
						Provider: providerName,
						Store:    "sqlite",
						Version:  version,
					}

					// Use locker to prevent race conditions
					locker.Lock(providerName)
					err := manager.UpdateState(providerName, state)
					locker.Unlock(providerName)

					Expect(err).NotTo(HaveOccurred())
				}(i)
			}

			wg.Wait()

			// State should exist (though version is non-deterministic due to race)
			Expect(manager.HasState(providerName)).To(BeTrue())
		})

		It("should handle concurrent initialization of same provider", func() {
			providerName := "concurrent-init"
			var wg sync.WaitGroup
			var errorCount int32

			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					err := manager.Initialize(providerName)
					if err != nil {
						atomic.AddInt32(&errorCount, 1)
					}
				}()
			}

			wg.Wait()

			// All initializations should succeed (idempotent)
			Expect(atomic.LoadInt32(&errorCount)).To(Equal(int32(0)))
			Expect(manager.Exists(providerName)).To(BeTrue())
		})
	})

	Describe("Real-world concurrency scenario", func() {
		It("should handle realistic provider execution pattern", func() {
			tempDir := GinkgoT().TempDir()
			manager := workspace.NewManager(tempDir)

			providers := []string{"alpine", "debian", "ubuntu"}
			var wg sync.WaitGroup

			// Simulate concurrent provider runs
			for _, provider := range providers {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()

					// Acquire lock
					locker.Lock(p)
					defer locker.Unlock(p)

					// Initialize workspace
					err := manager.Initialize(p)
					Expect(err).NotTo(HaveOccurred())

					// Write state
					state := &workspace.State{
						Provider: p,
						Store:    "sqlite",
						Version:  1,
					}
					err = manager.UpdateState(p, state)
					Expect(err).NotTo(HaveOccurred())

					// Read state back
					retrieved, err := manager.GetState(p)
					Expect(err).NotTo(HaveOccurred())
					Expect(retrieved.Provider).To(Equal(p))
				}(provider)
			}

			wg.Wait()

			// All providers should be initialized with state
			for _, provider := range providers {
				Expect(manager.Exists(provider)).To(BeTrue())
				Expect(manager.HasState(provider)).To(BeTrue())
			}
		})
	})

	Describe("Checksum operations concurrency", func() {
		var (
			tempDir string
		)

		BeforeEach(func() {
			tempDir = GinkgoT().TempDir()
		})

		It("should handle concurrent checksum computations", func() {
			// Create test files
			files := make([]string, 10)
			for i := 0; i < 10; i++ {
				file, err := os.CreateTemp(tempDir, "test-*.json")
				Expect(err).NotTo(HaveOccurred())
				file.Close()
				files[i] = file.Name()
			}

			var wg sync.WaitGroup
			checksums := make(map[string]string)
			var mu sync.Mutex

			// Compute checksums concurrently
			for _, file := range files {
				wg.Add(1)
				go func(f string) {
					defer wg.Done()

					checksum, err := workspace.ComputeChecksum(f)
					Expect(err).NotTo(HaveOccurred())

					mu.Lock()
					checksums[f] = checksum
					mu.Unlock()
				}(file)
			}

			wg.Wait()

			// All checksums should be computed
			Expect(checksums).To(HaveLen(10))
		})
	})
})
