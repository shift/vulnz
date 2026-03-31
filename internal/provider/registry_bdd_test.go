package provider_test

import (
	"fmt"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
)

var _ = Describe("Provider Registry", func() {
	BeforeEach(func() {
		// Reset registry before each test
		provider.Reset()
	})

	AfterEach(func() {
		// Clean up after each test
		provider.Reset()
	})

	Describe("Registration", func() {
		Context("when registering a new provider", func() {
			It("should register provider factory successfully", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("test-provider", factory)

				retrieved, ok := provider.Get("test-provider")
				Expect(ok).To(BeTrue())
				Expect(retrieved).NotTo(BeNil())
			})

			It("should allow multiple different providers", func() {
				factory1 := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}
				factory2 := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("provider-1", factory1)
				provider.Register("provider-2", factory2)

				Expect(provider.Count()).To(Equal(2))
			})
		})

		Context("when registering duplicate providers", func() {
			It("should panic on duplicate registration", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("duplicate", factory)

				// Second registration should panic
				Expect(func() {
					provider.Register("duplicate", factory)
				}).To(Panic())
			})

			It("should include provider name in panic message", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("my-provider", factory)

				defer func() {
					if r := recover(); r != nil {
						message := r.(string)
						Expect(message).To(ContainSubstring("my-provider"))
						Expect(message).To(ContainSubstring("already registered"))
					}
				}()

				provider.Register("my-provider", factory)
			})
		})

		Context("with various provider names", func() {
			It("should handle names with hyphens", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("alpine-3.18", factory)

				retrieved, ok := provider.Get("alpine-3.18")
				Expect(ok).To(BeTrue())
				Expect(retrieved).NotTo(BeNil())
			})

			It("should handle names with underscores", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("ubuntu_focal", factory)

				retrieved, ok := provider.Get("ubuntu_focal")
				Expect(ok).To(BeTrue())
				Expect(retrieved).NotTo(BeNil())
			})

			It("should be case-sensitive", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("Alpine", factory)

				_, ok := provider.Get("Alpine")
				Expect(ok).To(BeTrue())

				_, ok = provider.Get("alpine")
				Expect(ok).To(BeFalse())
			})
		})
	})

	Describe("Retrieval", func() {
		BeforeEach(func() {
			factory := func(config provider.Config) (provider.Provider, error) {
				return nil, nil
			}

			provider.Register("alpine", factory)
			provider.Register("debian", factory)
			provider.Register("ubuntu", factory)
		})

		It("should return factory for registered provider", func() {
			factory, ok := provider.Get("alpine")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should return false for non-existent provider", func() {
			factory, ok := provider.Get("non-existent")
			Expect(ok).To(BeFalse())
			Expect(factory).To(BeNil())
		})

		It("should return false for empty string", func() {
			factory, ok := provider.Get("")
			Expect(ok).To(BeFalse())
			Expect(factory).To(BeNil())
		})
	})

	Describe("Listing", func() {
		Context("with no providers", func() {
			It("should return empty list", func() {
				providers := provider.List()
				Expect(providers).To(BeEmpty())
			})
		})

		Context("with multiple providers", func() {
			BeforeEach(func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("ubuntu", factory)
				provider.Register("alpine", factory)
				provider.Register("debian", factory)
				provider.Register("nvd", factory)
			})

			It("should return all registered provider names", func() {
				providers := provider.List()
				Expect(providers).To(HaveLen(4))
				Expect(providers).To(ContainElement("alpine"))
				Expect(providers).To(ContainElement("debian"))
				Expect(providers).To(ContainElement("ubuntu"))
				Expect(providers).To(ContainElement("nvd"))
			})

			It("should return sorted list", func() {
				providers := provider.List()
				Expect(providers).To(HaveLen(4))

				// Should be alphabetically sorted
				Expect(providers[0]).To(Equal("alpine"))
				Expect(providers[1]).To(Equal("debian"))
				Expect(providers[2]).To(Equal("nvd"))
				Expect(providers[3]).To(Equal("ubuntu"))
			})
		})
	})

	Describe("Count", func() {
		It("should return zero for empty registry", func() {
			Expect(provider.Count()).To(Equal(0))
		})

		It("should return correct count after registrations", func() {
			factory := func(config provider.Config) (provider.Provider, error) {
				return nil, nil
			}

			provider.Register("provider1", factory)
			Expect(provider.Count()).To(Equal(1))

			provider.Register("provider2", factory)
			Expect(provider.Count()).To(Equal(2))

			provider.Register("provider3", factory)
			Expect(provider.Count()).To(Equal(3))
		})

		It("should not change count on duplicate registration attempt", func() {
			factory := func(config provider.Config) (provider.Provider, error) {
				return nil, nil
			}

			provider.Register("provider1", factory)
			Expect(provider.Count()).To(Equal(1))

			// Try to register duplicate (will panic)
			Expect(func() {
				provider.Register("provider1", factory)
			}).To(Panic())

			// Count should remain 1
			Expect(provider.Count()).To(Equal(1))
		})
	})

	Describe("Reset", func() {
		BeforeEach(func() {
			factory := func(config provider.Config) (provider.Provider, error) {
				return nil, nil
			}

			provider.Register("provider1", factory)
			provider.Register("provider2", factory)
			provider.Register("provider3", factory)
		})

		It("should clear all registered providers", func() {
			Expect(provider.Count()).To(Equal(3))

			provider.Reset()

			Expect(provider.Count()).To(Equal(0))
			Expect(provider.List()).To(BeEmpty())
		})

		It("should allow re-registration after reset", func() {
			factory := func(config provider.Config) (provider.Provider, error) {
				return nil, nil
			}

			provider.Reset()

			// Should not panic
			provider.Register("provider1", factory)
			Expect(provider.Count()).To(Equal(1))
		})
	})

	Describe("Thread-safety", func() {
		Context("concurrent registrations", func() {
			It("should handle concurrent registrations of different providers", func() {
				var wg sync.WaitGroup
				providerCount := 50

				for i := 0; i < providerCount; i++ {
					wg.Add(1)
					go func(index int) {
						defer wg.Done()

						factory := func(config provider.Config) (provider.Provider, error) {
							return nil, nil
						}

						providerName := fmt.Sprintf("provider-%d", index)
						provider.Register(providerName, factory)
					}(i)
				}

				wg.Wait()

				Expect(provider.Count()).To(Equal(providerCount))
			})

			It("should prevent duplicate registration race", func() {
				var wg sync.WaitGroup
				panicCount := atomic.Int32{}

				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				// Try to register same provider from multiple goroutines
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								panicCount.Add(1)
							}
						}()

						provider.Register("duplicate-provider", factory)
					}()
				}

				wg.Wait()

				// Only one should succeed, others should panic
				Expect(provider.Count()).To(Equal(1))
				Expect(panicCount.Load()).To(Equal(int32(9)))
			})
		})

		Context("concurrent lookups", func() {
			BeforeEach(func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				provider.Register("alpine", factory)
				provider.Register("debian", factory)
				provider.Register("ubuntu", factory)
			})

			It("should handle concurrent Get operations", func() {
				var wg sync.WaitGroup
				successCount := atomic.Int32{}

				for i := 0; i < 100; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						_, ok := provider.Get("alpine")
						if ok {
							successCount.Add(1)
						}
					}()
				}

				wg.Wait()

				Expect(successCount.Load()).To(Equal(int32(100)))
			})

			It("should handle concurrent List operations", func() {
				var wg sync.WaitGroup

				for i := 0; i < 100; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						providers := provider.List()
						Expect(providers).To(HaveLen(3))
					}()
				}

				wg.Wait()
			})

			It("should handle concurrent Count operations", func() {
				var wg sync.WaitGroup

				for i := 0; i < 100; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						count := provider.Count()
						Expect(count).To(Equal(3))
					}()
				}

				wg.Wait()
			})
		})

		Context("mixed concurrent operations", func() {
			It("should handle concurrent reads and resets", func() {
				factory := func(config provider.Config) (provider.Provider, error) {
					return nil, nil
				}

				// Register initial providers
				provider.Register("p1", factory)
				provider.Register("p2", factory)

				var wg sync.WaitGroup

				// Concurrent readers
				for i := 0; i < 50; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						provider.List()
						provider.Count()
						provider.Get("p1")
					}()
				}

				// Single reset in the middle
				wg.Add(1)
				go func() {
					defer wg.Done()
					provider.Reset()
				}()

				wg.Wait()

				// After reset, count should be 0
				Eventually(func() int {
					return provider.Count()
				}).Should(Equal(0))
			})
		})
	})

	Describe("Factory function behavior", func() {
		It("should execute factory function when retrieved", func() {
			executed := false
			factory := func(config provider.Config) (provider.Provider, error) {
				executed = true
				return nil, nil
			}

			provider.Register("test-factory", factory)

			// Get doesn't execute the factory, just returns it
			retrievedFactory, ok := provider.Get("test-factory")
			Expect(ok).To(BeTrue())
			Expect(executed).To(BeFalse())

			// Execute the factory
			_, err := retrievedFactory(provider.Config{})
			Expect(err).NotTo(HaveOccurred())
			Expect(executed).To(BeTrue())
		})

		It("should preserve factory closure state", func() {
			counter := 0
			factory := func(config provider.Config) (provider.Provider, error) {
				counter++
				return nil, nil
			}

			provider.Register("closure-test", factory)

			retrievedFactory, _ := provider.Get("closure-test")

			_, _ = retrievedFactory(provider.Config{})
			Expect(counter).To(Equal(1))

			_, _ = retrievedFactory(provider.Config{})
			Expect(counter).To(Equal(2))
		})
	})
})
