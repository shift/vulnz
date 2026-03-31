package workspace_test

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/workspace"
)

var _ = Describe("Workspace Manager", func() {
	var (
		manager      *workspace.Manager
		tempDir      string
		providerName string
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
		manager = workspace.NewManager(tempDir)
		providerName = "test-provider"
	})

	Describe("Initialization", func() {
		Context("when initializing a new workspace", func() {
			It("should create workspace directories", func() {
				err := manager.Initialize(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Verify workspace root exists
				workspacePath := manager.GetPath(providerName)
				info, err := os.Stat(workspacePath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should create input directory", func() {
				err := manager.Initialize(providerName)
				Expect(err).NotTo(HaveOccurred())

				inputPath := manager.GetInputPath(providerName)
				info, err := os.Stat(inputPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should create results directory", func() {
				err := manager.Initialize(providerName)
				Expect(err).NotTo(HaveOccurred())

				resultsPath := manager.GetResultsPath(providerName)
				info, err := os.Stat(resultsPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should be idempotent", func() {
				err := manager.Initialize(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Initialize again
				err = manager.Initialize(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Directories should still exist
				Expect(manager.Exists(providerName)).To(BeTrue())
			})

			It("should handle multiple providers", func() {
				providers := []string{"alpine", "debian", "ubuntu"}

				for _, provider := range providers {
					err := manager.Initialize(provider)
					Expect(err).NotTo(HaveOccurred())
					Expect(manager.Exists(provider)).To(BeTrue())
				}
			})
		})

		Context("with special characters in provider name", func() {
			It("should handle hyphens", func() {
				err := manager.Initialize("alpine-3.18")
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.Exists("alpine-3.18")).To(BeTrue())
			})

			It("should handle underscores", func() {
				err := manager.Initialize("ubuntu_focal")
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.Exists("ubuntu_focal")).To(BeTrue())
			})
		})
	})

	Describe("State management", func() {
		BeforeEach(func() {
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when writing state", func() {
			It("should write state atomically", func() {
				state := &workspace.State{
					Provider:  providerName,
					URLs:      []string{"https://example.com/data.json"},
					Store:     "sqlite",
					Timestamp: time.Now(),
					Version:   1,
				}

				err := manager.UpdateState(providerName, state)
				Expect(err).NotTo(HaveOccurred())

				// Verify metadata file exists
				metadataPath := manager.GetMetadataPath(providerName)
				info, err := os.Stat(metadataPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Size()).To(BeNumerically(">", 0))
			})

			It("should create metadata.json with pretty printing", func() {
				state := &workspace.State{
					Provider:  providerName,
					URLs:      []string{"https://example.com/data.json"},
					Store:     "flat-file",
					Timestamp: time.Now(),
					Version:   1,
				}

				err := manager.UpdateState(providerName, state)
				Expect(err).NotTo(HaveOccurred())

				// Read file and check formatting
				data, err := os.ReadFile(manager.GetMetadataPath(providerName))
				Expect(err).NotTo(HaveOccurred())

				content := string(data)
				Expect(content).To(ContainSubstring("\n"))
				Expect(content).To(ContainSubstring("  ")) // Indentation
			})

			It("should overwrite existing state", func() {
				state1 := &workspace.State{
					Provider:  providerName,
					URLs:      []string{"https://example.com/v1.json"},
					Store:     "sqlite",
					Timestamp: time.Now(),
					Version:   1,
				}

				err := manager.UpdateState(providerName, state1)
				Expect(err).NotTo(HaveOccurred())

				// Update with new state
				state2 := &workspace.State{
					Provider:  providerName,
					URLs:      []string{"https://example.com/v2.json"},
					Store:     "flat-file",
					Timestamp: time.Now().Add(time.Hour),
					Version:   2,
				}

				err = manager.UpdateState(providerName, state2)
				Expect(err).NotTo(HaveOccurred())

				// Read and verify it's the new state
				retrieved, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Version).To(Equal(2))
				Expect(retrieved.URLs).To(ContainElement("https://example.com/v2.json"))
			})

			It("should create workspace directory if it doesn't exist", func() {
				newProvider := "new-provider"
				state := &workspace.State{
					Provider:  newProvider,
					Store:     "sqlite",
					Timestamp: time.Now(),
					Version:   1,
				}

				err := manager.UpdateState(newProvider, state)
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.Exists(newProvider)).To(BeTrue())
			})
		})

		Context("when reading state", func() {
			var originalState *workspace.State

			BeforeEach(func() {
				originalState = &workspace.State{
					Provider:            providerName,
					URLs:                []string{"https://example.com/data.json", "https://example.com/meta.json"},
					Store:               "sqlite",
					Timestamp:           time.Now().UTC().Truncate(time.Second),
					Version:             1,
					DistributionVersion: 5,
					Stale:               false,
					Processor:           "vulnz-go/v1.0.0",
				}

				err := manager.UpdateState(providerName, originalState)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should read existing state", func() {
				state, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())
				Expect(state).NotTo(BeNil())
				Expect(state.Provider).To(Equal(providerName))
				Expect(state.Store).To(Equal("sqlite"))
				Expect(state.Version).To(Equal(1))
			})

			It("should preserve all state fields", func() {
				state, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())

				Expect(state.URLs).To(HaveLen(2))
				Expect(state.URLs).To(ContainElement("https://example.com/data.json"))
				Expect(state.URLs).To(ContainElement("https://example.com/meta.json"))
				Expect(state.DistributionVersion).To(Equal(5))
				Expect(state.Stale).To(BeFalse())
				Expect(state.Processor).To(Equal("vulnz-go/v1.0.0"))
			})

			It("should return error for non-existent state", func() {
				state, err := manager.GetState("non-existent-provider")
				Expect(err).To(HaveOccurred())
				Expect(state).To(BeNil())
			})

			It("should preserve timestamp", func() {
				state, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Timestamps should be equal (within reasonable tolerance)
				Expect(state.Timestamp.Unix()).To(Equal(originalState.Timestamp.Unix()))
			})
		})

		Context("with complex state structures", func() {
			It("should handle state with listing metadata", func() {
				state := &workspace.State{
					Provider:  providerName,
					Store:     "flat-file",
					Timestamp: time.Now(),
					Version:   1,
					Listing: &workspace.File{
						Path:         "checksums",
						Checksum:     "abcdef1234567890",
						Algorithm:    "xxh64",
						LastModified: time.Now(),
					},
				}

				err := manager.UpdateState(providerName, state)
				Expect(err).NotTo(HaveOccurred())

				retrieved, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Listing).NotTo(BeNil())
				Expect(retrieved.Listing.Path).To(Equal("checksums"))
				Expect(retrieved.Listing.Checksum).To(Equal("abcdef1234567890"))
			})

			It("should handle empty URL list", func() {
				state := &workspace.State{
					Provider:  providerName,
					URLs:      []string{},
					Store:     "sqlite",
					Timestamp: time.Now(),
					Version:   1,
				}

				err := manager.UpdateState(providerName, state)
				Expect(err).NotTo(HaveOccurred())

				retrieved, err := manager.GetState(providerName)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.URLs).To(BeEmpty())
			})
		})
	})

	Describe("Path operations", func() {
		It("should return correct workspace path", func() {
			path := manager.GetPath(providerName)
			expectedPath := filepath.Join(tempDir, providerName)
			Expect(path).To(Equal(expectedPath))
		})

		It("should return correct input path", func() {
			path := manager.GetInputPath(providerName)
			expectedPath := filepath.Join(tempDir, providerName, workspace.InputDir)
			Expect(path).To(Equal(expectedPath))
		})

		It("should return correct results path", func() {
			path := manager.GetResultsPath(providerName)
			expectedPath := filepath.Join(tempDir, providerName, workspace.ResultsDir)
			Expect(path).To(Equal(expectedPath))
		})

		It("should return correct metadata path", func() {
			path := manager.GetMetadataPath(providerName)
			expectedPath := filepath.Join(tempDir, providerName, workspace.MetadataFilename)
			Expect(path).To(Equal(expectedPath))
		})

		It("should return correct checksum path", func() {
			path := manager.GetChecksumPath(providerName)
			expectedPath := filepath.Join(tempDir, providerName, workspace.ChecksumFilename)
			Expect(path).To(Equal(expectedPath))
		})
	})

	Describe("Cleanup operations", func() {
		BeforeEach(func() {
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())

			// Create some test files
			inputFile := filepath.Join(manager.GetInputPath(providerName), "test-input.json")
			err = os.WriteFile(inputFile, []byte(`{"test": "input"}`), 0644)
			Expect(err).NotTo(HaveOccurred())

			resultsFile := filepath.Join(manager.GetResultsPath(providerName), "test-result.json")
			err = os.WriteFile(resultsFile, []byte(`{"test": "result"}`), 0644)
			Expect(err).NotTo(HaveOccurred())

			state := &workspace.State{
				Provider:  providerName,
				Store:     "sqlite",
				Timestamp: time.Now(),
				Version:   1,
			}
			err = manager.UpdateState(providerName, state)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when clearing entire workspace", func() {
			It("should remove all workspace data", func() {
				err := manager.Clear(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Workspace should not exist
				Expect(manager.Exists(providerName)).To(BeFalse())
			})

			It("should remove input, results, and state", func() {
				err := manager.Clear(providerName)
				Expect(err).NotTo(HaveOccurred())

				// None of the paths should exist
				_, err = os.Stat(manager.GetInputPath(providerName))
				Expect(os.IsNotExist(err)).To(BeTrue())

				_, err = os.Stat(manager.GetResultsPath(providerName))
				Expect(os.IsNotExist(err)).To(BeTrue())

				_, err = os.Stat(manager.GetMetadataPath(providerName))
				Expect(os.IsNotExist(err)).To(BeTrue())
			})

			It("should handle non-existent workspace", func() {
				err := manager.Clear("non-existent-provider")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when clearing only input directory", func() {
			It("should remove input directory", func() {
				err := manager.ClearInput(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Input directory should be empty but exist
				inputPath := manager.GetInputPath(providerName)
				entries, err := os.ReadDir(inputPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(entries).To(BeEmpty())
			})

			It("should preserve results and state", func() {
				err := manager.ClearInput(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Results should still exist
				resultsFile := filepath.Join(manager.GetResultsPath(providerName), "test-result.json")
				_, err = os.Stat(resultsFile)
				Expect(err).NotTo(HaveOccurred())

				// State should still exist
				Expect(manager.HasState(providerName)).To(BeTrue())
			})

			It("should recreate input directory after clearing", func() {
				err := manager.ClearInput(providerName)
				Expect(err).NotTo(HaveOccurred())

				info, err := os.Stat(manager.GetInputPath(providerName))
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})
		})

		Context("when clearing only results directory", func() {
			It("should remove results directory", func() {
				err := manager.ClearResults(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Results directory should be empty but exist
				resultsPath := manager.GetResultsPath(providerName)
				entries, err := os.ReadDir(resultsPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(entries).To(BeEmpty())
			})

			It("should preserve input and state", func() {
				err := manager.ClearResults(providerName)
				Expect(err).NotTo(HaveOccurred())

				// Input should still exist
				inputFile := filepath.Join(manager.GetInputPath(providerName), "test-input.json")
				_, err = os.Stat(inputFile)
				Expect(err).NotTo(HaveOccurred())

				// State should still exist
				Expect(manager.HasState(providerName)).To(BeTrue())
			})

			It("should recreate results directory after clearing", func() {
				err := manager.ClearResults(providerName)
				Expect(err).NotTo(HaveOccurred())

				info, err := os.Stat(manager.GetResultsPath(providerName))
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})
		})
	})

	Describe("Workspace existence checks", func() {
		It("should return false for non-existent workspace", func() {
			Expect(manager.Exists("non-existent")).To(BeFalse())
		})

		It("should return true for existing workspace", func() {
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Exists(providerName)).To(BeTrue())
		})

		It("should return false after clearing workspace", func() {
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())

			err = manager.Clear(providerName)
			Expect(err).NotTo(HaveOccurred())

			Expect(manager.Exists(providerName)).To(BeFalse())
		})
	})

	Describe("State existence checks", func() {
		BeforeEach(func() {
			err := manager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return false when no state exists", func() {
			Expect(manager.HasState(providerName)).To(BeFalse())
		})

		It("should return true after writing state", func() {
			state := &workspace.State{
				Provider:  providerName,
				Store:     "sqlite",
				Timestamp: time.Now(),
				Version:   1,
			}

			err := manager.UpdateState(providerName, state)
			Expect(err).NotTo(HaveOccurred())

			Expect(manager.HasState(providerName)).To(BeTrue())
		})

		It("should return false for non-existent provider", func() {
			Expect(manager.HasState("non-existent")).To(BeFalse())
		})
	})

	Describe("Provider listing", func() {
		Context("with no providers", func() {
			It("should return empty list", func() {
				providers, err := manager.ListProviders()
				Expect(err).NotTo(HaveOccurred())
				Expect(providers).To(BeEmpty())
			})
		})

		Context("with multiple providers", func() {
			BeforeEach(func() {
				providerNames := []string{"alpine", "debian", "ubuntu", "nvd"}
				for _, name := range providerNames {
					err := manager.Initialize(name)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should list all provider names", func() {
				providers, err := manager.ListProviders()
				Expect(err).NotTo(HaveOccurred())
				Expect(providers).To(HaveLen(4))
				Expect(providers).To(ContainElement("alpine"))
				Expect(providers).To(ContainElement("debian"))
				Expect(providers).To(ContainElement("ubuntu"))
				Expect(providers).To(ContainElement("nvd"))
			})

			It("should only include directories", func() {
				// Create a file in the root
				filePath := filepath.Join(tempDir, "not-a-provider.txt")
				err := os.WriteFile(filePath, []byte("test"), 0644)
				Expect(err).NotTo(HaveOccurred())

				providers, err := manager.ListProviders()
				Expect(err).NotTo(HaveOccurred())
				Expect(providers).To(HaveLen(4)) // Should not include the file
			})
		})

		Context("when workspace root doesn't exist", func() {
			It("should return empty list without error", func() {
				nonExistentManager := workspace.NewManager(filepath.Join(tempDir, "non-existent"))
				providers, err := nonExistentManager.ListProviders()
				Expect(err).NotTo(HaveOccurred())
				Expect(providers).To(BeEmpty())
			})
		})
	})

	Describe("Edge cases", func() {
		It("should handle deeply nested workspace root", func() {
			deepPath := filepath.Join(tempDir, "a", "b", "c", "d", "workspace")
			deepManager := workspace.NewManager(deepPath)

			err := deepManager.Initialize(providerName)
			Expect(err).NotTo(HaveOccurred())
			Expect(deepManager.Exists(providerName)).To(BeTrue())
		})

		It("should handle concurrent initialization", func() {
			// This is a simple test - full concurrency is tested in concurrency_bdd_test.go
			err1 := manager.Initialize(providerName)
			err2 := manager.Initialize(providerName)

			Expect(err1).NotTo(HaveOccurred())
			Expect(err2).NotTo(HaveOccurred())
			Expect(manager.Exists(providerName)).To(BeTrue())
		})

		It("should handle state with nil listing", func() {
			state := &workspace.State{
				Provider:  providerName,
				Store:     "sqlite",
				Timestamp: time.Now(),
				Version:   1,
				Listing:   nil,
			}

			err := manager.UpdateState(providerName, state)
			Expect(err).NotTo(HaveOccurred())

			retrieved, err := manager.GetState(providerName)
			Expect(err).NotTo(HaveOccurred())
			Expect(retrieved.Listing).To(BeNil())
		})
	})
})
