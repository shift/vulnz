package bitnami_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/bitnami"
)

func writeTestAdvisory(dir string, relPath string, advisory map[string]interface{}) error {
	fullPath := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(advisory, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

var _ = Describe("Bitnami Manager", func() {
	var (
		manager *bitnami.Manager
		tempDir string
		config  provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "bitnami-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "bitnami",
			Workspace: tempDir,
			Logger:    logger,
		}

		manager = bitnami.NewManager(bitnami.DefaultRepoURL, config)
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("walkAdvisories", func() {
		BeforeEach(func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(os.MkdirAll(dataDir, 0755)).To(Succeed())

			Expect(writeTestAdvisory(dataDir, "BITNAMI-CVE-2023-1234.json", map[string]interface{}{
				"id":        "BITNAMI-CVE-2023-1234",
				"published": "2023-06-15T00:00:00Z",
				"summary":   "Test advisory 1",
				"affected":  []interface{}{map[string]interface{}{"package": map[string]interface{}{"name": "nginx"}}},
			})).To(Succeed())

			Expect(writeTestAdvisory(dataDir, "BITNAMI-CVE-2023-5678.json", map[string]interface{}{
				"id":        "BITNAMI-CVE-2023-5678",
				"published": "2023-07-20T00:00:00Z",
				"summary":   "Test advisory 2",
			})).To(Succeed())

			Expect(writeTestAdvisory(dataDir, "subdir/BITNAMI-CVE-2024-0001.json", map[string]interface{}{
				"id":        "BITNAMI-CVE-2024-0001",
				"published": "2024-01-01T00:00:00Z",
				"summary":   "Nested advisory",
			})).To(Succeed())
		})

		It("should find and parse all JSON advisories", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(3))
		})

		It("should correctly extract advisory IDs", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("BITNAMI-CVE-2023-1234"))
			Expect(records).To(HaveKey("BITNAMI-CVE-2023-5678"))
			Expect(records).To(HaveKey("BITNAMI-CVE-2024-0001"))
		})

		It("should preserve advisory fields", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())

			rec := records["BITNAMI-CVE-2023-1234"]
			Expect(rec["summary"]).To(Equal("Test advisory 1"))
			Expect(rec["published"]).To(Equal("2023-06-15T00:00:00Z"))
		})

		It("should find advisories in subdirectories", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())

			rec := records["BITNAMI-CVE-2024-0001"]
			Expect(rec).NotTo(BeNil())
			Expect(rec["summary"]).To(Equal("Nested advisory"))
		})

		It("should skip non-JSON files", func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(os.WriteFile(filepath.Join(dataDir, "README.md"), []byte("not json"), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dataDir, "notes.txt"), []byte("text"), 0644)).To(Succeed())

			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(3))
		})

		It("should skip JSON files without an id field", func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(writeTestAdvisory(dataDir, "no-id.json", map[string]interface{}{
				"summary": "No ID here",
			})).To(Succeed())

			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(3))
		})

		It("should skip JSON files with empty id field", func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(writeTestAdvisory(dataDir, "empty-id.json", map[string]interface{}{
				"id":      "",
				"summary": "Empty ID",
			})).To(Succeed())

			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(3))
		})
	})

	Context("walkAdvisories with no data directory", func() {
		It("should return error when data directory is missing", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("data directory not found"))
			Expect(records).To(BeNil())
		})
	})

	Context("walkAdvisories with empty data directory", func() {
		BeforeEach(func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(os.MkdirAll(dataDir, 0755)).To(Succeed())
		})

		It("should return empty map", func() {
			records, err := manager.WalkAdvisories()
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("walkAdvisories with malformed JSON", func() {
		BeforeEach(func() {
			dataDir := filepath.Join(tempDir, "input", "vulndb", "data")
			Expect(os.MkdirAll(dataDir, 0755)).To(Succeed())

			Expect(writeTestAdvisory(dataDir, "BITNAMI-CVE-2023-GOOD.json", map[string]interface{}{
				"id":      "BITNAMI-CVE-2023-GOOD",
				"summary": "Valid advisory",
			})).To(Succeed())

			badPath := filepath.Join(dataDir, "bad.json")
			Expect(os.WriteFile(badPath, []byte(`{"invalid": json}`), 0644)).To(Succeed())
		})

		It("should return error for malformed JSON", func() {
			_, err := manager.WalkAdvisories()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse"))
		})
	})

	Context("Get", func() {
		It("should succeed after git clone", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeEmpty())
		})
	})

	Context("cloneRepo idempotency", func() {
		It("should not re-clone if directory exists", func() {
			vulndbDir := filepath.Join(tempDir, "input", "vulndb")
			Expect(os.MkdirAll(vulndbDir, 0755)).To(Succeed())

			ctx := context.Background()
			err := manager.CloneRepo(ctx)
			Expect(err).NotTo(HaveOccurred())

			_, statErr := os.Stat(vulndbDir)
			Expect(statErr).NotTo(HaveOccurred())
		})
	})
})
