package euvdmapping_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	euvdmapping "github.com/shift/vulnz/internal/provider/euvd-mapping"
)

var _ = Describe("EUVD Mapping Manager", func() {
	var (
		manager    *euvdmapping.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	testCSV := "euvd_id,cve_id\nEUVD-2023-1001,CVE-2023-1001\nEUVD-2023-1002,CVE-2023-1002\nEUVD-2023-1003,CVE-2023-1003\n"

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "euvd-mapping-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "euvd-mapping",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
		}
		os.RemoveAll(tempDir)
	})

	Context("when fetching CVE-EUVD mapping", func() {
		It("should download and parse CSV successfully", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte(testCSV))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			mappings, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(mappings).To(HaveLen(3))
		})

		It("should save raw CSV to workspace", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte(testCSV))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "cve-euvd-mapping.csv")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("euvd_id,cve_id"))
		})

		It("should correctly parse mapping records", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte(testCSV))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			mappings, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(mappings[0].EuvdID).To(Equal("EUVD-2023-1001"))
			Expect(mappings[0].CveID).To(Equal("CVE-2023-1001"))
			Expect(mappings[2].EuvdID).To(Equal("EUVD-2023-1003"))
			Expect(mappings[2].CveID).To(Equal("CVE-2023-1003"))
		})

		It("should handle empty CSV (header only)", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte("euvd_id,cve_id\n"))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			mappings, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(mappings).To(BeEmpty())
		})

		It("should skip malformed rows", func() {
			csv := "euvd_id,cve_id\nEUVD-2023-1001,CVE-2023-1001\nmalformed_row\nEUVD-2023-1002,CVE-2023-1002\n"

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte(csv))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			mappings, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(mappings).To(HaveLen(2))
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on HTTP failure", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv")
				w.Write([]byte(testCSV))
			}))

			manager = euvdmapping.NewManagerWithURL(testServer.URL, config)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the configured URL", func() {
			manager = euvdmapping.NewManagerWithURL("https://example.com/test.csv", config)
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal("https://example.com/test.csv"))
		})
	})
})
