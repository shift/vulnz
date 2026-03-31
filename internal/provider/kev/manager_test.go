package kev_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/kev"
)

var _ = Describe("KEV Manager", func() {
	var (
		manager    *kev.Manager
		tempDir    string
		testServer *httptest.Server
		testData   []interface{}
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "kev-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		testData = []interface{}{
			map[string]interface{}{
				"cveId":         "CVE-2023-1234",
				"euvdId":        "EUVD-2023-1234",
				"vendorProject": "Test Vendor",
				"product":       "Test Product",
				"dateAdded":     "2023-01-01",
				"sources":       []string{"cisa_kev"},
			},
			map[string]interface{}{
				"cveId":         "CVE-2023-5678",
				"euvdId":        "EUVD-2023-5678",
				"vendorProject": "Another Vendor",
				"product":       "Another Product",
				"dateAdded":     "2023-02-15",
				"sources":       []string{"cisa_kev", "eukev_kev"},
			},
			map[string]interface{}{
				"cveId":     "CVE-2025-25231",
				"euvdId":    "EUVD-2025-24160",
				"dateAdded": "2025-09-09",
				"sources":   []string{"eukev_kev"},
			},
		}

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testData)
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "kev",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = kev.NewManager(testServer.URL, config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching KEV data", func() {
		It("should download and parse KEV dump successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(3))
		})

		It("should save raw data to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "kev.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed []interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(len(parsed)).To(Equal(3))
		})

		It("should create proper vulnerability records with EU CRA metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-1234"]
			Expect(record).NotTo(BeNil())

			Expect(record["cveId"]).To(Equal("CVE-2023-1234"))
			Expect(record["euvdId"]).To(Equal("EUVD-2023-1234"))
			Expect(record["vendorProject"]).To(Equal("Test Vendor"))
			Expect(record["product"]).To(Equal("Test Product"))
			Expect(record["exploited_in_wild"]).To(BeTrue())
			Expect(record["namespace"]).To(Equal("euvd:kev"))

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["source"]).To(Equal("euvd-kev"))
			Expect(metadata["eu_cra_active_exploitation"]).To(BeTrue())
			Expect(metadata["requires_immediate_action"]).To(BeTrue())
			Expect(metadata["kev_date_added"]).To(Equal("2023-01-01"))
			Expect(metadata["cisa_kev"]).To(BeTrue())
			Expect(metadata["eu_kev"]).To(BeFalse())
		})

		It("should correctly identify dual-source records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-5678"]
			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["cisa_kev"]).To(BeTrue())
			Expect(metadata["eu_kev"]).To(BeTrue())
		})

		It("should correctly identify EU-only records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2025-25231"]
			Expect(record).NotTo(BeNil())
			Expect(record["vendorProject"]).To(BeNil())
			Expect(record["product"]).To(BeNil())

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["cisa_kev"]).To(BeFalse())
			Expect(metadata["eu_kev"]).To(BeTrue())
		})

		It("should set exploited_in_wild flag for all records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for cveID, record := range records {
				exploited, ok := record["exploited_in_wild"].(bool)
				Expect(ok).To(BeTrue(), "Record %s should have exploited_in_wild field", cveID)
				Expect(exploited).To(BeTrue(), "Record %s should have exploited_in_wild=true", cveID)
			}
		})

		It("should skip records with empty CVE ID", func() {
			testData = []interface{}{
				map[string]interface{}{
					"cveId":   "",
					"euvdId":  "EUVD-2023-0000",
					"sources": []string{"cisa_kev"},
				},
				map[string]interface{}{
					"cveId":   "CVE-2023-1111",
					"euvdId":  "EUVD-2023-1111",
					"sources": []string{"cisa_kev"},
				},
			}

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))
			Expect(records).To(HaveKey("CVE-2023-1111"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = kev.NewManager(testServer.URL, config)
		})

		It("should return error on HTTP failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed data", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))
			manager = kev.NewManager(testServer.URL, config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling empty dump", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			}))
			manager = kev.NewManager(testServer.URL, config)
		})

		It("should return empty map for empty dump", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})

		It("should respect context timeout", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				json.NewEncoder(w).Encode(testData)
			}))
			manager = kev.NewManager(testServer.URL, config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the configured URL", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal(testServer.URL))
		})
	})
})
