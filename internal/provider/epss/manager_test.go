package epss_test

import (
	"bytes"
	"compress/gzip"
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
	"github.com/shift/vulnz/internal/provider/epss"
)

var _ = Describe("EPSS Manager", func() {
	var (
		manager    *epss.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	generateGzippedCSV := func(csvContent string) []byte {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		gzWriter.Write([]byte(csvContent))
		gzWriter.Close()
		return buf.Bytes()
	}

	validCSV := `# scores generated 2025-03-28,see EPSS documentation for details,score_date:2025-03-28T00:00:00+0000,model_version:1.0.0
cve,epss,percentile
CVE-2023-1234,0.0253,0.4567
CVE-2023-5678,0.9812,0.9934
CVE-2024-0001,0.0010,0.0123
`

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "epss-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(generateGzippedCSV(validCSV))
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "epss",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = epss.NewManagerWithURL(testServer.URL, config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching EPSS data", func() {
		It("should download and parse EPSS data successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(3))
		})

		It("should save decompressed CSV to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "epss_data.csv")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("CVE-2023-1234"))
			Expect(string(content)).To(ContainSubstring("cve,epss,percentile"))
		})

		It("should create proper records with correct fields", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-1234"]
			Expect(record).NotTo(BeNil())
			Expect(record["cve"]).To(Equal("CVE-2023-1234"))
			Expect(record["epss"]).To(Equal(0.0253))
			Expect(record["percentile"]).To(Equal(0.4567))
			Expect(record["date"]).To(Equal("2025-03-28"))
			Expect(record["namespace"]).To(Equal("epss"))
		})

		It("should parse all CVE records correctly", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CVE-2023-1234"))
			Expect(records).To(HaveKey("CVE-2023-5678"))
			Expect(records).To(HaveKey("CVE-2024-0001"))

			Expect(records["CVE-2023-5678"]["epss"]).To(Equal(0.9812))
			Expect(records["CVE-2023-5678"]["percentile"]).To(Equal(0.9934))
			Expect(records["CVE-2024-0001"]["epss"]).To(Equal(0.0010))
			Expect(records["CVE-2024-0001"]["percentile"]).To(Equal(0.0123))
		})

		It("should extract date from comment line", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				Expect(record["date"]).To(Equal("2025-03-28"))
			}
		})

		It("should skip records with empty CVE", func() {
			testServer.Close()
			csvData := `# comment,score_date:2025-01-01T00:00:00+0000
cve,epss,percentile
,0.5,0.5
CVE-2023-1111,0.1,0.2
`
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(generateGzippedCSV(csvData))
			}))
			manager = epss.NewManagerWithURL(testServer.URL, config)

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
			manager = epss.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error on HTTP failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling invalid gzip data", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write([]byte("not valid gzip data"))
			}))
			manager = epss.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error on invalid gzip", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling missing score_date", func() {
		BeforeEach(func() {
			testServer.Close()
			csvData := `# some random comment without score_date
cve,epss,percentile
CVE-2023-1111,0.1,0.2
`
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(generateGzippedCSV(csvData))
			}))
			manager = epss.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error when score_date is missing", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("score_date"))
		})
	})

	Context("when handling empty data", func() {
		BeforeEach(func() {
			testServer.Close()
			csvData := `# comment,score_date:2025-01-01T00:00:00+0000
cve,epss,percentile
`
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(generateGzippedCSV(csvData))
			}))
			manager = epss.NewManagerWithURL(testServer.URL, config)
		})

		It("should return empty map for no data rows", func() {
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
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(generateGzippedCSV(validCSV))
			}))
			manager = epss.NewManagerWithURL(testServer.URL, config)

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
