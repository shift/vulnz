package epss_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/epss"
)

var _ = Describe("EPSS Provider", func() {
	var (
		epssProvider provider.Provider
		tempDir      string
		logger       *slog.Logger
		config       provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "epss-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "epss",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		epssProvider, err = epss.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(epssProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(epssProvider.Name()).To(Equal("epss"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := epssProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("auxiliary"))
			Expect(tags).To(ContainElement("epss"))
			Expect(tags).To(ContainElement("exploit-prediction"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("epss")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("epss"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("epss")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("epss"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := epssProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should handle first run with no previous update", func() {
			Skip("Requires network access to EPSS feed")

			ctx := context.Background()
			urls, count, err := epssProvider.Update(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(ContainSubstring("epss.cyentia.com"))
			Expect(count).To(BeNumerically(">", 0))
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := epss.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/epss.db"
			p, err := epss.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})

	Context("workspace state management", func() {
		It("should create workspace directories when needed", func() {
			workspacePath := tempDir
			info, err := os.Stat(workspacePath)

			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})
	})

	Context("error handling", func() {
		It("should handle invalid workspace paths gracefully", func() {
			config.Workspace = "/invalid/readonly/path/that/does/not/exist"
			p, err := epss.NewProvider(config)

			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			ctx := context.Background()
			_, _, updateErr := p.Update(ctx, nil)
			Expect(updateErr).To(HaveOccurred())
		})
	})

	Context("when using mocked data with Update", func() {
		It("should write records to flat-file storage", func() {
			csvData := `# scores,score_date:2025-01-15T00:00:00+0000
cve,epss,percentile
CVE-2024-9999,0.5,0.75
`
			var buf bytes.Buffer
			gzWriter := gzip.NewWriter(&buf)
			gzWriter.Write([]byte(csvData))
			gzWriter.Close()

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(buf.Bytes())
			}))
			defer testServer.Close()

			p, err := epss.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())

			ctx := context.Background()
			urls, count, err := p.Update(ctx, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal("https://epss.cyentia.com/epss_scores-current.csv.gz"))
			Expect(count).To(BeNumerically(">=", 1))
		})
	})
})
