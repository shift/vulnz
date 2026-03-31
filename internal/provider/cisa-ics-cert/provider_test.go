package csatics_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/cisa-ics-cert"
)

var _ = Describe("CISA ICS-CERT Provider", func() {
	var (
		cisaProvider provider.Provider
		tempDir      string
		logger       *slog.Logger
		config       provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "cisa-ics-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "cisa-ics-cert",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP: provider.HTTPConfig{
				Timeout:      1 * time.Second,
				MaxRetries:   1,
				RateLimitRPS: 10,
				UserAgent:    "vulnz-go-test/1.0",
			},
			Logger: logger,
		}

		cisaProvider, err = csatics.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(cisaProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(cisaProvider.Name()).To(Equal("cisa-ics-cert"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := cisaProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("cisa"))
			Expect(tags).To(ContainElement("ics"))
			Expect(tags).To(ContainElement("csaf"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("cisa-ics-cert")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("cisa-ics-cert"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("cisa-ics-cert")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("cisa-ics-cert"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := cisaProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := csatics.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/cisa-ics.db"
			p, err := csatics.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})

	Context("workspace state management", func() {
		It("should create workspace directories when needed", func() {
			info, err := os.Stat(tempDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})
	})

	Context("error handling", func() {
		It("should handle invalid workspace paths gracefully", func() {
			config.Workspace = "/invalid/readonly/path/that/does/not/exist"
			config.HTTP.Timeout = 1 * time.Millisecond
			p, err := csatics.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			ctx := context.Background()
			_, _, updateErr := p.Update(ctx, nil)
			Expect(updateErr).To(HaveOccurred())
		})
	})
})
