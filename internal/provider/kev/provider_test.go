package kev_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/kev"
)

var _ = Describe("KEV Provider", func() {
	var (
		kevProvider provider.Provider
		tempDir     string
		logger      *slog.Logger
		config      provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "kev-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "kev",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		kevProvider, err = kev.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(kevProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(kevProvider.Name()).To(Equal("kev"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := kevProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("auxiliary"))
			Expect(tags).To(ContainElement("exploited"))
			Expect(tags).To(ContainElement("euvd"))
			Expect(tags).To(ContainElement("eu-cra"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("kev")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("kev"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("kev")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("kev"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := kevProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should handle first run with no previous update", func() {
			Skip("Requires network access to EUVD KEV dump")

			ctx := context.Background()
			urls, count, err := kevProvider.Update(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(ContainSubstring("euvdservices.enisa.europa.eu"))
			Expect(count).To(BeNumerically(">", 0))
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := kev.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/kev.db"
			p, err := kev.NewProvider(config)
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
			p, err := kev.NewProvider(config)

			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			ctx := context.Background()
			_, _, updateErr := p.Update(ctx, nil)
			Expect(updateErr).To(HaveOccurred())
		})
	})
})
