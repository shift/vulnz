package fedora_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/fedora"
)

var _ = Describe("Fedora Provider", func() {
	var (
		fedoraProvider provider.Provider
		tempDir        string
		logger         *slog.Logger
		config         provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "fedora-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "fedora",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		fedoraProvider, err = fedora.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(fedoraProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(fedoraProvider.Name()).To(Equal("fedora"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := fedoraProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("fedora"))
			Expect(tags).To(ContainElement("rpm"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("fedora")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("fedora"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("fedora")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("fedora"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := fedoraProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should handle first run with no previous update", func() {
			Skip("Requires network access to Bodhi API")

			ctx := context.Background()
			urls, count, err := fedoraProvider.Update(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(urls)).To(BeNumerically(">", 0))
			Expect(count).To(BeNumerically(">", 0))
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := fedora.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/fedora.db"
			p, err := fedora.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})

	Context("error handling", func() {
		It("should handle invalid workspace paths gracefully", func() {
			config.Workspace = "/invalid/readonly/path/that/does/not/exist"
			p, err := fedora.NewProvider(config)

			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			ctx := context.Background()
			_, _, updateErr := p.Update(ctx, nil)
			Expect(updateErr).To(HaveOccurred())
		})
	})
})
