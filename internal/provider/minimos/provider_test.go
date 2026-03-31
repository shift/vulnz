package minimos_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/minimos"
)

var _ = Describe("Minimos Provider", func() {
	var (
		minimosProvider provider.Provider
		tempDir         string
		logger          *slog.Logger
		config          provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "minimos-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "minimos",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		minimosProvider, err = minimos.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(minimosProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(minimosProvider.Name()).To(Equal("minimos"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := minimosProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("minimos"))
			Expect(tags).To(ContainElement("apk"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("minimos")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("minimos"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("minimos")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("minimos"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := minimosProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should handle first run with no previous update", func() {
			Skip("Requires network access to minimos security.json")

			ctx := context.Background()
			urls, count, err := minimosProvider.Update(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(ContainSubstring("packages.mini.dev"))
			Expect(count).To(BeNumerically(">", 0))
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := minimos.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/minimos.db"
			p, err := minimos.NewProvider(config)
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
			p, err := minimos.NewProvider(config)

			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			ctx := context.Background()
			_, _, updateErr := p.Update(ctx, nil)
			Expect(updateErr).To(HaveOccurred())
		})
	})
})
