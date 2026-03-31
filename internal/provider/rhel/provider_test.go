package rhel_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/rhel"
)

var _ = Describe("RHEL Provider", func() {
	var (
		rhelProvider provider.Provider
		tempDir      string
		logger       *slog.Logger
		config       provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rhel-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "rhel",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		rhelProvider, err = rhel.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(rhelProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(rhelProvider.Name()).To(Equal("rhel"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := rhelProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("os"))
			Expect(tags).To(ContainElement("incremental"))
			Expect(tags).To(ContainElement("large"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("rhel")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("rhel"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("rhel")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("rhel"))
		})
	})

	Context("when updating vulnerability data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := rhelProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := rhel.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/rhel.db"
			p, err := rhel.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})
})
