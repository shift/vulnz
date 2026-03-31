package euvdmapping_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	euvdmapping "github.com/shift/vulnz/internal/provider/euvd-mapping"
)

var _ = Describe("EUVD Mapping Provider", func() {
	var (
		mappingProvider provider.Provider
		tempDir         string
		logger          *slog.Logger
		config          provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "euvd-mapping-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "euvd-mapping",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		mappingProvider, err = euvdmapping.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(mappingProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(mappingProvider.Name()).To(Equal("euvd-mapping"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := mappingProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("auxiliary"))
			Expect(tags).To(ContainElement("mapping"))
			Expect(tags).To(ContainElement("euvd"))
			Expect(tags).To(ContainElement("enisa"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("euvd-mapping")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("euvd-mapping"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("euvd-mapping")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("euvd-mapping"))
		})
	})

	Context("when updating mapping data", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, _, err := mappingProvider.Update(ctx, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should handle first run with no previous update", func() {
			Skip("Requires network access to EUVD mapping dump")

			ctx := context.Background()
			urls, count, err := mappingProvider.Update(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(urls).NotTo(BeEmpty())
			Expect(count).To(BeNumerically(">", 0))
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := euvdmapping.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			config.Storage.Path = tempDir + "/mapping.db"
			p, err := euvdmapping.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})
})
