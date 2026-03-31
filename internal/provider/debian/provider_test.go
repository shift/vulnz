package debian_test

import (
	"log/slog"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/debian"
)

var _ = Describe("Debian Provider", func() {
	var (
		debianProvider provider.Provider
		tempDir        string
		logger         *slog.Logger
		config         provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "debian-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "debian",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		debianProvider, err = debian.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(debianProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(debianProvider.Name()).To(Equal("debian"))
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := debianProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("debian"))
			Expect(tags).To(ContainElement("dpkg"))
		})
	})

	Context("provider registration", func() {
		It("should be registered in provider registry", func() {
			factory, ok := provider.Get("debian")
			Expect(ok).To(BeTrue())
			Expect(factory).NotTo(BeNil())
		})

		It("should appear in provider list", func() {
			providers := provider.List()
			Expect(providers).To(ContainElement("debian"))
		})

		It("should be able to create provider from registry", func() {
			factory, ok := provider.Get("debian")
			Expect(ok).To(BeTrue())

			p, err := factory(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
			Expect(p.Name()).To(Equal("debian"))
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
			p, err := debian.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})
})
