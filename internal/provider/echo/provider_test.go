package echo_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/echo"
)

var _ = Describe("Echo Provider", func() {
	var (
		echoProvider provider.Provider
		tempDir      string
		logger       *slog.Logger
		config       provider.Config
	)

	BeforeEach(func() {
		// Create temporary workspace
		var err error
		tempDir, err = os.MkdirTemp("", "echo-provider-test-*")
		Expect(err).NotTo(HaveOccurred())

		// Create logger
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		// Create provider config
		config = provider.Config{
			Name:      "echo",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir,
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		// Create provider
		echoProvider, err = echo.NewProvider(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(echoProvider).NotTo(BeNil())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("provider interface implementation", func() {
		It("should return correct name", func() {
			Expect(echoProvider.Name()).To(Equal("echo"))
		})

		It("should implement MetadataProvider interface", func() {
			mp, ok := echoProvider.(provider.MetadataProvider)
			Expect(ok).To(BeTrue())

			metadata := mp.Metadata()
			Expect(metadata.Name).To(Equal("echo"))
			Expect(metadata.Version).To(Equal("1.0.0"))
			Expect(metadata.Description).NotTo(BeEmpty())
		})

		It("should implement TagsProvider interface", func() {
			tp, ok := echoProvider.(provider.TagsProvider)
			Expect(ok).To(BeTrue())

			tags := tp.Tags()
			Expect(tags).To(ContainElement("vulnerability"))
			Expect(tags).To(ContainElement("test"))
		})
	})

	Context("when updating vulnerability data", func() {
		// Note: These tests make real HTTP requests and are skipped in CI
		// Use a mock server in parser_test.go for unit tests

		It("should respect context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond) // Ensure context is cancelled

			_, _, err := echoProvider.Update(ctx, nil)

			// Should fail due to cancelled/timed out context
			Expect(err).To(HaveOccurred())
		})

		It("should create workspace directories", func() {
			// Workspace should be initialized in NewProvider
			inputPath := tempDir + "/echo/input"
			resultsPath := tempDir + "/echo/results"

			inputInfo, err := os.Stat(inputPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(inputInfo.IsDir()).To(BeTrue())

			resultsInfo, err := os.Stat(resultsPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resultsInfo.IsDir()).To(BeTrue())
		})
	})

	Context("when integrating with storage backend", func() {
		It("should support flat-file storage", func() {
			config.Storage.Type = "flat-file"
			p, err := echo.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})

		It("should support SQLite storage", func() {
			config.Storage.Type = "sqlite"
			p, err := echo.NewProvider(config)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())
		})
	})

	Context("workspace state management", func() {
		It("should initialize workspace on provider creation", func() {
			workspacePath := tempDir + "/echo"
			info, err := os.Stat(workspacePath)

			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})
	})

	Context("error handling", func() {
		It("should return error when workspace initialization fails", func() {
			config.Workspace = "/invalid/readonly/path/that/does/not/exist"
			_, err := echo.NewProvider(config)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("workspace"))
		})
	})
})
