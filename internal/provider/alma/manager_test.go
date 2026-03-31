package alma_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/alma"
)

var _ = Describe("AlmaLinux Manager", func() {
	var (
		manager       *alma.Manager
		tempDir       string
		config        provider.Config
		advisoriesDir string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "alma-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		advisoriesDir = filepath.Join(tempDir, "advisories")
		Expect(os.MkdirAll(filepath.Join(advisoriesDir, "almalinux8"), 0755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(advisoriesDir, "almalinux9"), 0755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(advisoriesDir, "almalinux10"), 0755)).To(Succeed())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "alma",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = alma.NewManagerWithVersions(config, []int{8, 9})
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("NormalizeEcosystem", func() {
		It("should convert AlmaLinux:8 to alma:8", func() {
			Expect(alma.NormalizeEcosystem("AlmaLinux:8")).To(Equal("alma:8"))
		})

		It("should convert ALMALINUX:9 to alma:9", func() {
			Expect(alma.NormalizeEcosystem("ALMALINUX:9")).To(Equal("alma:9"))
		})

		It("should handle already lowercase", func() {
			Expect(alma.NormalizeEcosystem("alma:8")).To(Equal("alma:8"))
		})
	})

	Context("WalkAdvisories", func() {
		writeAdvisory := func(version int, filename string, advisory map[string]interface{}) {
			data, err := json.MarshalIndent(advisory, "", "  ")
			Expect(err).NotTo(HaveOccurred())
			dir := filepath.Join(advisoriesDir, fmt.Sprintf("almalinux%d", version))
			Expect(os.WriteFile(filepath.Join(dir, filename), data, 0644)).To(Succeed())
		}

		BeforeEach(func() {
			writeAdvisory(8, "ALSA-2024:3251.json", map[string]interface{}{
				"id":      "ALSA-2024:3251",
				"summary": "openssl security update",
				"affected": []interface{}{
					map[string]interface{}{
						"package": map[string]interface{}{
							"ecosystem": "AlmaLinux:8",
							"name":      "openssl",
						},
						"ranges": []interface{}{
							map[string]interface{}{
								"type": "ECOSYSTEM",
								"events": []interface{}{
									map[string]interface{}{"introduced": "0"},
									map[string]interface{}{"fixed": "1.1.1k-12.el8_9"},
								},
							},
						},
					},
				},
				"published": "2024-05-07T00:00:00Z",
				"details":   "openssl security fix",
			})

			writeAdvisory(9, "ALSA-2024:3252.json", map[string]interface{}{
				"id":      "ALSA-2024:3252",
				"summary": "kernel security update",
				"affected": []interface{}{
					map[string]interface{}{
						"package": map[string]interface{}{
							"ecosystem": "AlmaLinux:9",
							"name":      "kernel",
						},
					},
				},
				"published": "2024-05-08T00:00:00Z",
			})
		})

		It("should walk and parse advisories from configured versions", func() {
			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, tempDir)

			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).NotTo(BeNil())
			Expect(len(advisories)).To(Equal(2))
		})

		It("should produce correct identifiers", func() {
			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, tempDir)

			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).To(HaveKey("alma:8/alsa-2024:3251"))
			Expect(advisories).To(HaveKey("alma:9/alsa-2024:3252"))
		})

		It("should normalize ecosystems in affected packages", func() {
			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, tempDir)

			Expect(err).NotTo(HaveOccurred())

			adv := advisories["alma:8/alsa-2024:3251"]
			Expect(adv).NotTo(BeNil())

			affected := adv["affected"].([]interface{})
			Expect(affected).To(HaveLen(1))

			pkg := affected[0].(map[string]interface{})["package"].(map[string]interface{})
			Expect(pkg["ecosystem"]).To(Equal("alma:8"))
		})

		It("should inject namespace metadata", func() {
			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, tempDir)

			Expect(err).NotTo(HaveOccurred())

			adv := advisories["alma:8/alsa-2024:3251"]
			Expect(adv["namespace"]).To(Equal("alma:8"))

			metadata := adv["metadata"].(map[string]interface{})
			Expect(metadata["source"]).To(Equal("almalinux-osv"))
			Expect(metadata["distro"]).To(Equal("alma"))
			Expect(metadata["version"]).To(Equal(8))
			Expect(metadata["format"]).To(Equal("osv"))
		})
	})

	Context("when handling empty directories", func() {
		It("should return empty map when no advisories found", func() {
			emptyDir, err := os.MkdirTemp("", "alma-empty-test-*")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(emptyDir)

			Expect(os.MkdirAll(filepath.Join(emptyDir, "advisories", "almalinux8"), 0755)).To(Succeed())

			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, emptyDir)

			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).NotTo(BeNil())
			Expect(len(advisories)).To(Equal(0))
		})
	})

	Context("when handling malformed JSON", func() {
		It("should return error on invalid JSON file", func() {
			badDir, err := os.MkdirTemp("", "alma-bad-test-*")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(badDir)

			advDir := filepath.Join(badDir, "advisories", "almalinux8")
			Expect(os.MkdirAll(advDir, 0755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(advDir, "bad.json"), []byte(`{invalid json}`), 0644)).To(Succeed())

			ctx := context.Background()
			_, err = manager.WalkAdvisories(ctx, badDir)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse"))
		})
	})

	Context("when handling advisories without ID", func() {
		It("should skip advisories with missing ID", func() {
			noIdDir, err := os.MkdirTemp("", "alma-noid-test-*")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(noIdDir)

			advDir := filepath.Join(noIdDir, "advisories", "almalinux8")
			Expect(os.MkdirAll(advDir, 0755)).To(Succeed())

			data, _ := json.Marshal(map[string]interface{}{"summary": "no id"})
			Expect(os.WriteFile(filepath.Join(advDir, "noid.json"), data, 0644)).To(Succeed())

			ctx := context.Background()
			advisories, err := manager.WalkAdvisories(ctx, noIdDir)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(advisories)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation during walk", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.WalkAdvisories(ctx, tempDir)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the default repo URL", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal("https://github.com/AlmaLinux/osv-database.git"))
		})
	})
})
