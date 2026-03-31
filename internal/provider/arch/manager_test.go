package arch_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/arch"
)

var _ = Describe("Arch Manager", func() {
	var (
		manager    *arch.Manager
		tempDir    string
		testServer *httptest.Server
		asaDates   map[string]string
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "arch-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		asaDates = map[string]string{
			"ASA-2021-1": "2021-06-22",
			"ASA-2021-2": "2021-07-15",
			"ASA-2022-1": "2022-01-10",
		}

		testData := []map[string]interface{}{
			{
				"name":       "AVG-1",
				"group":      1,
				"severity":   "Low",
				"type":       "unknown",
				"status":     "Fixed",
				"affected":   "libpng 1.6.37-1",
				"fixed":      "libpng 1.6.38-1",
				"issues":     []string{"CVE-2021-12345"},
				"advisories": []string{"ASA-2021-1"},
			},
			{
				"name":       "AVG-2",
				"group":      2,
				"severity":   "High",
				"type":       "denial of service",
				"status":     "Fixed",
				"affected":   "openssl 1.1.1k-1, libopenssl 1.1.1k-1",
				"fixed":      "openssl 1.1.1l-1, libopenssl 1.1.1l-1",
				"issues":     []string{"CVE-2021-23456", "CVE-2021-34567"},
				"advisories": []string{"ASA-2021-2"},
			},
			{
				"name":       "AVG-3",
				"group":      3,
				"severity":   "Critical",
				"type":       "remote code execution",
				"status":     "Not affected",
				"affected":   "kernel 5.12-1",
				"fixed":      "",
				"issues":     []string{"CVE-2021-99999"},
				"advisories": []string{},
			},
			{
				"name":       "AVG-4",
				"group":      4,
				"severity":   "Medium",
				"type":       "information disclosure",
				"status":     "Fixed",
				"affected":   "curl 7.77.0-1",
				"fixed":      "curl 7.78.0-1",
				"issues":     []string{},
				"advisories": []string{"ASA-2022-1"},
			},
			{
				"name":       "AVG-5",
				"group":      5,
				"severity":   "Low",
				"type":       "",
				"status":     "Fixed",
				"affected":   "bash 5.1-1",
				"fixed":      "bash 5.1.8-1",
				"issues":     []string{"CVE-2022-11111"},
				"advisories": []string{},
			},
		}

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/all.json" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(testData)
				return
			}

			if strings.HasSuffix(r.URL.Path, "/raw") {
				parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
				if len(parts) >= 2 {
					asaID := parts[len(parts)-2]
					if date, ok := asaDates[asaID]; ok {
						w.Header().Set("Content-Type", "text/plain")
						fmt.Fprintf(w, "Date    : %s\nSeverity: High\nPackage: test\n", date)
						return
					}
				}
				w.WriteHeader(http.StatusNotFound)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "arch",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = arch.NewManagerWithURL(testServer.URL+"/all.json", config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching arch data", func() {
		It("should download and parse all.json successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(5))
		})

		It("should save raw data to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "all.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed []interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(len(parsed)).To(Equal(5))
		})

		It("should filter out Not affected entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(HaveKey("CVE-2021-99999"))
		})

		It("should create one record per CVE per group", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CVE-2021-12345"))
			Expect(records).To(HaveKey("CVE-2021-23456"))
			Expect(records).To(HaveKey("CVE-2021-34567"))
		})

		It("should use AVG name when no CVEs exist", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("AVG-4"))
		})

		It("should map severity correctly", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records["CVE-2021-12345"].Severity).To(Equal("Low"))
			Expect(records["CVE-2021-23456"].Severity).To(Equal("High"))
			Expect(records["AVG-4"].Severity).To(Equal("Medium"))
		})

		It("should set namespace to arch:rolling", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				Expect(r.Namespace).To(Equal("arch:rolling"))
			}
		})

		It("should parse single fixed package", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2021-12345"]
			Expect(record.FixedIn).To(HaveLen(1))
			Expect(record.FixedIn[0].Name).To(Equal("libpng"))
			Expect(record.FixedIn[0].Version).To(Equal("1.6.38-1"))
			Expect(record.FixedIn[0].VersionFormat).To(Equal("pacman"))
		})

		It("should parse multiple fixed packages", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2021-23456"]
			Expect(record.FixedIn).To(HaveLen(2))
			Expect(record.FixedIn[0].Name).To(Equal("openssl"))
			Expect(record.FixedIn[0].Version).To(Equal("1.1.1l-1"))
			Expect(record.FixedIn[1].Name).To(Equal("libopenssl"))
			Expect(record.FixedIn[1].Version).To(Equal("1.1.1l-1"))
		})

		It("should include ASA date as issued in metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2021-12345"]
			Expect(record.Metadata.Issued).To(Equal("2021-06-22"))
		})

		It("should include CVE references in metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2021-23456"]
			Expect(record.Metadata.CVE).To(HaveLen(2))
			Expect(record.Metadata.CVE[0].Name).To(Equal("CVE-2021-23456"))
			Expect(record.Metadata.CVE[0].Link).To(ContainSubstring("CVE-2021-23456"))
			Expect(record.Metadata.CVE[1].Name).To(Equal("CVE-2021-34567"))
		})

		It("should include advisory IDs in metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2021-12345"]
			Expect(record.Metadata.Advisories).To(ConsistOf("ASA-2021-1"))
		})

		It("should set link to security.archlinux.org", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records["CVE-2021-12345"].Link).To(Equal("https://security.archlinux.org/AVG-1"))
			Expect(records["CVE-2021-23456"].Link).To(Equal("https://security.archlinux.org/AVG-2"))
			Expect(records["AVG-4"].Link).To(Equal("https://security.archlinux.org/AVG-4"))
		})

		It("should use type as description or fallback", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records["CVE-2021-12345"].Description).To(Equal("Arch vulnerability AVG-1"))
			Expect(records["CVE-2021-23456"].Description).To(Equal("denial of service"))
			Expect(records["AVG-4"].Description).To(Equal("information disclosure"))
		})

		It("should handle record with no advisories", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2022-11111"]
			Expect(record.Metadata.Issued).To(Equal(""))
			Expect(record.Metadata.Advisories).To(BeEmpty())
			Expect(record.FixedIn).To(HaveLen(1))
			Expect(record.FixedIn[0].Name).To(Equal("bash"))
			Expect(record.FixedIn[0].Version).To(Equal("5.1.8-1"))
		})

		It("should handle record with empty type", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records["CVE-2022-11111"].Description).To(Equal("Arch vulnerability AVG-5"))
		})
	})

	Context("ParsePackages", func() {
		It("should parse single package with version", func() {
			pkgs := arch.ParsePackages("libpng 1.6.38-1")
			Expect(pkgs).To(HaveLen(1))
			Expect(pkgs[0].Name).To(Equal("libpng"))
			Expect(pkgs[0].Version).To(Equal("1.6.38-1"))
		})

		It("should parse multiple packages", func() {
			pkgs := arch.ParsePackages("openssl 1.1.1l-1, libopenssl 1.1.1l-1")
			Expect(pkgs).To(HaveLen(2))
			Expect(pkgs[0].Name).To(Equal("openssl"))
			Expect(pkgs[0].Version).To(Equal("1.1.1l-1"))
			Expect(pkgs[1].Name).To(Equal("libopenssl"))
			Expect(pkgs[1].Version).To(Equal("1.1.1l-1"))
		})

		It("should return nil for empty string", func() {
			Expect(arch.ParsePackages("")).To(BeNil())
			Expect(arch.ParsePackages("   ")).To(BeNil())
		})

		It("should handle package without version", func() {
			pkgs := arch.ParsePackages("pkgname")
			Expect(pkgs).To(HaveLen(1))
			Expect(pkgs[0].Name).To(Equal("pkgname"))
			Expect(pkgs[0].Version).To(Equal(""))
		})
	})

	Context("ParseASA", func() {
		It("should extract date from ASA text", func() {
			text := "Date    : 2021-06-22\nSeverity: High\nPackage: test\n"
			Expect(arch.ParseASA(text)).To(Equal("2021-06-22"))
		})

		It("should handle flexible spacing", func() {
			text := "Date:2022-01-10\nSeverity: Low\n"
			Expect(arch.ParseASA(text)).To(Equal("2022-01-10"))
		})

		It("should return empty for missing date", func() {
			text := "Severity: High\nPackage: test\n"
			Expect(arch.ParseASA(text)).To(Equal(""))
		})

		It("should return empty for empty text", func() {
			Expect(arch.ParseASA("")).To(Equal(""))
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on HTTP failure", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = arch.NewManagerWithURL(testServer.URL+"/all.json", config)

			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed data", func() {
		It("should return error on invalid JSON", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))
			manager = arch.NewManagerWithURL(testServer.URL+"/all.json", config)

			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling empty data", func() {
		It("should return empty map for empty all.json", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			}))
			manager = arch.NewManagerWithURL(testServer.URL+"/all.json", config)

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the configured URL", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal(testServer.URL + "/all.json"))
		})
	})
})
