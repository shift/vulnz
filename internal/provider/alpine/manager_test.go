package alpine_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/alpine"
)

const mockLandingHTML = `<!DOCTYPE html>
<html>
<body>
<a href="v3.18/">v3.18/</a>
<a href="v3.19/">v3.19/</a>
<a href="v3.20/">v3.20/</a>
<a href="edge/">edge/</a>
<a href="last-update">last-update</a>
<a href="license.txt">license.txt</a>
</body>
</html>`

const mockMainYAML = `packages:
  - pkg:
      name: openssl
      secfixes:
        3.0.1-r0:
          - CVE-2023-32001
          - CVE-2023-32002
        3.0.2-r0:
          - CVE-2024-0001
  - pkg:
      name: libcurl
      secfixes:
        8.0.0-r0:
          - CVE-2023-32001
`

const mockCommunityYAML = `packages:
  - pkg:
      name: nginx
      secfixes:
        1.24.0-r0:
          - CVE-2024-0002
          - CVE-2024-0003
`

var _ = Describe("Alpine Manager", func() {
	var (
		manager    *alpine.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
		requestLog []string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "alpine-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		requestLog = nil

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestLog = append(requestLog, r.URL.Path)

			switch {
			case r.URL.Path == "/":
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(mockLandingHTML))
			case r.URL.Path == "/v3.18/main.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockMainYAML))
			case r.URL.Path == "/v3.18/community.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockCommunityYAML))
			case r.URL.Path == "/v3.19/main.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockMainYAML))
			case r.URL.Path == "/v3.19/community.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockCommunityYAML))
			case r.URL.Path == "/v3.20/main.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockMainYAML))
			case r.URL.Path == "/v3.20/community.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte(mockCommunityYAML))
			case r.URL.Path == "/edge/main.yaml":
				w.Header().Set("Content-Type", "application/yaml")
				w.Write([]byte("packages: []"))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "alpine",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = alpine.NewManager(testServer.URL, config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching alpine data", func() {
		It("should discover releases and fetch YAML files", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">", 0))
		})

		It("should fetch landing page first", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(requestLog[0]).To(Equal("/"))
		})

		It("should fetch main and community YAML for each release", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(requestLog).To(ContainElements(
				"/v3.18/main.yaml",
				"/v3.18/community.yaml",
				"/v3.19/main.yaml",
				"/v3.19/community.yaml",
				"/v3.20/main.yaml",
				"/v3.20/community.yaml",
			))
		})

		It("should save landing page to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "index.html")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("v3.18"))
		})

		It("should save YAML files to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			mainPath := filepath.Join(tempDir, "input", "v3.18", "main.yaml")
			_, statErr := os.Stat(mainPath)
			Expect(statErr).NotTo(HaveOccurred())

			communityPath := filepath.Join(tempDir, "input", "v3.18", "community.yaml")
			_, statErr = os.Stat(communityPath)
			Expect(statErr).NotTo(HaveOccurred())
		})

		It("should create vulnerability records with correct namespace", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			v318Records := records["v3.18"]
			Expect(v318Records).NotTo(BeNil())

			record := v318Records["CVE-2023-32001"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Name"]).To(Equal("CVE-2023-32001"))
			Expect(vuln["NamespaceName"]).To(Equal("alpine:v3.18"))
			Expect(vuln["Severity"]).To(Equal("Unknown"))
			Expect(vuln["Link"]).To(Equal("https://security.alpinelinux.org/vuln/CVE-2023-32001"))
		})

		It("should accumulate FixedIn entries across packages", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			v318Records := records["v3.18"]
			record := v318Records["CVE-2023-32001"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})

			Expect(len(fixedIn)).To(BeNumerically(">=", 2))
		})

		It("should set VersionFormat to apk for all FixedIn entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for release, releaseRecords := range records {
				for vulnID, record := range releaseRecords {
					vuln := record["Vulnerability"].(map[string]interface{})
					fixedInList := vuln["FixedIn"].([]interface{})

					for _, fi := range fixedInList {
						entry := fi.(map[string]interface{})
						Expect(entry["VersionFormat"]).To(Equal("apk"), "Release %s, Vuln %s should have VersionFormat=apk", release, vulnID)
						Expect(entry["NamespaceName"]).To(Equal("alpine:"+release), "Release %s, Vuln %s should have correct namespace", release, vulnID)
					}
				}
			}
		})

		It("should create records for all releases", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("v3.18"))
			Expect(records).To(HaveKey("v3.19"))
			Expect(records).To(HaveKey("v3.20"))
		})

		It("should return all fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(len(urls)).To(BeNumerically(">", 0))
			for _, u := range urls {
				Expect(u).To(ContainSubstring(testServer.URL))
			}
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = alpine.NewManager(testServer.URL, config)
		})

		It("should return error on landing page failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed YAML", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/":
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte(`<a href="v3.18/">v3.18/</a>`))
				default:
					w.Header().Set("Content-Type", "application/yaml")
					w.Write([]byte(`invalid: yaml: content: [`))
				}
			}))
			manager = alpine.NewManager(testServer.URL, config)
		})

		It("should return error on invalid YAML", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse yaml"))
		})
	})

	Context("when handling empty packages", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/":
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte(`<a href="v3.18/">v3.18/</a>`))
				default:
					w.Header().Set("Content-Type", "application/yaml")
					w.Write([]byte("packages: []"))
				}
			}))
			manager = alpine.NewManager(testServer.URL, config)
		})

		It("should return empty map for empty packages", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(records["v3.18"]).NotTo(BeNil())
			Expect(len(records["v3.18"])).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})

		It("should respect context timeout", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(mockLandingHTML))
			}))
			manager = alpine.NewManager(testServer.URL, config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling no releases found", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<html><body>no links here</body></html>`))
			}))
			manager = alpine.NewManager(testServer.URL, config)
		})

		It("should return error when no releases are discovered", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no releases found"))
		})
	})

	Context("link extraction", func() {
		It("should ignore last-update and license.txt links", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).NotTo(HaveKey("last-update"))
			Expect(records).NotTo(HaveKey("license.txt"))
		})

		It("should handle trailing slashes in links", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("v3.18"))
		})
	})
})
