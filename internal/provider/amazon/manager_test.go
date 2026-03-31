package amazon_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/amazon"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

const mockRSSAL2 = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Amazon Linux 2 Security Advisories</title>
    <item>
      <title>ALAS-2025-1234 (Critical): openssl update</title>
      <link>%s/AL2/ALAS-2025-1234.html</link>
      <description>CVE-2025-1111,CVE-2025-2222</description>
      <pubDate>Mon, 10 Mar 2025 12:00:00 GMT</pubDate>
    </item>
    <item>
      <title>ALAS-2025-5678 (Medium): bash update</title>
      <link>%s/AL2/ALAS-2025-5678.html</link>
      <description>CVE-2025-3333</description>
      <pubDate>Tue, 11 Mar 2025 08:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>`

const mockRSSALEmpty = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Amazon Linux 2022 Security Advisories</title>
  </channel>
</rss>`

const mockHTMLALAS1 = `<!DOCTYPE html>
<html><head><title>ALAS-2025-1234</title></head><body>
<div id="issue_overview">
Issue Overview:
A vulnerability was found in OpenSSL.
</div>
<div id="new_packages">
x86_64:
openssl-1.1.1k-9.amzn2.0.1.x86_64.rpm
openssl-devel-1.1.1k-9.amzn2.0.1.x86_64.rpm
noarch:
openssl-debuginfo-1.1.1k-9.amzn2.0.1.noarch.rpm
i686:
openssl-libs-1.1.1k-9.amzn2.0.1.i686.rpm
src:
openssl-1.1.1k-9.amzn2.0.1.src.rpm
</div>
</body></html>`

const mockHTMLALAS2 = `<!DOCTYPE html>
<html><head><title>ALAS-2025-5678</title></head><body>
<div id="issue_overview">
Issue Overview:
Bash has a command injection flaw.
</div>
<div id="new_packages">
x86_64:
bash-4.2.46-35.amzn2.0.4.x86_64.rpm
</div>
</body></html>`

func extractVuln(record map[string]interface{}) vulnerability.Vulnerability {
	return record["Vulnerability"].(vulnerability.Vulnerability)
}

var _ = Describe("Amazon Manager", func() {
	var (
		manager    *amazon.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "amazon-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/AL2/alas.rss"):
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprintf(w, mockRSSAL2, testServer.URL, testServer.URL)
			case strings.HasSuffix(r.URL.Path, "/AL2022/alas.rss"):
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprint(w, mockRSSALEmpty)
			case strings.HasSuffix(r.URL.Path, "/AL2023/alas.rss"):
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprint(w, mockRSSALEmpty)
			case strings.HasSuffix(r.URL.Path, "ALAS-2025-1234.html"):
				fmt.Fprint(w, mockHTMLALAS1)
			case strings.HasSuffix(r.URL.Path, "ALAS-2025-5678.html"):
				fmt.Fprint(w, mockHTMLALAS2)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "amazon",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		advisories := map[string]string{
			"2":    testServer.URL + "/AL2/alas.rss",
			"2022": testServer.URL + "/AL2022/alas.rss",
			"2023": testServer.URL + "/AL2023/alas.rss",
		}

		manager = amazon.NewManagerWithAdvisories(config, advisories)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when parsing RSS feeds", func() {
		It("should parse RSS items and extract ALAS summaries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(BeNumerically(">=", 2))
		})

		It("should extract ALAS ID and severity from title", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			foundCritical := false
			foundMedium := false
			for _, record := range records {
				vuln := extractVuln(record)
				if vuln.Name == "ALAS-2025-1234" {
					Expect(vuln.Severity).To(Equal("Critical"))
					foundCritical = true
				}
				if vuln.Name == "ALAS-2025-5678" {
					Expect(vuln.Severity).To(Equal("Medium"))
					foundMedium = true
				}
			}
			Expect(foundCritical).To(BeTrue())
			Expect(foundMedium).To(BeTrue())
		})
	})

	Context("when parsing HTML pages", func() {
		It("should extract packages filtered by architecture", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			vuln := extractVuln(records["amzn:2/alas-2025-1234"])
			Expect(vuln.Name).To(Equal("ALAS-2025-1234"))
			Expect(len(vuln.FixedIn)).To(Equal(3))

			names := make(map[string]bool)
			for _, fi := range vuln.FixedIn {
				names[fi.Name] = true
			}
			Expect(names["openssl"]).To(BeTrue())
			Expect(names["openssl-devel"]).To(BeTrue())
			Expect(names["openssl-debuginfo"]).To(BeTrue())
			Expect(names["openssl-libs"]).To(BeFalse())
		})

		It("should extract description from issue_overview", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			vuln := extractVuln(records["amzn:2/alas-2025-1234"])
			Expect(vuln.Description).To(ContainSubstring("OpenSSL"))

			vuln2 := extractVuln(records["amzn:2/alas-2025-5678"])
			Expect(vuln2.Description).To(ContainSubstring("Bash"))
		})

		It("should parse RPM package filenames and extract NVR", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			vuln := extractVuln(records["amzn:2/alas-2025-1234"])
			for _, fi := range vuln.FixedIn {
				Expect(fi.VersionFormat).To(Equal("rpm"))
				Expect(fi.Version).NotTo(BeEmpty())
			}
		})
	})

	Context("when building vulnerability records", func() {
		It("should set correct namespace for AL2", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				vuln := extractVuln(record)
				Expect(vuln.NamespaceName).To(Equal("amzn:2"))
			}
		})

		It("should include CVE metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			vuln := extractVuln(records["amzn:2/alas-2025-1234"])
			cveRaw := vuln.Metadata["CVE"]
			cveSlice, ok := cveRaw.([]map[string]string)
			if !ok {
				cveAnySlice := cveRaw.([]any)
				Expect(len(cveAnySlice)).To(Equal(2))
				cveNames := make(map[string]bool)
				for _, c := range cveAnySlice {
					cveMap := c.(map[string]string)
					cveNames[cveMap["Name"]] = true
				}
				Expect(cveNames["CVE-2025-1111"]).To(BeTrue())
				Expect(cveNames["CVE-2025-2222"]).To(BeTrue())
			} else {
				Expect(len(cveSlice)).To(Equal(2))
				cveNames := make(map[string]bool)
				for _, c := range cveSlice {
					cveNames[c["Name"]] = true
				}
				Expect(cveNames["CVE-2025-1111"]).To(BeTrue())
				Expect(cveNames["CVE-2025-2222"]).To(BeTrue())
			}
		})

		It("should include ALAS link", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				vuln := extractVuln(record)
				Expect(vuln.Link).ToNot(BeEmpty())
			}
		})

		It("should set identifier format as namespace/alas-id", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("amzn:2/alas-2025-1234"))
			Expect(records).To(HaveKey("amzn:2/alas-2025-5678"))
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on RSS fetch failure", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			advisories := map[string]string{
				"2": testServer.URL + "/AL2/alas.rss",
			}
			manager = amazon.NewManagerWithAdvisories(config, advisories)

			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})

		It("should handle 403 for individual ALAS pages gracefully", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, ".html") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprintf(w, mockRSSAL2, testServer.URL, testServer.URL)
			}))

			advisories := map[string]string{
				"2": testServer.URL + "/AL2/alas.rss",
			}
			manager = amazon.NewManagerWithAdvisories(config, advisories)

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
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
		It("should return configured advisory URLs", func() {
			urls := manager.URLs()
			Expect(len(urls)).To(BeNumerically(">=", 3))
		})
	})
})
