package echo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider/echo"
)

var _ = Describe("Echo Parser", func() {
	var (
		parser     *echo.Parser
		tempDir    string
		testServer *httptest.Server
		testData   echo.RawData
	)

	BeforeEach(func() {
		// Create temporary workspace
		var err error
		tempDir, err = os.MkdirTemp("", "echo-parser-test-*")
		Expect(err).NotTo(HaveOccurred())

		// Create test data
		testData = echo.RawData{
			"libssl": {
				"CVE-2023-0001": echo.CVEInfo{
					Severity:     "High",
					FixedVersion: "1.1.1t-r0",
				},
				"CVE-2023-0002": echo.CVEInfo{
					Severity:     "Medium",
					FixedVersion: "1.1.1t-r1",
				},
			},
			"curl": {
				"CVE-2023-0003": echo.CVEInfo{
					Severity:     "Low",
					FixedVersion: "8.0.1-r0",
				},
			},
		}

		// Create test HTTP server
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testData)
		}))

		// Create parser
		httpClient := &http.Client{}
		parser = echo.NewParser(testServer.URL, "echo", tempDir, httpClient)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching vulnerability data", func() {
		It("should download and parse JSON successfully", func() {
			ctx := context.Background()
			vulns, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(vulns).NotTo(BeNil())
			Expect(len(vulns)).To(Equal(3))
		})

		It("should create proper vulnerability records", func() {
			ctx := context.Background()
			vulns, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			// Check CVE-2023-0001
			vuln, exists := vulns["CVE-2023-0001"]
			Expect(exists).To(BeTrue())
			Expect(vuln.Name).To(Equal("CVE-2023-0001"))
			Expect(vuln.NamespaceName).To(Equal("echo:rolling"))
			Expect(vuln.Severity).To(Equal("High"))
			Expect(vuln.Link).To(ContainSubstring("nvd.nist.gov"))
			Expect(len(vuln.FixedIn)).To(Equal(1))
			Expect(vuln.FixedIn[0].Name).To(Equal("libssl"))
			Expect(vuln.FixedIn[0].Version).To(Equal("1.1.1t-r0"))
			Expect(vuln.FixedIn[0].VersionFormat).To(Equal("dpkg"))
		})

		It("should handle multiple packages with same CVE", func() {
			// Add same CVE to another package in test data
			testData["openssl"] = map[string]echo.CVEInfo{
				"CVE-2023-0001": {
					Severity:     "High",
					FixedVersion: "3.0.8-r0",
				},
			}

			ctx := context.Background()
			vulns, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			vuln := vulns["CVE-2023-0001"]
			Expect(len(vuln.FixedIn)).To(BeNumerically(">=", 1))
		})

		It("should normalize empty severity to Unknown", func() {
			testData["test-pkg"] = map[string]echo.CVEInfo{
				"CVE-2023-9999": {
					Severity:     "",
					FixedVersion: "1.0.0",
				},
			}

			ctx := context.Background()
			vulns, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			vuln := vulns["CVE-2023-9999"]
			Expect(vuln.Severity).To(Equal("Unknown"))
		})

		It("should create proper namespace", func() {
			ctx := context.Background()
			vulns, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			for _, vuln := range vulns {
				Expect(vuln.NamespaceName).To(Equal("echo:rolling"))
				for _, fix := range vuln.FixedIn {
					Expect(fix.NamespaceName).To(Equal("echo:rolling"))
				}
			}
		})
	})

	Context("when handling errors", func() {
		It("should return error on HTTP failure", func() {
			testServer.Close() // Close server to simulate failure

			ctx := context.Background()
			_, err := parser.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("download echo data"))
		})

		It("should return error on malformed JSON", func() {
			// Replace server with one returning invalid JSON
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("invalid json {{{"))
			}))

			httpClient := &http.Client{}
			parser = echo.NewParser(testServer.URL, "echo", tempDir, httpClient)

			ctx := context.Background()
			_, err := parser.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("json"))
		})

		It("should handle context cancellation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
			defer cancel()

			time.Sleep(1 * time.Millisecond) // Ensure context times out

			_, err := parser.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("context"))
		})
	})

	Context("when saving downloaded data", func() {
		It("should create advisories directory", func() {
			ctx := context.Background()
			_, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			advisoriesDir := filepath.Join(tempDir, "echo-advisories")
			info, err := os.Stat(advisoriesDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})

		It("should save JSON file", func() {
			ctx := context.Background()
			_, err := parser.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			dataFile := filepath.Join(tempDir, "echo-advisories", "data.json")
			_, err = os.Stat(dataFile)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
