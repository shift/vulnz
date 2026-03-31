package secureos_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/secureos"
)

func buildGzippedSecDB(packages interface{}) ([]byte, string) {
	db := map[string]interface{}{
		"packages": packages,
	}
	jsonData, _ := json.Marshal(db)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(jsonData)
	gz.Close()
	gzData := buf.Bytes()

	hash := sha256.Sum256(gzData)
	sha := fmt.Sprintf("%x", hash[:])
	return gzData, sha
}

func buildTestSecDB() (map[string]interface{}, []byte, string) {
	pkgs := []interface{}{
		map[string]interface{}{
			"pkg": map[string]interface{}{
				"name": "openssl",
				"secfixes": map[string]interface{}{
					"3.0.1-r0": []string{"CVE-2023-32001"},
					"3.0.2-r1": []string{"CVE-2023-32001", "CVE-2023-5678"},
					"3.0.3-r1": []string{"CVE-2024-0001"},
				},
			},
		},
		map[string]interface{}{
			"pkg": map[string]interface{}{
				"name": "nginx",
				"secfixes": map[string]interface{}{
					"1.24.0-r0": []string{"CVE-2023-1234"},
					"1.25.0-r1": []string{"CVE-2024-5678", "GHSA-abcd-1234"},
				},
			},
		},
	}

	gzData, sha := buildGzippedSecDB(pkgs)
	return map[string]interface{}{
		"latest_url": "/v1/secdb/test-2025-03-28.json.gz",
		"sha256":     sha,
	}, gzData, sha
}

var _ = Describe("SecureOS Manager", func() {
	var (
		manager    *secureos.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
		metadata   map[string]interface{}
		gzData     []byte
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "secureos-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		metadata, gzData, _ = buildTestSecDB()

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/latest.json" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
				return
			}
			if r.URL.Path == "/v1/secdb/test-2025-03-28.json.gz" {
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(gzData)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "secureos",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching secureos data", func() {
		It("should download and parse secdb successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">", 0))
		})

		It("should save raw metadata and secdb to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			metadataPath := filepath.Join(tempDir, "input", "secdb", "latest.json")
			content, readErr := os.ReadFile(metadataPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed map[string]interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(parsed).To(HaveKey("latest_url"))

			jsonPath := filepath.Join(tempDir, "input", "secdb", "secdb.json")
			_, statErr := os.Stat(jsonPath)
			Expect(statErr).NotTo(HaveOccurred())
		})

		It("should create proper vulnerability records with correct namespace", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-32001"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Name"]).To(Equal("CVE-2023-32001"))
			Expect(vuln["NamespaceName"]).To(Equal("secureos:rolling"))
			Expect(vuln["Severity"]).To(Equal("Unknown"))
			Expect(vuln["Link"]).To(Equal("https://security.secureos.io/CVE-2023-32001"))
		})

		It("should accumulate FixedIn entries across versions", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-32001"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})
			Expect(len(fixedIn)).To(Equal(2))
		})

		It("should set VersionFormat to apk for all FixedIn entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for vulnID, record := range records {
				vuln := record["Vulnerability"].(map[string]interface{})
				fixedInList := vuln["FixedIn"].([]interface{})

				for _, fi := range fixedInList {
					entry := fi.(map[string]interface{})
					Expect(entry["VersionFormat"]).To(Equal("apk"), "Vulnerability %s should have VersionFormat=apk", vulnID)
					Expect(entry["NamespaceName"]).To(Equal("secureos:rolling"), "Vulnerability %s should have NamespaceName=secureos:rolling", vulnID)
				}
			}
		})

		It("should compute VulnerableRange for non-first fix versions with revision > 0", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-32001"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})

			foundRange := false
			for _, fi := range fixedIn {
				entry := fi.(map[string]interface{})
				if vr, ok := entry["VulnerableRange"]; ok {
					Expect(vr).To(Equal(">=3.0.2-r0, <3.0.2-r1"))
					foundRange = true
				}
			}
			Expect(foundRange).To(BeTrue())
		})

		It("should handle GHSA identifiers", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["GHSA-abcd-1234"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Name"]).To(Equal("GHSA-abcd-1234"))
		})

		It("should not set Link for non-CVE identifiers", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["GHSA-abcd-1234"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Link"]).To(Equal(""))
		})

		It("should skip empty vulnerability IDs", func() {
			pkgs := []interface{}{
				map[string]interface{}{
					"pkg": map[string]interface{}{
						"name": "test-pkg",
						"secfixes": map[string]interface{}{
							"1.0.0-r0": []string{"", "CVE-2023-1111"},
						},
					},
				},
			}
			gzData2, sha2 := buildGzippedSecDB(pkgs)
			metadata2 := map[string]interface{}{
				"latest_url": "/v1/secdb/test-empty-vid.json.gz",
				"sha256":     sha2,
			}

			testServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/latest.json" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(metadata2)
					return
				}
				if r.URL.Path == "/v1/secdb/test-empty-vid.json.gz" {
					w.Header().Set("Content-Type", "application/gzip")
					w.Write(gzData2)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer testServer2.Close()

			mgr := secureos.NewManagerWithURL(testServer2.URL+"/v1/latest.json", config)
			ctx := context.Background()
			records, err := mgr.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveKey("CVE-2023-1111"))
			Expect(records).NotTo(HaveKey(""))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
		})

		It("should return error on metadata fetch failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed metadata", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"latest_url": "missing-sha"}`))
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
		})

		It("should return error on missing sha256", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("sha256"))
		})
	})

	Context("when handling SHA256 mismatch", func() {
		BeforeEach(func() {
			badMetadata := map[string]interface{}{
				"latest_url": "/v1/secdb/test-2025-03-28.json.gz",
				"sha256":     "0000000000000000000000000000000000000000000000000000000000000000",
			}

			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/latest.json" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(badMetadata)
					return
				}
				if r.URL.Path == "/v1/secdb/test-2025-03-28.json.gz" {
					w.Header().Set("Content-Type", "application/gzip")
					w.Write(gzData)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
		})

		It("should return error on SHA256 mismatch", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("sha256 mismatch"))
		})
	})

	Context("when handling malformed secdb data", func() {
		BeforeEach(func() {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			gz.Write([]byte(`{"invalid": json`))
			gz.Close()
			badGz := buf.Bytes()

			hash := sha256.Sum256(badGz)
			badMetadata := map[string]interface{}{
				"latest_url": "/v1/secdb/bad.json.gz",
				"sha256":     fmt.Sprintf("%x", hash[:]),
			}

			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/latest.json" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(badMetadata)
					return
				}
				if r.URL.Path == "/v1/secdb/bad.json.gz" {
					w.Header().Set("Content-Type", "application/gzip")
					w.Write(badGz)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
		})

		It("should return error on invalid secdb JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse secdb JSON"))
		})
	})

	Context("when handling empty secdb", func() {
		BeforeEach(func() {
			pkgs := []interface{}{}
			emptyGz, emptySha := buildGzippedSecDB(pkgs)
			emptyMetadata := map[string]interface{}{
				"latest_url": "/v1/secdb/empty.json.gz",
				"sha256":     emptySha,
			}

			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/latest.json" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(emptyMetadata)
					return
				}
				if r.URL.Path == "/v1/secdb/empty.json.gz" {
					w.Header().Set("Content-Type", "application/gzip")
					w.Write(emptyGz)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)
		})

		It("should return empty map for empty packages", func() {
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

		It("should respect context timeout", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				if r.URL.Path == "/v1/latest.json" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(metadata)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			manager = secureos.NewManagerWithURL(testServer.URL+"/v1/latest.json", config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the configured metadata URL", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal(testServer.URL + "/v1/latest.json"))
		})
	})
})
