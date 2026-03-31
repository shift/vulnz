package debian_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/debian"
)

const mockJSON = `{
  "curl": {
    "CVE-2024-12345": {
      "description": "curl vulnerability",
      "releases": {
        "bookworm": {
          "status": "open",
          "urgency": "high",
          "fixed_version": "7.88.1-10+deb12u5"
        },
        "trixie": {
          "status": "open",
          "urgency": "medium",
          "fixed_version": "8.5.0-2"
        },
        "sid": {
          "status": "open",
          "urgency": "low",
          "fixed_version": "8.9.0-1"
        }
      }
    },
    "CVE-2024-12346": {
      "description": "another curl vulnerability",
      "releases": {
        "bookworm": {
          "status": "open",
          "urgency": "medium**",
          "fixed_version": "7.88.1-10+deb12u5"
        },
        "bullseye": {
          "status": "resolved",
          "urgency": "unimportant",
          "fixed_version": "0"
        }
      }
    },
    "CVE-2024-99999": {
      "description": "nodsa test vulnerability",
      "releases": {
        "bookworm": {
          "status": "open",
          "urgency": "low",
          "fixed_version": "7.88.1-10+deb12u7",
          "nodsa": true
        }
      }
    },
    "CVE-2024-88888": {
      "description": "no fix version test",
      "releases": {
        "bookworm": {
          "status": "open",
          "urgency": "high"
        }
      }
    }
  },
  "openssl": {
    "CVE-2024-00001": {
      "description": "openssl test vuln",
      "releases": {
        "bookworm": {
          "status": "open",
          "urgency": "high",
          "fixed_version": "3.0.14-1~deb12u1"
        }
      }
    }
  },
  "TEMP-0000001-AABBCC": {
    "description": "non-CVE entry",
    "releases": {
      "bookworm": {
        "status": "open",
        "urgency": "low",
        "fixed_version": "1.0-1"
      }
    }
  }
}`

const mockDSA = `[2024-01-15] DSA-5678-1 curl - security update
  {CVE-2024-12345 CVE-2024-12346}
  [bookworm] - curl 7.88.1-10+deb12u5
  [trixie] - curl 8.5.0-2
  NOTE: [sid] - curl 8.9.0-1

[2024-02-20] DSA-5678-2 curl - security update
  [bookworm] - curl 7.88.1-10+deb12u7

[2024-03-10] DSA-5700-1 openssl - security update
  {CVE-2024-00001}
  [bookworm] - openssl 3.0.14-1~deb12u1

[2024-04-01] DSA-5800-1 libxml2 - security update
  {CVE-2024-11111}
  [bookworm] - libxml2 2.9.14-3+deb12u1
`

var _ = Describe("Debian Manager", func() {
	var (
		manager    *debian.Manager
		tempDir    string
		jsonServer *httptest.Server
		dsaServer  *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "debian-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		jsonServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(mockJSON))
		}))

		dsaServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(mockDSA))
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "debian",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = debian.NewManager(jsonServer.URL, dsaServer.URL, config)
	})

	AfterEach(func() {
		jsonServer.Close()
		dsaServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching data", func() {
		It("should fetch and parse both JSON and DSA data successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">=", 4))
		})

		It("should save raw JSON to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			content, readErr := os.ReadFile(tempDir + "/input/debian.json")
			Expect(readErr).NotTo(HaveOccurred())

			var parsed map[string]interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(parsed).To(HaveKey("curl"))
		})

		It("should save raw DSA to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			content, readErr := os.ReadFile(tempDir + "/input/DSA")
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("DSA-5678-1"))
		})
	})

	Context("vulnerability record generation", func() {
		It("should produce records with correct namespaces", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			namespaces := make(map[string]bool)
			for _, r := range records {
				namespaces[r.NamespaceName] = true
			}

			Expect(namespaces).To(HaveKey("debian:12"))
			Expect(namespaces).To(HaveKey("debian:13"))
			Expect(namespaces).To(HaveKey("debian:unstable"))
		})

		It("should skip non-CVE entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				Expect(r.Name).NotTo(ContainSubstring("TEMP-"))
			}
		})

		It("should skip entries with fixed_version 0", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-12346" && r.NamespaceName == "debian:11" {
					for _, fi := range r.FixedIn {
						Expect(fi.Name).NotTo(Equal("curl"))
					}
				}
			}
		})

		It("should set version to None when fixed_version is missing", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, r := range records {
				if r.Name == "CVE-2024-88888" && r.NamespaceName == "debian:12" {
					found = true
					Expect(r.FixedIn).To(HaveLen(1))
					Expect(r.FixedIn[0].Version).To(Equal("None"))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should map urgency to correct severity", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-12345" && r.NamespaceName == "debian:12" {
					Expect(r.Severity).To(Equal("High"))
				}
				if r.Name == "CVE-2024-12345" && r.NamespaceName == "debian:13" {
					Expect(r.Severity).To(Equal("Medium"))
				}
				if r.Name == "CVE-2024-12345" && r.NamespaceName == "debian:unstable" {
					Expect(r.Severity).To(Equal("Low"))
				}
			}
		})

		It("should handle urgency variants like medium**", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-12346" && r.NamespaceName == "debian:12" {
					Expect(r.Severity).To(Equal("Medium"))
				}
			}
		})

		It("should use dpkg as version format", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				for _, fi := range r.FixedIn {
					Expect(fi.VersionFormat).To(Equal("dpkg"))
				}
			}
		})
	})

	Context("DSA matching", func() {
		It("should attach DSA vendor advisory when DSA matches", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-12345" && r.NamespaceName == "debian:12" {
					Expect(r.FixedIn).NotTo(BeEmpty())
					found := false
					for _, fi := range r.FixedIn {
						if fi.Name == "curl" {
							found = true
							Expect(fi.VendorAdvisory).NotTo(BeNil())
							Expect(fi.VendorAdvisory.NoAdvisory).To(BeFalse())
							Expect(fi.VendorAdvisory.AdvisorySummary).NotTo(BeEmpty())
							Expect(fi.VendorAdvisory.AdvisorySummary[0].ID).To(Equal("DSA-5678-1"))
						}
					}
					Expect(found).To(BeTrue())
				}
			}
		})

		It("should set NoAdvisory=true when nodsa is present", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-99999" && r.NamespaceName == "debian:12" {
					Expect(r.FixedIn).NotTo(BeEmpty())
					Expect(r.FixedIn[0].VendorAdvisory).NotTo(BeNil())
					Expect(r.FixedIn[0].VendorAdvisory.NoAdvisory).To(BeTrue())
				}
			}
		})

		It("should set empty AdvisorySummary when no DSA and no nodsa", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-88888" && r.NamespaceName == "debian:12" {
					Expect(r.FixedIn).NotTo(BeEmpty())
					Expect(r.FixedIn[0].VendorAdvisory).NotTo(BeNil())
					Expect(r.FixedIn[0].VendorAdvisory.NoAdvisory).To(BeFalse())
					Expect(r.FixedIn[0].VendorAdvisory.AdvisorySummary).To(BeEmpty())
				}
			}
		})

		It("should match openssl DSA", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-00001" && r.NamespaceName == "debian:12" {
					Expect(r.FixedIn).NotTo(BeEmpty())
					Expect(r.FixedIn[0].VendorAdvisory).NotTo(BeNil())
					Expect(r.FixedIn[0].VendorAdvisory.AdvisorySummary[0].ID).To(Equal("DSA-5700-1"))
				}
			}
		})

		It("should handle incremental DSAs sharing base ID", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, r := range records {
				if r.Name == "CVE-2024-12345" && r.NamespaceName == "debian:12" {
					dsaIDs := []string{}
					for _, fi := range r.FixedIn {
						if fi.VendorAdvisory != nil && !fi.VendorAdvisory.NoAdvisory {
							for _, s := range fi.VendorAdvisory.AdvisorySummary {
								dsaIDs = append(dsaIDs, s.ID)
							}
						}
					}
					Expect(dsaIDs).To(ContainElements("DSA-5678-1", "DSA-5678-2"))
				}
			}
		})
	})

	Context("skip undetermined status", func() {
		It("should skip entries with undetermined status", func() {
			undeterminedJSON := `{
  "testpkg": {
    "CVE-2024-55555": {
      "description": "undetermined test",
      "releases": {
        "bookworm": {
          "status": "undetermined",
          "urgency": "high",
          "fixed_version": "1.0-1"
        }
      }
    }
  }
}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(undeterminedJSON))
			}))
			defer server.Close()

			mgr := debian.NewManager(server.URL, dsaServer.URL, config)
			ctx := context.Background()
			records, err := mgr.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(BeEmpty())
		})
	})

	Context("URLs method", func() {
		It("should return both configured URLs", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(2))
			Expect(urls[0]).To(Equal(jsonServer.URL))
			Expect(urls[1]).To(Equal(dsaServer.URL))
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on JSON fetch failure", func() {
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer badServer.Close()

			mgr := debian.NewManager(badServer.URL, dsaServer.URL, config)
			ctx := context.Background()
			_, err := mgr.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("fetch JSON"))
		})

		It("should return error on DSA fetch failure", func() {
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer badServer.Close()

			mgr := debian.NewManager(jsonServer.URL, badServer.URL, config)
			ctx := context.Background()
			_, err := mgr.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("fetch DSA"))
		})

		It("should return error on invalid JSON", func() {
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			}))
			defer badServer.Close()

			mgr := debian.NewManager(badServer.URL, dsaServer.URL, config)
			ctx := context.Background()
			_, err := mgr.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
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

	Context("when DSA list is empty", func() {
		It("should still process JSON records without DSA matching", func() {
			emptyDSAServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(""))
			}))
			defer emptyDSAServer.Close()

			mgr := debian.NewManager(jsonServer.URL, emptyDSAServer.URL, config)
			ctx := context.Background()
			records, err := mgr.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(BeNumerically(">", 0))

			for _, r := range records {
				for _, fi := range r.FixedIn {
					Expect(fi.VendorAdvisory).NotTo(BeNil())
					if !fi.VendorAdvisory.NoAdvisory {
						Expect(fi.VendorAdvisory.AdvisorySummary).To(BeEmpty())
					}
				}
			}
		})
	})

	Context("payload generation", func() {
		It("should produce valid payload via ToPayload", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(BeNumerically(">", 0))

			payload := records[0].ToPayload()
			Expect(payload).To(HaveKey("Vulnerability"))

			Expect(payload["Vulnerability"]).NotTo(BeNil())
		})
	})
})
