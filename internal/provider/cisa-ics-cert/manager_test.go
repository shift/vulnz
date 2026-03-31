package csatics_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/cisa-ics-cert"
)

var _ = Describe("CISA ICS-CERT Manager", func() {
	var (
		manager    *csatics.Manager
		testServer *httptest.Server
	)

	BeforeEach(func() {
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			path := r.URL.Path

			if path == "/contents/csaf_files/OT" {
				cats := []map[string]interface{}{
					{"name": "white", "type": "dir", "path": "csaf_files/OT/white"},
					{"name": "gray", "type": "dir", "path": "csaf_files/OT/gray"},
				}
				json.NewEncoder(w).Encode(cats)
				return
			}

			if path == "/contents/csaf_files/OT/white" {
				years := []map[string]interface{}{
					{"name": "2024", "type": "dir"},
				}
				json.NewEncoder(w).Encode(years)
				return
			}

			if path == "/contents/csaf_files/OT/gray" {
				years := []map[string]interface{}{
					{"name": "2025", "type": "dir"},
				}
				json.NewEncoder(w).Encode(years)
				return
			}

			if path == "/contents/csaf_files/OT/white/2024" {
				files := []map[string]interface{}{
					{
						"name":         "icsa-24-123-01.json",
						"type":         "file",
						"download_url": testServer.URL + "/raw/icsa-24-123-01.json",
					},
				}
				json.NewEncoder(w).Encode(files)
				return
			}

			if path == "/contents/csaf_files/OT/gray/2025" {
				files := []map[string]interface{}{
					{
						"name":         "icsa-25-045-01.json",
						"type":         "file",
						"download_url": testServer.URL + "/raw/icsa-25-045-01.json",
					},
				}
				json.NewEncoder(w).Encode(files)
				return
			}

			if path == "/raw/icsa-24-123-01.json" {
				csaf := map[string]interface{}{
					"document": map[string]interface{}{
						"tracking": map[string]interface{}{
							"id":                   "ICSA-24-123-01",
							"initial_release_date": "2024-05-01T00:00:00Z",
							"current_release_date": "2024-05-15T00:00:00Z",
						},
						"title": "Siemens SCADA Vulnerability",
						"notes": []map[string]interface{}{
							{"category": "summary", "text": "A vulnerability in Siemens SCADA system allows remote code execution via crafted packets targeting the communication module."},
						},
					},
					"vulnerabilities": []map[string]interface{}{
						{
							"cve": "CVE-2024-1234",
							"scores": []map[string]interface{}{
								{
									"cvss": map[string]interface{}{
										"baseScore":    9.8,
										"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
							},
						},
					},
					"product_tree": map[string]interface{}{
						"relationships": []map[string]interface{}{
							{
								"product": map[string]interface{}{
									"name": "Siemens SIMATIC WinCC",
									"product_identification_helper": map[string]interface{}{
										"cpes": []string{"cpe:2.3:a:siemens:simatic_wincc:8.0:*:*:*:*:*:*:*"},
									},
								},
							},
						},
					},
				}
				json.NewEncoder(w).Encode(csaf)
				return
			}

			if path == "/raw/icsa-25-045-01.json" {
				csaf := map[string]interface{}{
					"document": map[string]interface{}{
						"tracking": map[string]interface{}{
							"id":                   "ICSA-25-045-01",
							"initial_release_date": "2025-02-10T00:00:00Z",
							"current_release_date": "2025-02-20T00:00:00Z",
						},
						"title": "Schneider Electric HMI Firmware Issue",
						"notes": []map[string]interface{}{
							{"category": "summary", "text": "Schneider Electric HMI panel has a firmware vulnerability that could allow authentication bypass."},
						},
					},
					"vulnerabilities": []map[string]interface{}{
						{
							"cve": "CVE-2025-5678",
							"scores": []map[string]interface{}{
								{
									"cvss": map[string]interface{}{
										"baseScore":    7.5,
										"vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
									},
								},
							},
						},
						{
							"cve":    "CVE-2025-5679",
							"scores": []map[string]interface{}{},
						},
					},
					"product_tree": map[string]interface{}{
						"relationships": []map[string]interface{}{
							{
								"product": map[string]interface{}{
									"name": "Schneider Electric Magelis HMI",
									"product_identification_helper": map[string]interface{}{
										"cpes": []string{},
									},
								},
							},
						},
					},
				}
				json.NewEncoder(w).Encode(csaf)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		}))

		cfg := provider.Config{
			HTTP: provider.HTTPConfig{
				UserAgent: "vulnz-go-test/1.0",
			},
		}
		manager = csatics.NewManagerWithURL(testServer.URL+"/contents/csaf_files/OT", cfg, testServer.Client())
	})

	AfterEach(func() {
		testServer.Close()
	})

	Context("when fetching CISA ICS-CERT data", func() {
		It("should download and parse all advisories", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(3))
		})

		It("should track fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(urls).To(HaveLen(2))
		})

		It("should create records with correct namespace", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				Expect(record["namespace"]).To(Equal("cisa:ics-cert"))
			}
		})

		It("should extract CVE IDs from vulnerabilities", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CVE-2024-1234"))
			Expect(records).To(HaveKey("CVE-2025-5678"))
			Expect(records).To(HaveKey("CVE-2025-5679"))
		})

		It("should extract description from summary notes", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			Expect(record["description"]).To(ContainSubstring("Siemens SCADA"))
		})

		It("should extract CVSS scores", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			cvss := record["cvss"].([]map[string]interface{})
			Expect(cvss).To(HaveLen(1))

			cvssEntry := cvss[0]
			Expect(cvssEntry["version"]).To(Equal("3.1"))
			Expect(cvssEntry["vector"]).To(Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))

			metrics := cvssEntry["metrics"].(map[string]interface{})
			Expect(metrics["baseScore"]).To(Equal(9.8))
		})

		It("should extract product and vendor info", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["vendor"]).To(Equal("Siemens"))
			Expect(metadata["product"]).To(Equal("Siemens SIMATIC WinCC"))
		})

		It("should extract CPEs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			metadata := record["metadata"].(map[string]interface{})
			icsMeta := metadata["ics_ot_metadata"].(map[string]interface{})
			cpes := icsMeta["cpes"].([]string)
			Expect(cpes).To(ContainElement("cpe:2.3:a:siemens:simatic_wincc:8.0:*:*:*:*:*:*:*"))
		})

		It("should classify OT categories via keywords", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			metadata := record["metadata"].(map[string]interface{})
			icsMeta := metadata["ics_ot_metadata"].(map[string]interface{})
			Expect(icsMeta["ot_category"]).To(Equal("scada"))
		})

		It("should create advisory links", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			advisories := record["advisories"].([]map[string]interface{})
			Expect(advisories).To(HaveLen(1))

			adv := advisories[0]
			Expect(adv["id"]).To(Equal("ICSA-24-123-01"))
			Expect(adv["link"]).To(Equal("https://www.cisa.gov/news-events/ics-advisories/icsa-24-123-01"))
		})

		It("should include metadata fields", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-1234"]
			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["cisa_advisory_id"]).To(Equal("ICSA-24-123-01"))
			Expect(metadata["cisa_title"]).To(Equal("Siemens SCADA Vulnerability"))
			Expect(metadata["published"]).To(Equal("2024-05-01T00:00:00Z"))
			Expect(metadata["updated"]).To(Equal("2024-05-15T00:00:00Z"))
			Expect(metadata["source"]).To(Equal("cisa-ics-cert"))
			Expect(metadata["cves"]).To(Equal([]string{"CVE-2024-1234"}))
		})

		It("should handle advisories with multiple CVEs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CVE-2025-5678"))
			Expect(records).To(HaveKey("CVE-2025-5679"))

			for _, id := range []string{"CVE-2025-5678", "CVE-2025-5679"} {
				record := records[id]
				metadata := record["metadata"].(map[string]interface{})
				Expect(metadata["cisa_advisory_id"]).To(Equal("ICSA-25-045-01"))
			}
		})

		It("should detect CVSS 3.0 version", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2025-5678"]
			cvss := record["cvss"].([]map[string]interface{})
			Expect(cvss).To(HaveLen(1))

			cvssEntry := cvss[0]
			Expect(cvssEntry["version"]).To(Equal("3.0"))
		})

		It("should handle CVEs with no CVSS scores", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2025-5679"]
			cvss := record["cvss"].([]map[string]interface{})
			Expect(cvss).To(HaveLen(0))
		})
	})

	Context("when no CVEs in advisory", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				path := r.URL.Path

				if path == "/contents/csaf_files/OT" {
					json.NewEncoder(w).Encode([]map[string]interface{}{
						{"name": "white", "type": "dir"},
					})
					return
				}
				if path == "/contents/csaf_files/OT/white" {
					json.NewEncoder(w).Encode([]map[string]interface{}{
						{"name": "2024", "type": "dir"},
					})
					return
				}
				if path == "/contents/csaf_files/OT/white/2024" {
					json.NewEncoder(w).Encode([]map[string]interface{}{
						{
							"name":         "icsa-24-999-01.json",
							"type":         "file",
							"download_url": testServer.URL + "/raw/icsa-24-999-01.json",
						},
					})
					return
				}
				if path == "/raw/icsa-24-999-01.json" {
					json.NewEncoder(w).Encode(map[string]interface{}{
						"document": map[string]interface{}{
							"tracking": map[string]interface{}{
								"id":                   "ICSA-24-999-01",
								"initial_release_date": "2024-01-01T00:00:00Z",
								"current_release_date": "2024-01-01T00:00:00Z",
							},
							"title": "Generic ICS Advisory",
							"notes": []map[string]interface{}{
								{"category": "summary", "text": "A generic firmware vulnerability in industrial equipment."},
							},
						},
						"vulnerabilities": []interface{}{},
						"product_tree":    map[string]interface{}{},
					})
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))

			cfg := provider.Config{
				HTTP: provider.HTTPConfig{
					UserAgent: "vulnz-go-test/1.0",
				},
			}
			manager = csatics.NewManagerWithURL(testServer.URL+"/contents/csaf_files/OT", cfg, testServer.Client())
		})

		It("should use advisory ID as record key", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("ICSA-24-999-01"))
			record := records["ICSA-24-999-01"]
			Expect(record["id"]).To(Equal("ICSA-24-999-01"))
		})

		It("should classify as firmware", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ICSA-24-999-01"]
			metadata := record["metadata"].(map[string]interface{})
			icsMeta := metadata["ics_ot_metadata"].(map[string]interface{})
			Expect(icsMeta["ot_category"]).To(Equal("firmware"))
		})

		It("should have empty cves list for non-CVE IDs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ICSA-24-999-01"]
			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["cves"]).To(Equal([]string{}))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			cfg := provider.Config{
				HTTP: provider.HTTPConfig{
					UserAgent: "vulnz-go-test/1.0",
				},
			}
			manager = csatics.NewManagerWithURL(testServer.URL+"/contents/csaf_files/OT", cfg, testServer.Client())
		})

		It("should return error on HTTP failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling malformed JSON", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))

			cfg := provider.Config{
				HTTP: provider.HTTPConfig{
					UserAgent: "vulnz-go-test/1.0",
				},
			}
			manager = csatics.NewManagerWithURL(testServer.URL+"/contents/csaf_files/OT", cfg, testServer.Client())
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
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

	Context("OT classification", func() {
		It("should classify PLC", func() {
			Expect(csatics.ClassifyOT("Vulnerability in PLC communication module")).To(Equal("plc"))
		})

		It("should classify SCADA", func() {
			Expect(csatics.ClassifyOT("SCADA system remote code execution")).To(Equal("scada"))
		})

		It("should classify HMI", func() {
			Expect(csatics.ClassifyOT("HMI panel authentication bypass")).To(Equal("hmi"))
		})

		It("should classify RTU", func() {
			Expect(csatics.ClassifyOT("RTU firmware update vulnerability")).To(Equal("rtu"))
		})

		It("should classify DCS", func() {
			Expect(csatics.ClassifyOT("Distributed control system flaw")).To(Equal("dcs"))
		})

		It("should classify IoT", func() {
			Expect(csatics.ClassifyOT("IoT device network exposure")).To(Equal("iot"))
		})

		It("should classify firmware", func() {
			Expect(csatics.ClassifyOT("Some random firmware update vulnerability")).To(Equal("firmware"))
		})

		It("should default to ics-generic", func() {
			Expect(csatics.ClassifyOT("Some random advisory text")).To(Equal("ics-generic"))
		})
	})
})
