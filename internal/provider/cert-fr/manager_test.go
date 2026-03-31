package certfr_test

import (
	"context"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	certfr "github.com/shift/vulnz/internal/provider/cert-fr"
)

const testRSSFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CERT-FR - Avis de securite</title>
    <link>https://www.cert.ssi.gouv.fr/</link>
    <description>Actualites du CERT-FR</description>
    <item>
      <title>CERTFR-2024-AVI-0123 (Critical): Vulnerability in OpenSSH allows remote code execution</title>
      <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0123/</link>
      <guid isPermaLink="true">https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0123/</guid>
      <pubDate>Mon, 15 Jan 2024 10:00:00 +0100</pubDate>
      <description>Multiple vulnerabilities including CVE-2024-12345 and CVE-2024-12346 in OpenSSH</description>
    </item>
    <item>
      <title>CERTFR-2024-ALE-0456: Urgent alert on OpenSSL</title>
      <link>https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-0456/</link>
      <guid isPermaLink="true">https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-0456/</guid>
      <pubDate>Tue, 20 Feb 2024 14:30:00 +0100</pubDate>
      <description>A critical vulnerability CVE-2024-56789 affects OpenSSL versions prior to 3.2.1</description>
    </item>
    <item>
      <title>CERTFR-2024-AVI-0789 Advisory without CVE references</title>
      <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0789/</link>
      <guid isPermaLink="true">https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0789/</guid>
      <pubDate>Wed, 10 Mar 2024 09:00:00 +0100</pubDate>
      <description>This advisory covers a security issue without any CVE assignment yet.</description>
    </item>
  </channel>
</rss>`

var _ = Describe("CERT-FR Manager", func() {
	var (
		manager   *certfr.Manager
		tempDir   string
		config    provider.Config
		serverURL string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "certfr-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		config = provider.Config{
			Name:      "cert-fr",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
		}
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	var server *mockRSSServer

	BeforeEach(func() {
		server = newMockRSSServer(testRSSFeed)
	})

	AfterEach(func() {
		server.Close()
	})

	Context("with mock RSS server", func() {
		BeforeEach(func() {
			serverURL = server.Address
			manager = certfr.NewManagerWithURL(serverURL, config, server.HTTPClient())
		})

		It("should fetch and parse RSS feed successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">=", 4))
		})

		It("should track fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal(serverURL))
		})

		It("should save raw RSS feed to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "cert_fr_feed.xml")
			_, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())
		})

		It("should create records keyed by CVE for advisories with CVEs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CVE-2024-12345"))
			Expect(records).To(HaveKey("CVE-2024-12346"))
			Expect(records).To(HaveKey("CVE-2024-56789"))

			record := records["CVE-2024-12345"]
			Expect(record["id"]).To(Equal("CVE-2024-12345"))
			Expect(record["namespace"]).To(Equal("cert-fr:anssi"))
		})

		It("should create record keyed by advisory ID when no CVEs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("CERTFR-2024-AVI-0789"))

			record := records["CERTFR-2024-AVI-0789"]
			Expect(record["id"]).To(Equal("CERTFR-2024-AVI-0789"))
			Expect(record["namespace"]).To(Equal("cert-fr:anssi"))
		})

		It("should set correct advisory metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-12345"]
			metadata := record["metadata"].(map[string]interface{})

			Expect(metadata["cert_fr_advisory_id"]).To(Equal("CERTFR-2024-AVI-0123"))
			Expect(metadata["is_alert"]).To(BeFalse())
			Expect(metadata["source"]).To(Equal("cert-fr"))
			Expect(metadata["published"]).To(Equal("Mon, 15 Jan 2024 10:00:00 +0100"))
		})

		It("should correctly identify ALE as alert", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-56789"]
			metadata := record["metadata"].(map[string]interface{})

			Expect(metadata["cert_fr_advisory_id"]).To(Equal("CERTFR-2024-ALE-0456"))
			Expect(metadata["is_alert"]).To(BeTrue())
		})

		It("should include advisory references with correct links", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-12345"]
			advisories := record["advisories"].([]interface{})

			Expect(advisories).To(HaveLen(1))
			adv := advisories[0].(map[string]interface{})
			Expect(adv["id"]).To(Equal("CERTFR-2024-AVI-0123"))
			Expect(adv["link"]).To(Equal("https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0123/"))
		})

		It("should include fix with unknown state", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-12345"]
			fix := record["fix"].(map[string]interface{})
			Expect(fix["state"]).To(Equal("unknown"))
		})

		It("should include empty cvss array", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2024-12345"]
			cvss := record["cvss"].([]interface{})
			Expect(cvss).To(BeEmpty())
		})
	})

	Context("parseRSS", func() {
		It("should parse valid RSS XML", func() {
			items, err := certfr.ParseRSS([]byte(testRSSFeed))
			Expect(err).NotTo(HaveOccurred())
			Expect(len(items)).To(Equal(3))
		})

		It("should return error on invalid XML", func() {
			_, err := certfr.ParseRSS([]byte("not xml at all <><><>"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("decode RSS XML"))
		})

		It("should extract advisory IDs from titles", func() {
			items, err := certfr.ParseRSS([]byte(testRSSFeed))
			Expect(err).NotTo(HaveOccurred())

			Expect(items[0].AdvisoryID).To(Equal("CERTFR-2024-AVI-0123"))
			Expect(items[1].AdvisoryID).To(Equal("CERTFR-2024-ALE-0456"))
			Expect(items[2].AdvisoryID).To(Equal("CERTFR-2024-AVI-0789"))
		})

		It("should extract CVEs from descriptions", func() {
			items, err := certfr.ParseRSS([]byte(testRSSFeed))
			Expect(err).NotTo(HaveOccurred())

			Expect(items[0].CVEs).To(ConsistOf("CVE-2024-12345", "CVE-2024-12346"))
			Expect(items[1].CVEs).To(ConsistOf("CVE-2024-56789"))
			Expect(items[2].CVEs).To(BeEmpty())
		})
	})

	Context("extractCVEs", func() {
		It("should extract unique CVE IDs", func() {
			input := "CVE-2024-1234 CVE-2024-5678 CVE-2024-1234"
			cves := certfr.ExtractCVEs(input)
			Expect(cves).To(ConsistOf("CVE-2024-1234", "CVE-2024-5678"))
		})

		It("should return empty for no CVEs", func() {
			cves := certfr.ExtractCVEs("no cves here")
			Expect(cves).To(BeEmpty())
		})

		It("should match CVE pattern with 4+ digit suffix", func() {
			cves := certfr.ExtractCVEs("CVE-2024-12345")
			Expect(cves).To(ConsistOf("CVE-2024-12345"))
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on HTTP failure", func() {
			errServer := newMockRSSServerError(500)
			defer errServer.Close()
			manager = certfr.NewManagerWithURL(errServer.Address, config, errServer.HTTPClient())

			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
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
})
