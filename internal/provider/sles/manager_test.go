package sles_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/sles"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

const testOVALXML = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd
    http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <generator>
    <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">SUSE OVAL</oval:product_name>
    <oval:schema_version xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">5.11.2</oval:schema_version>
    <oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">2024-01-01T00:00:00</oval:timestamp>
  </generator>
  <definitions>
    <definition id="oval:org.anchore.test:def:1" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2024-0001-test</title>
        <affected family="unix">
          <platform>SUSE Linux Enterprise Server 15 SP3</platform>
        </affected>
        <reference source="SUSE CVE" ref_id="CVE-2024-0001" ref_url="https://www.suse.com/security/cve/CVE-2024-0001/"/>
        <reference source="CVE" ref_id="CVE-2024-0001" ref_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"/>
        <description>Test vulnerability for sqlite3 in SLES 15 SP3</description>
        <advisory>
          <severity>important</severity>
          <issued date="2024-01-15"/>
        </advisory>
      </metadata>
      <criteria operator="OR">
        <criteria operator="AND">
          <criteria operator="OR">
            <criterion test_ref="oval:org.anchore.test:tst:1" comment="SUSE Linux Enterprise Server 15 SP3 is installed"/>
          </criteria>
          <criteria operator="OR">
            <criterion test_ref="oval:org.anchore.test:tst:3" comment="sqlite3-3.36.0-3.12.1 is installed"/>
          </criteria>
        </criteria>
      </criteria>
    </definition>
    <definition id="oval:org.anchore.test:def:2" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2024-0002-test</title>
        <affected family="unix">
          <platform>SUSE Linux Enterprise Server 15 SP3</platform>
        </affected>
        <reference source="SUSE CVE" ref_id="CVE-2024-0002" ref_url="https://www.suse.com/security/cve/CVE-2024-0002/"/>
        <reference source="CVE" ref_id="CVE-2024-0002" ref_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0002"/>
        <description>Test critical vulnerability for openssl in SLES 15 SP3</description>
        <advisory>
          <severity>critical</severity>
          <issued date="2024-02-01"/>
        </advisory>
      </metadata>
      <criteria operator="OR">
        <criteria operator="AND">
          <criteria operator="OR">
            <criterion test_ref="oval:org.anchore.test:tst:1" comment="SUSE Linux Enterprise Server 15 SP3 is installed"/>
          </criteria>
          <criteria operator="OR">
            <criterion test_ref="oval:org.anchore.test:tst:4" comment="openssl-1.1.1k-3.15.1 is installed"/>
            <criterion test_ref="oval:org.anchore.test:tst:5" comment="openssl-devel-1.1.1k-3.15.1 is installed"/>
          </criteria>
        </criteria>
      </criteria>
    </definition>
    <definition id="oval:org.anchore.test:def:3" class="patch" version="1">
      <metadata>
        <title>non-vuln-definition</title>
        <affected family="unix">
          <platform>SUSE Linux Enterprise Server 15 SP3</platform>
        </affected>
        <description>This is a patch definition, not a vulnerability</description>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:org.anchore.test:tst:1" comment="SUSE Linux Enterprise Server 15 SP3 is installed"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="oval:org.anchore.test:tst:1" version="1" comment="SUSE Linux Enterprise Server 15 SP3 is installed" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.anchore.test:obj:1"/>
      <state state_ref="oval:org.anchore.test:ste:1"/>
    </rpminfo_test>
    <rpminfo_test id="oval:org.anchore.test:tst:2" version="1" comment="sle-module-basesystem-release is ==15" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.anchore.test:obj:2"/>
      <state state_ref="oval:org.anchore.test:ste:2"/>
    </rpminfo_test>
    <rpminfo_test id="oval:org.anchore.test:tst:3" version="1" comment="sqlite3-3.36.0-3.12.1 is installed" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.anchore.test:obj:3"/>
      <state state_ref="oval:org.anchore.test:ste:3"/>
    </rpminfo_test>
    <rpminfo_test id="oval:org.anchore.test:tst:4" version="1" comment="openssl-1.1.1k-3.15.1 is installed" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.anchore.test:obj:4"/>
      <state state_ref="oval:org.anchore.test:ste:4"/>
    </rpminfo_test>
    <rpminfo_test id="oval:org.anchore.test:tst:5" version="1" comment="openssl-devel-1.1.1k-3.15.1 is installed" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.anchore.test:obj:5"/>
      <state state_ref="oval:org.anchore.test:ste:5"/>
    </rpminfo_test>
  </tests>
  <objects>
    <rpminfo_object id="oval:org.anchore.test:obj:1" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>SUSE Linux Enterprise Server 15 SP3</name>
    </rpminfo_object>
    <rpminfo_object id="oval:org.anchore.test:obj:2" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>sle-module-basesystem-release</name>
    </rpminfo_object>
    <rpminfo_object id="oval:org.anchore.test:obj:3" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>sqlite3</name>
    </rpminfo_object>
    <rpminfo_object id="oval:org.anchore.test:obj:4" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>openssl</name>
    </rpminfo_object>
    <rpminfo_object id="oval:org.anchore.test:obj:5" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>openssl-devel</name>
    </rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="oval:org.anchore.test:ste:1" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="equals">0:15.3-1</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:org.anchore.test:ste:2" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <version operation="equals">15</version>
    </rpminfo_state>
    <rpminfo_state id="oval:org.anchore.test:ste:3" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">0:3.36.0-3.12.1</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:org.anchore.test:ste:4" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">0:1.1.1k-3.15.1</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:org.anchore.test:ste:5" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">0:1.1.1k-3.15.1</evr>
    </rpminfo_state>
  </states>
</oval_definitions>`

func extractVuln(record map[string]interface{}) (vulnerability.Vulnerability, bool) {
	v, ok := record["Vulnerability"].(vulnerability.Vulnerability)
	return v, ok
}

var _ = Describe("SLES Manager", func() {
	var (
		manager *sles.Manager
		tempDir string
		config  provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "sles-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "sles",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("when parsing OVAL data", func() {
		BeforeEach(func() {
			manager = sles.NewManagerWithVersions(config, []string{"15"})
		})

		It("should parse embedded OVAL XML and produce vulnerability records", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).NotTo(BeEmpty())

			Expect(advisories).To(HaveKey("sles:15.3/cve-2024-0001"))
			Expect(advisories).To(HaveKey("sles:15.3/cve-2024-0002"))
		})

		It("should extract correct vulnerability metadata", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())

			record := advisories["sles:15.3/cve-2024-0001"]
			Expect(record).NotTo(BeNil())

			vuln, ok := extractVuln(record)
			Expect(ok).To(BeTrue())
			Expect(vuln.Name).To(Equal("CVE-2024-0001-test"))
			Expect(vuln.NamespaceName).To(Equal("sles:15.3"))
			Expect(vuln.Severity).To(Equal("High"))
			Expect(vuln.Link).To(ContainSubstring("CVE-2024-0001"))
			Expect(vuln.Description).To(ContainSubstring("sqlite3"))
		})

		It("should map critical severity correctly", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())

			record := advisories["sles:15.3/cve-2024-0002"]
			Expect(record).NotTo(BeNil())

			vuln, ok := extractVuln(record)
			Expect(ok).To(BeTrue())
			Expect(vuln.Severity).To(Equal("Critical"))
		})

		It("should extract package fix information", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())

			record := advisories["sles:15.3/cve-2024-0001"]
			Expect(record).NotTo(BeNil())

			vuln, ok := extractVuln(record)
			Expect(ok).To(BeTrue())
			Expect(vuln.FixedIn).To(HaveLen(1))
			Expect(vuln.FixedIn[0].Name).To(Equal("sqlite3"))
			Expect(vuln.FixedIn[0].Version).To(Equal("0:3.36.0-3.12.1"))
			Expect(vuln.FixedIn[0].VersionFormat).To(Equal("rpm"))
			Expect(vuln.FixedIn[0].NamespaceName).To(Equal("sles:15.3"))
		})

		It("should handle definitions with multiple packages", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).To(HaveKey("sles:15.3/cve-2024-0002"))

			record := advisories["sles:15.3/cve-2024-0002"]
			vuln, ok := extractVuln(record)
			Expect(ok).To(BeTrue())
			Expect(vuln.FixedIn).To(HaveLen(2))

			pkgNames := make([]string, len(vuln.FixedIn))
			for i, fi := range vuln.FixedIn {
				pkgNames[i] = fi.Name
			}
			Expect(pkgNames).To(ContainElements("openssl", "openssl-devel"))
		})

		It("should skip non-vulnerability definitions", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())

			for id := range advisories {
				Expect(id).NotTo(ContainSubstring("non-vuln"))
			}
		})

		It("should produce correct namespace format", func() {
			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "15")

			Expect(err).NotTo(HaveOccurred())

			for id := range advisories {
				Expect(strings.HasPrefix(id, "sles:15.3/")).To(BeTrue(), "identifier %s should start with sles:15.3/", id)
			}
		})
	})

	Context("when handling empty or invalid data", func() {
		BeforeEach(func() {
			manager = sles.NewManagerWithVersions(config, []string{"15"})
		})

		It("should return empty map for empty XML", func() {
			emptyXML := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">SUSE OVAL</oval:product_name>
  </generator>
  <definitions></definitions>
  <tests></tests>
  <objects></objects>
  <states></states>
</oval_definitions>`

			advisories, err := manager.ParseOVAL(context.Background(), []byte(emptyXML), "15")
			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).To(BeEmpty())
		})

		It("should return error for invalid XML", func() {
			_, err := manager.ParseOVAL(context.Background(), []byte("not xml"), "15")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation during parse", func() {
			manager = sles.NewManagerWithVersions(config, []string{"15"})

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.ParseOVAL(ctx, []byte(testOVALXML), "15")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("version filtering", func() {
		It("should filter advisories by major version", func() {
			manager = sles.NewManagerWithVersions(config, []string{"12"})

			advisories, err := manager.ParseOVAL(context.Background(), []byte(testOVALXML), "12")
			Expect(err).NotTo(HaveOccurred())
			Expect(advisories).To(BeEmpty())
		})
	})

	Context("URLs method", func() {
		It("should return empty URLs before download", func() {
			manager = sles.NewManagerWithVersions(config, []string{"15"})
			urls := manager.URLs()
			Expect(urls).To(BeEmpty())
		})
	})
})
