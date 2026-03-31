package mariner_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/mariner"
)

const testOVALXML = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions>
  <generator>
    <product_name>vulnz-go test</product_name>
    <product_version>1.0</product_version>
    <schema_version>5.11.2</schema_version>
    <timestamp>2024-01-01T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.microsoft.cbl-mariner:def:1000" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2021-44228 log4j vulnerability</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="CVE" ref_id="CVE-2021-44228" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"/>
        <description>Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.</description>
        <advisory>
          <severity>Critical</severity>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1000" comment="openssl is earlier than 1.1.1k-7.cm2"/>
      </criteria>
    </definition>
    <definition id="oval:com.microsoft.cbl-mariner:def:1001" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2022-1234 no severity</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="CVE" ref_id="CVE-2022-1234" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2022-1234"/>
        <description>A vulnerability with no severity specified.</description>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1001" comment="bash is earlier than 5.1-2"/>
      </criteria>
    </definition>
    <definition id="oval:com.microsoft.cbl-mariner:def:1002" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2023-5678 no CVE reference</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="BUGZILLA" ref_id="12345" ref_url="https://bugzilla.example.com/12345"/>
        <description>A vulnerability with no CVE reference.</description>
        <advisory>
          <severity>High</severity>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1002" comment="curl is earlier than 7.88.0"/>
      </criteria>
    </definition>
    <definition id="oval:com.microsoft.cbl-mariner:def:1003" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2024-9999 with multiple EVR states</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="CVE" ref_id="CVE-2024-9999" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-9999"/>
        <description>A vulnerability with a range of affected versions.</description>
        <advisory>
          <severity>Moderate</severity>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1003a" comment="nginx is earlier than 1.24.0"/>
        <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1003b" comment="nginx is greater than 0:1.20.0-1"/>
      </criteria>
    </definition>
    <definition id="oval:com.microsoft.cbl-mariner:def:1004" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2024-0001 nested criteria</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="CVE" ref_id="CVE-2024-0001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001"/>
        <description>A vulnerability with nested criteria.</description>
        <advisory>
          <severity>Low</severity>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criteria operator="OR">
          <criterion test_ref="oval:com.microsoft.cbl-mariner:tst:1004" comment="kernel is earlier than 5.15.0-1"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1000" comment="openssl is earlier than 1.1.1k-7.cm2" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1000"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1000"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1001" comment="bash is earlier than 5.1-2" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1001"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1001"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1002" comment="curl is earlier than 7.88.0" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1002"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1002"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1003a" comment="nginx is earlier than 1.24.0" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1003"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1003a"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1003b" comment="nginx is greater than 0:1.20.0-1" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1003"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1003b"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.microsoft.cbl-mariner:tst:1004" comment="kernel is earlier than 5.15.0-1" check="at least one" version="1">
      <object object_ref="oval:com.microsoft.cbl-mariner:obj:1004"/>
      <state state_ref="oval:com.microsoft.cbl-mariner:ste:1004"/>
    </rpminfo_test>
  </tests>
  <objects>
    <rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1000" version="1">
      <name>openssl</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1001" version="1">
      <name>bash</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1002" version="1">
      <name>curl</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1003" version="1">
      <name>nginx</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1004" version="1">
      <name>kernel</name>
    </rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1000" version="1">
      <evr operation="less than" datatype="evr_string">0:1.1.1k-7.cm2</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1001" version="1">
      <evr operation="less than" datatype="evr_string">0:5.1-2.cm2</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1002" version="1">
      <evr operation="less than" datatype="evr_string">0:7.88.0-1.cm2</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1003a" version="1">
      <evr operation="less than" datatype="evr_string">0:1.24.0-1.cm2</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1003b" version="1">
      <evr operation="greater than" datatype="evr_string">0:1.20.0-1.cm2</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1004" version="1">
      <evr operation="less than" datatype="evr_string">0:5.15.0-1.cm2</evr>
    </rpminfo_state>
  </states>
</oval_definitions>`

var _ = Describe("Mariner Manager", func() {
	var (
		manager *mariner.Manager
		tempDir string
		config  provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "mariner-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "mariner",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = mariner.NewManager(config, []string{"2.0"})
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("when parsing OVAL data", func() {
		It("should parse valid OVAL and extract vulnerability records", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			Expect(vulns).NotTo(BeNil())
			Expect(len(vulns)).To(BeNumerically(">=", 3))
		})

		It("should extract correct CVE ID from definition", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			var found bool
			for _, v := range vulns {
				if v.Name == "CVE-2021-44228" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should set correct namespace from filename", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				Expect(v.NamespaceName).To(Equal("mariner:2.0"))
			}
		})

		It("should extract severity correctly", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				if v.Name == "CVE-2021-44228" {
					Expect(v.Severity).To(Equal("Critical"))
				}
				if v.Name == "CVE-2024-9999" {
					Expect(v.Severity).To(Equal("Moderate"))
				}
				if v.Name == "CVE-2024-0001" {
					Expect(v.Severity).To(Equal("Low"))
				}
			}
		})

		It("should skip definitions without severity", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				Expect(v.Name).NotTo(Equal("CVE-2022-1234"))
			}
		})

		It("should skip definitions without CVE reference", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				Expect(v.Name).NotTo(Equal("CVE-2023-5678"))
			}
		})

		It("should extract package name and fix version from EVR", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			var found bool
			for _, v := range vulns {
				if v.Name == "CVE-2021-44228" {
					found = true
					Expect(v.FixedIn).To(HaveLen(1))
					Expect(v.FixedIn[0].Name).To(Equal("openssl"))
					Expect(v.FixedIn[0].Version).To(Equal("0:1.1.1k-7.cm2"))
					Expect(v.FixedIn[0].VersionFormat).To(Equal("rpm"))
					Expect(v.FixedIn[0].VulnerableRange).To(Equal("< 0:1.1.1k-7.cm2"))
					Expect(v.FixedIn[0].NamespaceName).To(Equal("mariner:2.0"))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should build vulnerable range with multiple EVR states sorted in reverse", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			var found bool
			for _, v := range vulns {
				if v.Name == "CVE-2024-9999" {
					found = true
					Expect(v.FixedIn).To(HaveLen(1))
					Expect(v.FixedIn[0].Name).To(Equal("nginx"))
					Expect(v.FixedIn[0].VulnerableRange).To(Equal("> 0:1.20.0-1.cm2, < 0:1.24.0-1.cm2"))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should extract link from reference", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				if v.Name == "CVE-2021-44228" {
					Expect(v.Link).To(Equal("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"))
				}
			}
		})

		It("should extract description from definition", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				if v.Name == "CVE-2021-44228" {
					Expect(v.Description).To(ContainSubstring("Log4j"))
				}
			}
		})

		It("should handle nested criteria", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			var found bool
			for _, v := range vulns {
				if v.Name == "CVE-2024-0001" {
					found = true
					Expect(v.FixedIn).To(HaveLen(1))
					Expect(v.FixedIn[0].Name).To(Equal("kernel"))
					Expect(v.FixedIn[0].Version).To(Equal("0:5.15.0-1.cm2"))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should handle azurelinux version filename", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "azurelinux-3.0-oval.xml")

			for _, v := range vulns {
				Expect(v.NamespaceName).To(Equal("mariner:3.0"))
				Expect(v.FixedIn[0].NamespaceName).To(Equal("mariner:3.0"))
			}
		})

		It("should produce valid payloads", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			for _, v := range vulns {
				payload := v.ToPayload()
				Expect(payload).To(HaveKey("Vulnerability"))
			}
		})

		It("should return empty for malformed XML", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte(`<not valid xml`), "cbl-mariner-2.0-oval.xml")

			Expect(vulns).To(BeNil())
		})

		It("should return empty for empty input", func() {
			ctx := context.Background()
			vulns := mariner.ParseOVAL(ctx, []byte{}, "cbl-mariner-2.0-oval.xml")

			Expect(vulns).To(BeNil())
		})

		It("should return empty for context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			vulns := mariner.ParseOVAL(ctx, []byte(testOVALXML), "cbl-mariner-2.0-oval.xml")

			Expect(vulns).To(BeNil())
		})
	})

	Context("when handling version configuration", func() {
		It("should accept custom versions", func() {
			mgr := mariner.NewManager(config, []string{"1.0", "3.0"})
			Expect(mgr).NotTo(BeNil())
		})

		It("should return empty URLs before Get is called", func() {
			urls := manager.URLs()
			Expect(urls).To(BeEmpty())
		})
	})

	Context("when handling edge cases", func() {
		It("should handle OVAL with no definitions", func() {
			ctx := context.Background()
			emptyOVAL := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions>
  <generator>
    <product_name>test</product_name>
    <product_version>1.0</product_version>
    <schema_version>5.11.2</schema_version>
    <timestamp>2024-01-01T00:00:00Z</timestamp>
  </generator>
  <definitions>
  </definitions>
  <tests>
  </tests>
  <objects>
  </objects>
  <states>
  </states>
</oval_definitions>`

			vulns := mariner.ParseOVAL(ctx, []byte(emptyOVAL), "cbl-mariner-2.0-oval.xml")
			Expect(vulns).NotTo(BeNil())
			Expect(len(vulns)).To(Equal(0))
		})

		It("should handle definition with no criteria", func() {
			ctx := context.Background()
			noCriteria := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions>
  <generator>
    <product_name>test</product_name>
    <product_version>1.0</product_version>
    <schema_version>5.11.2</schema_version>
    <timestamp>2024-01-01T00:00:00Z</timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.microsoft.cbl-mariner:def:9999" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2099-0001 no criteria</title>
        <affected family="unix">
          <platform>CBL-Mariner 2.0</platform>
        </affected>
        <reference source="CVE" ref_id="CVE-2099-0001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2099-0001"/>
        <description>No criteria test.</description>
        <advisory>
          <severity>High</severity>
        </advisory>
      </metadata>
      <criteria operator="AND">
      </criteria>
    </definition>
  </definitions>
  <tests>
  </tests>
  <objects>
  </objects>
  <states>
  </states>
</oval_definitions>`

			vulns := mariner.ParseOVAL(ctx, []byte(noCriteria), "cbl-mariner-2.0-oval.xml")
			Expect(vulns).NotTo(BeNil())
			Expect(len(vulns)).To(Equal(0))
		})
	})
})
