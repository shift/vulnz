package oracle_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	govalParser "github.com/quay/goval-parser/oval"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/oracle"
)

const testOVALXML = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <generator>
    <oval:product_name>Oracle Linux OVAL</oval:product_name>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2024-01-15T00:00:00</oval:timestamp>
  </generator>
  <definitions>
    <definition id="oval:com.oracle.elsa:def:20240001" version="1" class="patch">
      <metadata>
        <title>ELSA-2024-0001: openssl security update</title>
        <affected family="unix">
          <platform>Oracle Linux 8</platform>
          <platform>Oracle Linux 9</platform>
          <product>openssl</product>
        </affected>
        <reference source="elsa" ref_id="ELSA-2024-0001" ref_url="https://linux.oracle.com/errata/ELSA-2024-0001.html"/>
        <reference source="cve" ref_id="CVE-2024-1001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1001"/>
        <reference source="cve" ref_id="CVE-2024-1002" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1002"/>
        <description>OpenSSL vulnerabilities in Oracle Linux 8 and 9</description>
        <advisory>
          <severity>Critical</severity>
          <issued date="2024-01-15"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criteria operator="OR">
          <criterion comment="Oracle Linux 8 is installed" test_ref="oval:com.oracle.elsa:tst:1001"/>
          <criterion comment="Oracle Linux 9 is installed" test_ref="oval:com.oracle.elsa:tst:1002"/>
        </criteria>
        <criteria operator="AND">
          <criterion comment="openssl is earlier than 1.1.1k-9.el8_8" test_ref="oval:com.oracle.elsa:tst:2001"/>
          <criterion comment="openssl-devel is earlier than 1.1.1k-9.el8_8" test_ref="oval:com.oracle.elsa:tst:2002"/>
          <criterion comment="openssl-libs is earlier than 1.1.1k-9.el8_8" test_ref="oval:com.oracle.elsa:tst:2003"/>
          <criterion comment="kernel-uek is signed with the Oracle Linux 8 key" test_ref="oval:com.oracle.elsa:tst:3001"/>
        </criteria>
      </criteria>
    </definition>
    <definition id="oval:com.oracle.elsa:def:20240002" version="1" class="patch">
      <metadata>
        <title>ELSA-2024-0002: bash security update</title>
        <affected family="unix">
          <platform>Oracle Linux 8</platform>
          <product>bash</product>
        </affected>
        <reference source="elsa" ref_id="ELSA-2024-0002" ref_url="https://linux.oracle.com/errata/ELSA-2024-0002.html"/>
        <reference source="cve" ref_id="CVE-2024-2001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-2001"/>
        <description>Bash vulnerability in Oracle Linux 8</description>
        <advisory>
          <severity>Important</severity>
          <issued date="2024-02-01"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Oracle Linux 8 is installed" test_ref="oval:com.oracle.elsa:tst:1001"/>
        <criterion comment="bash is earlier than 5.1.8-6.el8_7" test_ref="oval:com.oracle.elsa:tst:4001"/>
        <criterion comment="bash-doc is earlier than 5.1.8-6.el8_7" test_ref="oval:com.oracle.elsa:tst:4002"/>
      </criteria>
    </definition>
    <definition id="oval:com.oracle.elsa:def:20240003" version="1" class="patch">
      <metadata>
        <title>ELSA-2024-0003: ksplice security update</title>
        <affected family="unix">
          <platform>Oracle Linux 8</platform>
          <product>kernel-uek</product>
        </affected>
        <reference source="elsa" ref_id="ELSA-2024-0003" ref_url="https://linux.oracle.com/errata/ELSA-2024-0003.html"/>
        <reference source="cve" ref_id="CVE-2024-3001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-3001"/>
        <description>Ksplice vulnerability in Oracle Linux 8</description>
        <advisory>
          <severity>Moderate</severity>
          <issued date="2024-03-01"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Oracle Linux 8 is installed" test_ref="oval:com.oracle.elsa:tst:1001"/>
        <criterion comment="kernel-uek is earlier than 5.15.0-203.147.1.el8uek.ksplice1" test_ref="oval:com.oracle.elsa:tst:5001"/>
        <criterion comment="openssl is earlier than 1.1.1k-9.el8_8" test_ref="oval:com.oracle.elsa:tst:2001"/>
      </criteria>
    </definition>
    <definition id="oval:com.oracle.elsa:def:20240004" version="1" class="patch">
      <metadata>
        <title>ELSA-2024-0004: curl security update (low)</title>
        <affected family="unix">
          <platform>Oracle Linux 9</platform>
          <product>curl</product>
        </affected>
        <reference source="elsa" ref_id="ELSA-2024-0004" ref_url="https://linux.oracle.com/errata/ELSA-2024-0004.html"/>
        <reference source="cve" ref_id="CVE-2024-4001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-4001"/>
        <description>Curl vulnerability in Oracle Linux 9</description>
        <advisory>
          <severity>Low</severity>
          <issued date="2024-04-01"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Oracle Linux 9 is installed" test_ref="oval:com.oracle.elsa:tst:1002"/>
        <criterion comment="curl is earlier than 8.0.1-3.el9" test_ref="oval:com.oracle.elsa:tst:6001"/>
      </criteria>
    </definition>
    <definition id="oval:com.oracle.elsa:def:20240005" version="1" class="patch">
      <metadata>
        <title>No advisory reference definition</title>
        <affected family="unix">
          <platform>Oracle Linux 8</platform>
          <product>test</product>
        </affected>
        <reference source="cve" ref_id="CVE-2024-5001" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-5001"/>
        <description>Definition without ELSA advisory reference</description>
        <advisory>
          <severity>Low</severity>
          <issued date="2024-05-01"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion comment="Oracle Linux 8 is installed" test_ref="oval:com.oracle.elsa:tst:1001"/>
        <criterion comment="testpkg is earlier than 1.0-1.el8" test_ref="oval:com.oracle.elsa:tst:7001"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="oval:com.oracle.elsa:tst:1001" version="1" check="all" comment="Oracle Linux 8 is installed">
      <object object_ref="oval:com.oracle.elsa:obj:1001"/>
      <state state_ref="oval:com.oracle.elsa:ste:1001"/>
    </rpminfo_test>
    <rpminfo_test id="oval:com.oracle.elsa:tst:1002" version="1" check="all" comment="Oracle Linux 9 is installed">
      <object object_ref="oval:com.oracle.elsa:obj:1002"/>
      <state state_ref="oval:com.oracle.elsa:ste:1002"/>
    </rpminfo_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:2001" version="1" check="all" comment="openssl is earlier than 1.1.1k-9.el8_8">
      <object object_ref="oval:com.oracle.elsa:obj:2001"/>
      <state state_ref="oval:com.oracle.elsa:ste:2001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:2002" version="1" check="all" comment="openssl-devel is earlier than 1.1.1k-9.el8_8">
      <object object_ref="oval:com.oracle.elsa:obj:2002"/>
      <state state_ref="oval:com.oracle.elsa:ste:2001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:2003" version="1" check="all" comment="openssl-libs is earlier than 1.1.1k-9.el8_8">
      <object object_ref="oval:com.oracle.elsa:obj:2003"/>
      <state state_ref="oval:com.oracle.elsa:ste:2001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:3001" version="1" check="all" comment="kernel-uek is signed with the Oracle Linux 8 key">
      <object object_ref="oval:com.oracle.elsa:obj:3001"/>
      <state state_ref="oval:com.oracle.elsa:ste:3001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:4001" version="1" check="all" comment="bash is earlier than 5.1.8-6.el8_7">
      <object object_ref="oval:com.oracle.elsa:obj:4001"/>
      <state state_ref="oval:com.oracle.elsa:ste:4001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:4002" version="1" check="all" comment="bash-doc is earlier than 5.1.8-6.el8_7">
      <object object_ref="oval:com.oracle.elsa:obj:4002"/>
      <state state_ref="oval:com.oracle.elsa:ste:4001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:5001" version="1" check="all" comment="kernel-uek is earlier than 5.15.0-203.147.1.el8uek.ksplice1">
      <object object_ref="oval:com.oracle.elsa:obj:5001"/>
      <state state_ref="oval:com.oracle.elsa:ste:5001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:6001" version="1" check="all" comment="curl is earlier than 8.0.1-3.el9">
      <object object_ref="oval:com.oracle.elsa:obj:6001"/>
      <state state_ref="oval:com.oracle.elsa:ste:6001"/>
    </rpm_version_test>
    <rpm_version_test id="oval:com.oracle.elsa:tst:7001" version="1" check="all" comment="testpkg is earlier than 1.0-1.el8">
      <object object_ref="oval:com.oracle.elsa:obj:7001"/>
      <state state_ref="oval:com.oracle.elsa:ste:7001"/>
    </rpm_version_test>
  </tests>
  <objects>
    <rpminfo_object id="oval:com.oracle.elsa:obj:1001" version="1">
      <name>oraclelinux-release</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:1002" version="1">
      <name>oraclelinux-release</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:2001" version="1">
      <name>openssl</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:2002" version="1">
      <name>openssl-devel</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:2003" version="1">
      <name>openssl-libs</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:3001" version="1">
      <name>kernel-uek</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:4001" version="1">
      <name>bash</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:4002" version="1">
      <name>bash-doc</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:5001" version="1">
      <name>kernel-uek</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:6001" version="1">
      <name>curl</name>
    </rpminfo_object>
    <rpminfo_object id="oval:com.oracle.elsa:obj:7001" version="1">
      <name>testpkg</name>
    </rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="oval:com.oracle.elsa:ste:1001" version="1">
      <evr datatype="evr_string" operation="less than">0:8-0</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:1002" version="1">
      <evr datatype="evr_string" operation="less than">0:9-0</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:2001" version="1">
      <evr datatype="evr_string" operation="less than">0:1.1.1k-9.el8_8</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:3001" version="1">
      <signature_keyid operation="pattern match">.*</signature_keyid>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:4001" version="1">
      <evr datatype="evr_string" operation="less than">0:5.1.8-6.el8_7</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:5001" version="1">
      <evr datatype="evr_string" operation="less than">0:5.15.0-203.147.1.el8uek.ksplice1</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:6001" version="1">
      <evr datatype="evr_string" operation="less than">0:8.0.1-3.el9</evr>
    </rpminfo_state>
    <rpminfo_state id="oval:com.oracle.elsa:ste:7001" version="1">
      <evr datatype="evr_string" operation="less than">0:1.0-1.el8</evr>
    </rpminfo_state>
  </states>
</oval_definitions>`

func createTestServer(xmlContent string) *httptest.Server {
	tmpFile, err := os.CreateTemp("", "test-oval-*.xml")
	Expect(err).NotTo(HaveOccurred())
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	Expect(os.WriteFile(tmpFile.Name(), []byte(xmlContent), 0644)).NotTo(HaveOccurred())

	bz2File := tmpFile.Name() + ".bz2"
	cmd := exec.Command("bzip2", "-c", tmpFile.Name())
	out, err := os.Create(bz2File)
	Expect(err).NotTo(HaveOccurred())
	cmd.Stdout = out
	Expect(cmd.Run()).NotTo(HaveOccurred())
	out.Close()
	defer os.Remove(bz2File)

	bz2Data, err := os.ReadFile(bz2File)
	Expect(err).NotTo(HaveOccurred())

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bzip2")
		w.Write(bz2Data)
	}))
}

var _ = Describe("Oracle Manager", func() {
	var (
		manager    *oracle.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "oracle-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "oracle",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      30 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
		}
		os.RemoveAll(tempDir)
	})

	Context("when fetching and parsing OVAL data", func() {
		BeforeEach(func() {
			testServer = createTestServer(testOVALXML)
			manager = oracle.NewManagerWithURL(testServer.URL, config)
		})

		It("should download, decompress, and parse OVAL data successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">=", 5))
		})

		It("should save raw bz2 and decompressed XML to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			bz2Path := filepath.Join(tempDir, "input", "com.oracle.elsa-all.xml.bz2")
			_, bz2Err := os.Stat(bz2Path)
			Expect(bz2Err).NotTo(HaveOccurred())

			xmlPath := filepath.Join(tempDir, "input", "com.oracle.elsa-all.xml")
			xmlData, xmlErr := os.ReadFile(xmlPath)
			Expect(xmlErr).NotTo(HaveOccurred())
			Expect(len(xmlData)).To(BeNumerically(">", 0))
			Expect(string(xmlData)).To(ContainSubstring("oval_definitions"))
		})

		It("should create vulnerability records with correct structure", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record, ok := records["ol:8/cve-2024-2001"]
			Expect(ok).To(BeTrue())

			vuln, ok := record["Vulnerability"].(map[string]interface{})
			Expect(ok).To(BeTrue())

			Expect(vuln["Name"]).To(Equal("CVE-2024-2001"))
			Expect(vuln["NamespaceName"]).To(Equal("ol:8"))
			Expect(vuln["Severity"]).To(Equal("High"))
			Expect(vuln["Description"]).To(ContainSubstring("Bash"))
		})

		It("should extract correct CVE IDs from definitions", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("ol:8/cve-2024-1001"))
			Expect(records).To(HaveKey("ol:8/cve-2024-1002"))
			Expect(records).To(HaveKey("ol:8/cve-2024-2001"))
			Expect(records).To(HaveKey("ol:9/cve-2024-1001"))
			Expect(records).To(HaveKey("ol:9/cve-2024-1002"))
			Expect(records).To(HaveKey("ol:9/cve-2024-4001"))
		})

		It("should normalize severity correctly", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record1001 := records["ol:8/cve-2024-1001"]
			vuln1001 := record1001["Vulnerability"].(map[string]interface{})
			Expect(vuln1001["Severity"]).To(Equal("Critical"))

			record2001 := records["ol:8/cve-2024-2001"]
			vuln2001 := record2001["Vulnerability"].(map[string]interface{})
			Expect(vuln2001["Severity"]).To(Equal("High"))

			record4001 := records["ol:9/cve-2024-4001"]
			vuln4001 := record4001["Vulnerability"].(map[string]interface{})
			Expect(vuln4001["Severity"]).To(Equal("Low"))
		})

		It("should extract package versions from criteria comments", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-2001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]map[string]interface{})

			pkgNames := make([]string, 0, len(fixedIn))
			for _, fi := range fixedIn {
				pkgNames = append(pkgNames, fi["Name"].(string))
			}
			Expect(pkgNames).To(ContainElements("bash", "bash-doc"))
		})

		It("should set correct namespace for platform versions", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record8 := records["ol:8/cve-2024-1001"]
			Expect(record8).NotTo(BeNil())
			vuln8 := record8["Vulnerability"].(map[string]interface{})
			Expect(vuln8["NamespaceName"]).To(Equal("ol:8"))

			record9 := records["ol:9/cve-2024-1001"]
			Expect(record9).NotTo(BeNil())
			vuln9 := record9["Vulnerability"].(map[string]interface{})
			Expect(vuln9["NamespaceName"]).To(Equal("ol:9"))
		})

		It("should include metadata with oracle source info", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-1001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			metadata := vuln["Metadata"].(map[string]interface{})

			Expect(metadata["source"]).To(Equal("oracle-oval"))
			Expect(metadata["distro"]).To(Equal("oracle"))
			Expect(metadata["version"]).To(Equal("8"))
			Expect(metadata["advisoryID"]).To(Equal("ELSA-2024-0001"))
			Expect(metadata["format"]).To(Equal("oval"))
		})

		It("should include link to Oracle errata page", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-1001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Link"]).To(ContainSubstring("linux.oracle.com/errata/ELSA-2024-0001"))
		})

		It("should set rpm version format", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-2001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]map[string]interface{})

			Expect(len(fixedIn)).To(BeNumerically(">=", 1))
			Expect(fixedIn[0]["VersionFormat"]).To(Equal("rpm"))
		})

		It("should sort FixedIn entries by name then version", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-1001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]map[string]interface{})

			Expect(len(fixedIn)).To(BeNumerically(">=", 2))

			for i := 1; i < len(fixedIn); i++ {
				prevName := fixedIn[i-1]["Name"].(string)
				currName := fixedIn[i]["Name"].(string)
				Expect(prevName <= currName).To(BeTrue())
			}
		})
	})

	Context("ksplice filtering", func() {
		BeforeEach(func() {
			testServer = createTestServer(testOVALXML)
			manager = oracle.NewManagerWithURL(testServer.URL, config)
		})

		It("should filter out ksplice package versions", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-3001"]
			Expect(record).NotTo(BeNil())
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]map[string]interface{})

			for _, fi := range fixedIn {
				Expect(fi["Version"].(string)).NotTo(ContainSubstring("ksplice"))
			}
		})

		It("should retain non-ksplice packages from the same definition", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["ol:8/cve-2024-3001"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]map[string]interface{})

			pkgNames := make([]string, 0, len(fixedIn))
			for _, fi := range fixedIn {
				pkgNames = append(pkgNames, fi["Name"].(string))
			}
			Expect(pkgNames).To(ContainElement("openssl"))
		})
	})

	Context("skipping invalid definitions", func() {
		BeforeEach(func() {
			testServer = createTestServer(testOVALXML)
			manager = oracle.NewManagerWithURL(testServer.URL, config)
		})

		It("should skip definitions without ELSA advisory reference", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).NotTo(HaveKey("ol:8/cve-2024-5001"))
		})
	})

	Context("URLs method", func() {
		It("should return the configured URL", func() {
			manager = oracle.NewManagerWithURL("https://example.com/oval.xml.bz2", config)
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal("https://example.com/oval.xml.bz2"))
		})

		It("should return default URL when created with NewManager", func() {
			manager = oracle.NewManager(config)
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(ContainSubstring("linux.oracle.com"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = oracle.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error on HTTP failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			testServer = createTestServer(testOVALXML)
			manager = oracle.NewManagerWithURL(testServer.URL, config)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("OVAL parsing edge cases", func() {
		It("should handle empty OVAL data gracefully", func() {
			emptyXML := `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <generator>
    <product_name>Oracle Linux OVAL</product_name>
    <schema_version>5.11</schema_version>
    <timestamp>2024-01-01T00:00:00</timestamp>
  </generator>
  <definitions/>
  <tests/>
  <objects/>
  <states/>
</oval_definitions>`

			testServer = createTestServer(emptyXML)
			manager = oracle.NewManagerWithURL(testServer.URL, config)

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})
	})
})

var _ = Describe("Oracle OVAL parsing helpers", func() {
	Context("getELSAAdvisoryID", func() {
		It("should extract ELSA ID from reference with source=elsa", func() {
			def := &govalParser.Definition{
				References: []govalParser.Reference{
					{Source: "elsa", RefID: "ELSA-2024-1234"},
					{Source: "cve", RefID: "CVE-2024-1234"},
				},
			}

			result := oracle.GetELSAAdvisoryID(def)
			Expect(result).To(Equal("ELSA-2024-1234"))
		})

		It("should return empty string when no elsa reference exists", func() {
			def := &govalParser.Definition{
				References: []govalParser.Reference{
					{Source: "cve", RefID: "CVE-2024-1234"},
				},
			}

			result := oracle.GetELSAAdvisoryID(def)
			Expect(result).To(BeEmpty())
		})

		It("should return empty string for nil definition", func() {
			result := oracle.GetELSAAdvisoryID(nil)
			Expect(result).To(BeEmpty())
		})

		It("should handle case-insensitive source matching", func() {
			def := &govalParser.Definition{
				References: []govalParser.Reference{
					{Source: "ELSA", RefID: "ELSA-2024-9999"},
				},
			}

			result := oracle.GetELSAAdvisoryID(def)
			Expect(result).To(Equal("ELSA-2024-9999"))
		})
	})

	Context("getOracleSeverity", func() {
		It("should normalize critical severity", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: "Critical"},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("Critical"))
		})

		It("should normalize important severity to High", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: "Important"},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("High"))
		})

		It("should normalize moderate severity to Medium", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: "Moderate"},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("Medium"))
		})

		It("should normalize n/a severity to Low", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: "N/A"},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("Low"))
		})

		It("should return Unknown for empty severity", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: ""},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("Unknown"))
		})

		It("should pass through unknown severity values", func() {
			def := &govalParser.Definition{
				Advisory: govalParser.Advisory{Severity: "CustomSeverity"},
			}
			Expect(oracle.GetOracleSeverity(def)).To(Equal("CustomSeverity"))
		})
	})

	Context("ExtractPackageVersions", func() {
		It("should extract package versions from criterion comments", func() {
			def := &govalParser.Definition{
				Criteria: govalParser.Criteria{
					Operator: "AND",
					Criterions: []govalParser.Criterion{
						{Comment: "Oracle Linux 8 is installed"},
						{Comment: "openssl is earlier than 1.1.1k-9.el8_8"},
						{Comment: "bash is earlier than 5.1.8-6.el8_7"},
					},
				},
			}

			pkgs := oracle.ExtractPackageVersions(def)
			Expect(len(pkgs)).To(BeNumerically(">=", 2))

			names := make([]string, 0, len(pkgs))
			for _, p := range pkgs {
				names = append(names, p.Name)
			}
			Expect(names).To(ContainElements("openssl", "bash"))
		})

		It("should extract from nested criteria", func() {
			def := &govalParser.Definition{
				Criteria: govalParser.Criteria{
					Operator: "AND",
					Criterias: []govalParser.Criteria{
						{
							Operator: "AND",
							Criterions: []govalParser.Criterion{
								{Comment: "nginx is earlier than 1.20.1-9.el8"},
							},
						},
					},
				},
			}

			pkgs := oracle.ExtractPackageVersions(def)
			Expect(len(pkgs)).To(Equal(1))
			Expect(pkgs[0].Name).To(Equal("nginx"))
			Expect(pkgs[0].Version).To(Equal("1.20.1-9.el8"))
		})

		It("should skip signed-with criteria", func() {
			def := &govalParser.Definition{
				Criteria: govalParser.Criteria{
					Operator: "AND",
					Criterions: []govalParser.Criterion{
						{Comment: "kernel-uek is signed with the Oracle Linux 8 key"},
						{Comment: "openssl is earlier than 1.1.1k-9.el8_8"},
					},
				},
			}

			pkgs := oracle.ExtractPackageVersions(def)
			Expect(len(pkgs)).To(Equal(1))
			Expect(pkgs[0].Name).To(Equal("openssl"))
		})

		It("should deduplicate packages", func() {
			def := &govalParser.Definition{
				Criteria: govalParser.Criteria{
					Operator: "AND",
					Criterias: []govalParser.Criteria{
						{
							Operator: "OR",
							Criterions: []govalParser.Criterion{
								{Comment: "openssl is earlier than 1.1.1k-9.el8_8"},
							},
						},
						{
							Operator: "AND",
							Criterions: []govalParser.Criterion{
								{Comment: "openssl is earlier than 1.1.1k-9.el8_8"},
							},
						},
					},
				},
			}

			pkgs := oracle.ExtractPackageVersions(def)
			Expect(len(pkgs)).To(Equal(1))
		})
	})

	Context("FilterKsplice", func() {
		It("should filter out ksplice versions", func() {
			pkgs := []oracle.PkgVersion{
				{Name: "kernel-uek", Version: "5.15.0-203.el8uek.ksplice1"},
				{Name: "openssl", Version: "1.1.1k-9.el8_8"},
				{Name: "kernel-uek", Version: "5.15.0-200.el8uek"},
			}

			filtered := oracle.FilterKsplice(pkgs)
			Expect(len(filtered)).To(Equal(2))
			Expect(filtered[0].Name).To(Equal("openssl"))
			Expect(filtered[1].Name).To(Equal("kernel-uek"))
			Expect(filtered[1].Version).NotTo(ContainSubstring("ksplice"))
		})
	})

	Context("DetectPlatforms", func() {
		It("should detect platforms from affected platforms", func() {
			def := &govalParser.Definition{
				Affecteds: []govalParser.Affected{
					{
						Platforms: []string{
							"Oracle Linux 7",
							"Oracle Linux 8",
							"Oracle Linux 9",
						},
					},
				},
			}

			versions := oracle.DetectPlatforms(def)
			Expect(versions).To(Equal([]string{"7", "8", "9"}))
		})

		It("should fallback to criteria comments when no platforms specified", func() {
			def := &govalParser.Definition{
				Affecteds: []govalParser.Affected{},
				Criteria: govalParser.Criteria{
					Operator: "AND",
					Criterions: []govalParser.Criterion{
						{Comment: "Oracle Linux 8 is installed"},
					},
				},
			}

			versions := oracle.DetectPlatforms(def)
			Expect(versions).To(Equal([]string{"8"}))
		})

		It("should return default version 8 when no platforms detected", func() {
			def := &govalParser.Definition{
				Affecteds: []govalParser.Affected{},
				Criteria:  govalParser.Criteria{Operator: "AND"},
			}

			versions := oracle.DetectPlatforms(def)
			Expect(versions).To(Equal([]string{"8"}))
		})
	})
})
