package mariner

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	govalParser "github.com/quay/goval-parser/oval"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/oval"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

var versionToURL = map[string]string{
	"1.0": "https://raw.githubusercontent.com/microsoft/CBL-MarinerVulnerabilityData/main/cbl-mariner-1.0-oval.xml",
	"2.0": "https://raw.githubusercontent.com/microsoft/CBL-MarinerVulnerabilityData/main/cbl-mariner-2.0-oval.xml",
	"3.0": "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml",
}

var versionToFilename = map[string]string{
	"1.0": "cbl-mariner-1.0-oval.xml",
	"2.0": "cbl-mariner-2.0-oval.xml",
	"3.0": "azurelinux-3.0-oval.xml",
}

type Manager struct {
	config   provider.Config
	client   *http.Client
	versions []string
	urls     []string
}

func NewManager(config provider.Config, versions []string) *Manager {
	return &Manager{
		config:   config,
		client:   &http.Client{Timeout: config.HTTP.Timeout},
		versions: versions,
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]any, error) {
	records := make(map[string]map[string]any)

	for _, version := range m.versions {
		data, url, err := m.downloadOVAL(ctx, version)
		if err != nil {
			return nil, fmt.Errorf("download OVAL for version %s: %w", version, err)
		}
		m.urls = append(m.urls, url)

		filename := versionToFilename[version]
		vulns := ParseOVAL(ctx, data, filename)

		for _, v := range vulns {
			payload := v.ToPayload()
			key := fmt.Sprintf("%s/%s", v.NamespaceName, v.Name)
			records[key] = payload
		}
	}

	return records, nil
}

func (m *Manager) downloadOVAL(ctx context.Context, version string) ([]byte, string, error) {
	url, ok := versionToURL[version]
	if !ok {
		return nil, "", fmt.Errorf("no URL configured for version %s", version)
	}

	filename, ok := versionToFilename[version]
	if !ok {
		return nil, "", fmt.Errorf("no filename configured for version %s", version)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch OVAL data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, "", fmt.Errorf("create input directory: %w", err)
	}

	destPath := filepath.Join(inputDir, filename)
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, "", fmt.Errorf("save OVAL data: %w", err)
	}

	return body, url, nil
}

func ParseOVAL(ctx context.Context, data []byte, filename string) []vulnerability.Vulnerability {
	if err := ctx.Err(); err != nil {
		return nil
	}

	var root govalParser.Root
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil
	}

	version := extractVersion(filename)
	severityMap := extractSeveritiesFromXML(data)
	return extractRecords(&root, version, severityMap)
}

func extractVersion(filename string) string {
	parts := strings.Split(filename, "-")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func extractRecords(root *govalParser.Root, version string, severityMap map[string]string) []vulnerability.Vulnerability {
	rpmTests := make(map[string]*govalParser.RPMInfoTest, len(root.Tests.RPMInfoTests))
	for i := range root.Tests.RPMInfoTests {
		rpmTests[root.Tests.RPMInfoTests[i].ID] = &root.Tests.RPMInfoTests[i]
	}

	rpmObjects := make(map[string]*govalParser.RPMInfoObject, len(root.Objects.RPMInfoObjects))
	for i := range root.Objects.RPMInfoObjects {
		rpmObjects[root.Objects.RPMInfoObjects[i].ID] = &root.Objects.RPMInfoObjects[i]
	}

	rpmStates := make(map[string]*govalParser.RPMInfoState, len(root.States.RPMInfoStates))
	for i := range root.States.RPMInfoStates {
		rpmStates[root.States.RPMInfoStates[i].ID] = &root.States.RPMInfoStates[i]
	}

	namespace := fmt.Sprintf("mariner:%s", version)
	results := make([]vulnerability.Vulnerability, 0)

	for i := range root.Definitions.Definitions {
		def := &root.Definitions.Definitions[i]

		severity := oval.GetSeverity(def)
		if severity == "Unknown" {
			if s, ok := severityMap[def.ID]; ok {
				severity = oval.NormalizeSeverity(s)
			}
		}
		if severity == "Unknown" {
			continue
		}

		cves := oval.ExtractCVEs(def)
		if len(cves) == 0 {
			continue
		}

		vulnID := cves[0]

		link := ""
		if len(def.References) > 0 && def.References[0].RefURL != "" {
			link = def.References[0].RefURL
		}

		tests := collectRPMTests(&def.Criteria, rpmTests)
		if len(tests) == 0 {
			continue
		}

		fixedIn := buildFixedIn(tests, rpmObjects, rpmStates, namespace)
		if fixedIn == nil {
			continue
		}

		vuln := vulnerability.Vulnerability{
			Name:          vulnID,
			NamespaceName: namespace,
			Description:   def.Description,
			Severity:      severity,
			Link:          link,
			CVSS:          []vulnerability.CVSS{},
			FixedIn:       []vulnerability.FixedIn{*fixedIn},
			Metadata:      map[string]any{},
		}

		results = append(results, vuln)
	}

	return results
}

func collectRPMTests(criteria *govalParser.Criteria, rpmTests map[string]*govalParser.RPMInfoTest) []*govalParser.RPMInfoTest {
	if criteria == nil {
		return nil
	}

	var tests []*govalParser.RPMInfoTest

	for _, c := range criteria.Criterions {
		if test, ok := rpmTests[c.TestRef]; ok {
			tests = append(tests, test)
		}
	}

	for i := range criteria.Criterias {
		tests = append(tests, collectRPMTests(&criteria.Criterias[i], rpmTests)...)
	}

	return tests
}

func buildFixedIn(tests []*govalParser.RPMInfoTest, rpmObjects map[string]*govalParser.RPMInfoObject, rpmStates map[string]*govalParser.RPMInfoState, namespace string) *vulnerability.FixedIn {
	if len(tests) == 0 {
		return nil
	}

	firstTest := tests[0]
	objRefs := firstTest.ObjectRef()
	if len(objRefs) == 0 {
		return nil
	}

	obj, ok := rpmObjects[objRefs[0].ObjectRef]
	if !ok || obj.Name == "" {
		return nil
	}
	pkgName := obj.Name

	var vulnRange []string
	var fixedVersion string

	for _, test := range tests {
		stateRefs := test.StateRef()
		for _, sr := range stateRefs {
			state, ok := rpmStates[sr.StateRef]
			if !ok || state.EVR == nil || state.EVR.Body == "" {
				continue
			}

			switch state.EVR.Operation {
			case govalParser.OpLessThan:
				vulnRange = append(vulnRange, fmt.Sprintf("< %s", state.EVR.Body))
				fixedVersion = state.EVR.Body
			case govalParser.OpGreaterThan:
				vulnRange = append(vulnRange, fmt.Sprintf("> %s", state.EVR.Body))
			case govalParser.OpLessThanOrEqual:
				vulnRange = append(vulnRange, fmt.Sprintf("<= %s", state.EVR.Body))
			}
		}
	}

	if len(vulnRange) == 0 {
		return nil
	}

	sort.Sort(sort.Reverse(sort.StringSlice(vulnRange)))

	if fixedVersion == "" {
		fixedVersion = "None"
	}

	vulnRangeStr := strings.Join(vulnRange, ", ")

	fixedIn := vulnerability.NewFixedIn(pkgName, namespace, "rpm", fixedVersion)
	fixedIn.VulnerableRange = vulnRangeStr

	return &fixedIn
}

type severityDef struct {
	XMLName  xml.Name `xml:"definition"`
	ID       string   `xml:"id,attr"`
	Metadata struct {
		Severity string `xml:"severity"`
	} `xml:"metadata"`
}

func extractSeveritiesFromXML(data []byte) map[string]string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	severities := make(map[string]string)
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "definition" {
			var def severityDef
			if decodeErr := decoder.DecodeElement(&def, &se); decodeErr == nil && def.Metadata.Severity != "" {
				severities[def.ID] = def.Metadata.Severity
			}
		}
	}
	return severities
}
