package sles

import (
	"bytes"
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	govalParser "github.com/quay/goval-parser/oval"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/oval"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

var (
	platformRe    = regexp.MustCompile(`SUSE Linux Enterprise Server \d+.* is installed`)
	artifactRe    = regexp.MustCompile(`.* is installed`)
	platformVerRe = regexp.MustCompile(`SUSE Linux Enterprise Server (\d+(?:\.\d+)?)`)
	slesReleaseRe = regexp.MustCompile(`(sles-release|sles-ltss-release) is installed`)
)

type severityMapEntry struct {
	raw        string
	normalized string
}

var severityMappings = []severityMapEntry{
	{"low", "Low"},
	{"moderate", "Medium"},
	{"medium", "Medium"},
	{"high", "High"},
	{"important", "High"},
	{"critical", "Critical"},
}

type Manager struct {
	config   provider.Config
	versions []string
	urls     []string
	client   *http.Client
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithVersions(config, defaultVersions)
}

func NewManagerWithVersions(config provider.Config, versions []string) *Manager {
	return &Manager{
		config:   config,
		versions: versions,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{})

	for _, majorVersion := range m.versions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		xmlData, err := m.downloadOVAL(ctx, majorVersion)
		if err != nil {
			return nil, fmt.Errorf("download OVAL for SLES %s: %w", majorVersion, err)
		}

		advisories, err := m.ParseOVAL(ctx, xmlData, majorVersion)
		if err != nil {
			return nil, fmt.Errorf("parse OVAL for SLES %s: %w", majorVersion, err)
		}

		for id, advisory := range advisories {
			if existing, ok := result[id]; ok {
				mergeAdvisories(existing, advisory)
			} else {
				result[id] = advisory
			}
		}
	}

	return result, nil
}

func (m *Manager) ParseOVAL(ctx context.Context, xmlData []byte, majorVersion string) (map[string]map[string]interface{}, error) {
	return m.parseOVAL(ctx, xmlData, majorVersion)
}

func (m *Manager) downloadOVAL(ctx context.Context, majorVersion string) ([]byte, error) {
	inputDir := filepath.Join(m.config.Workspace, "input", ovalDirName)
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	downloadURL := fmt.Sprintf(ovalURLTemplate, majorVersion)
	ovalFilePath := filepath.Join(inputDir, fmt.Sprintf(ovalFileNameFmt, majorVersion))

	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create HEAD request: %w", err)
	}
	headReq.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	headResp, err := m.client.Do(headReq)
	if err != nil {
		return nil, fmt.Errorf("HEAD request for OVAL: %w", err)
	}
	headResp.Body.Close()

	if headResp.StatusCode == http.StatusNotFound {
		downloadURL = strings.TrimSuffix(downloadURL, ".bz2") + ".gz"
		ovalFilePath = strings.TrimSuffix(ovalFilePath, ".bz2") + ".gz"
	}

	m.urls = append(m.urls, downloadURL)

	m.config.Logger.InfoContext(ctx, "downloading OVAL file",
		"version", majorVersion,
		"url", downloadURL,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch OVAL data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d for %s", resp.StatusCode, downloadURL)
	}

	compressedData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if err := os.WriteFile(ovalFilePath, compressedData, 0644); err != nil {
		return nil, fmt.Errorf("save compressed OVAL: %w", err)
	}

	xmlReader := bzip2.NewReader(bytes.NewReader(compressedData))
	xmlData, err := io.ReadAll(xmlReader)
	if err != nil {
		return nil, fmt.Errorf("decompress bz2: %w", err)
	}

	xmlPath := strings.TrimSuffix(ovalFilePath, ".bz2")
	if err := os.WriteFile(xmlPath, xmlData, 0644); err != nil {
		return nil, fmt.Errorf("save XML OVAL: %w", err)
	}

	return xmlData, nil
}

func (m *Manager) parseOVAL(ctx context.Context, xmlData []byte, majorVersion string) (map[string]map[string]interface{}, error) {
	var root govalParser.Root
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return nil, fmt.Errorf("parse OVAL XML: %w", err)
	}

	definitions := root.Definitions.Definitions
	m.config.Logger.InfoContext(ctx, "parsed OVAL definitions",
		"version", majorVersion,
		"count", len(definitions),
	)

	rpmTests := buildRPMTestMap(root.Tests.RPMInfoTests)
	rpmObjects := buildRPMObjectMap(root.Objects.RPMInfoObjects)
	rpmStates := buildRPMStateMap(root.States.RPMInfoStates)

	result := make(map[string]map[string]interface{})

	for i := range definitions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		def := &definitions[i]

		if def.Class != "vulnerability" {
			continue
		}

		advisoryID := getSUSEAdvisoryID(def)
		if advisoryID == "" {
			continue
		}

		cves := oval.ExtractCVEs(def)
		if len(cves) == 0 {
			continue
		}

		severity := mapSLESSeverity(def)
		description := def.Description
		link := getSUSELink(def)

		impacts := traverseCriteria(&def.Criteria, majorVersion, rpmTests, rpmObjects, rpmStates)
		if len(impacts) == 0 {
			continue
		}

		for _, impact := range impacts {
			namespace := fmt.Sprintf("%s:%s", defaultNamespace, impact.releaseVersion)

			fixedIn := make([]vulnerability.FixedIn, 0, len(impact.fixes))
			for _, fix := range impact.fixes {
				if fix.version == "0" || fix.version == "None" || fix.version == "" {
					continue
				}
				fixedIn = append(fixedIn, vulnerability.NewFixedIn(fix.name, namespace, "rpm", fix.version))
			}

			if len(fixedIn) == 0 {
				continue
			}

			sort.Slice(fixedIn, func(i, j int) bool {
				if fixedIn[i].Name != fixedIn[j].Name {
					return fixedIn[i].Name < fixedIn[j].Name
				}
				return fixedIn[i].Version < fixedIn[j].Version
			})

			vuln := vulnerability.Vulnerability{
				Name:          advisoryID,
				NamespaceName: namespace,
				Description:   description,
				Severity:      severity,
				Link:          link,
				FixedIn:       fixedIn,
				CVSS:          []vulnerability.CVSS{},
			}

			for _, cveID := range cves {
				identifier := fmt.Sprintf("%s/%s", namespace, strings.ToLower(cveID))

				existingPayload, ok := result[identifier]
				if ok {
					mergeIntoPayload(existingPayload, vuln)
				} else {
					result[identifier] = vuln.ToPayload()
				}
			}
		}
	}

	return result, nil
}

type rpmTestInfo struct {
	id        string
	comment   string
	objectRef string
	stateRef  string
}

type rpmObjectInfo struct {
	id   string
	name string
}

type rpmStateInfo struct {
	id        string
	operation string
	value     string
}

type impactGroup struct {
	releaseVersion string
	releaseName    string
	fixes          []pkgFix
}

type pkgFix struct {
	name    string
	version string
}

func buildRPMTestMap(tests []govalParser.RPMInfoTest) map[string]rpmTestInfo {
	m := make(map[string]rpmTestInfo, len(tests))
	for i := range tests {
		t := &tests[i]
		objRef := ""
		if len(t.ObjectRef()) > 0 {
			objRef = t.ObjectRef()[0].ObjectRef
		}
		stateRef := ""
		if len(t.StateRef()) > 0 {
			stateRef = t.StateRef()[0].StateRef
		}
		m[t.ID] = rpmTestInfo{
			id:        t.ID,
			comment:   t.Comment,
			objectRef: objRef,
			stateRef:  stateRef,
		}
	}
	return m
}

func buildRPMObjectMap(objects []govalParser.RPMInfoObject) map[string]rpmObjectInfo {
	m := make(map[string]rpmObjectInfo, len(objects))
	for i := range objects {
		o := &objects[i]
		m[o.ID] = rpmObjectInfo{
			id:   o.ID,
			name: o.Name,
		}
	}
	return m
}

func buildRPMStateMap(states []govalParser.RPMInfoState) map[string]rpmStateInfo {
	m := make(map[string]rpmStateInfo, len(states))
	for i := range states {
		s := &states[i]
		value := ""
		operation := ""
		if s.EVR != nil {
			value = s.EVR.Body
			operation = opToString(s.EVR.Operation)
		} else if s.RPMVersion != nil {
			value = s.RPMVersion.Body
			operation = opToString(s.RPMVersion.Operation)
		}
		m[s.ID] = rpmStateInfo{
			id:        s.ID,
			operation: operation,
			value:     value,
		}
	}
	return m
}

func opToString(op govalParser.Operation) string {
	switch op {
	case govalParser.OpEquals:
		return "equals"
	case govalParser.OpNotEquals:
		return "not equal"
	case govalParser.OpLessThan:
		return "less than"
	case govalParser.OpLessThanOrEqual:
		return "less than or equal"
	case govalParser.OpGreaterThan:
		return "greater than"
	case govalParser.OpGreaterThanOrEqual:
		return "greater than or equal"
	case govalParser.OpPatternMatch:
		return "pattern match"
	default:
		return ""
	}
}

func traverseCriteria(
	criteria *govalParser.Criteria,
	majorVersion string,
	tests map[string]rpmTestInfo,
	objects map[string]rpmObjectInfo,
	states map[string]rpmStateInfo,
) []impactGroup {
	if criteria == nil {
		return nil
	}

	var results []impactGroup

	if strings.EqualFold(criteria.Operator, "or") {
		for i := range criteria.Criterias {
			group := criteria.Criterias[i]
			if len(group.Criterias) != 2 {
				continue
			}

			namespaceIDs := parseSubGroup(&group.Criterias[0], platformRe)
			if len(namespaceIDs) == 0 {
				continue
			}

			testIDs := parseSubGroup(&group.Criterias[1], artifactRe)
			if len(testIDs) == 0 {
				continue
			}

			for _, nsTestID := range namespaceIDs {
				nsTest, ok := tests[nsTestID]
				if !ok {
					continue
				}

				releaseName := extractReleaseName(nsTest.comment)
				releaseVersion := extractReleaseVersion(nsTestID, tests, objects, states, majorVersion)
				if releaseVersion == "" || !strings.HasPrefix(releaseVersion, majorVersion) {
					continue
				}

				fixes := collectFixes(testIDs, tests, objects, states)
				if len(fixes) > 0 {
					results = append(results, impactGroup{
						releaseVersion: releaseVersion,
						releaseName:    releaseName,
						fixes:          fixes,
					})
				}
			}
		}
	} else if len(criteria.Criterias) == 2 {
		namespaceIDs := parseSubGroup(&criteria.Criterias[0], platformRe)
		if len(namespaceIDs) == 0 {
			return nil
		}

		testIDs := parseSubGroup(&criteria.Criterias[1], artifactRe)

		for _, nsTestID := range namespaceIDs {
			nsTest, ok := tests[nsTestID]
			if !ok {
				continue
			}

			releaseName := extractReleaseName(nsTest.comment)
			releaseVersion := extractReleaseVersion(nsTestID, tests, objects, states, majorVersion)
			if releaseVersion == "" || !strings.HasPrefix(releaseVersion, majorVersion) {
				continue
			}

			fixes := collectFixes(testIDs, tests, objects, states)
			if len(fixes) > 0 {
				results = append(results, impactGroup{
					releaseVersion: releaseVersion,
					releaseName:    releaseName,
					fixes:          fixes,
				})
			}
		}
	}

	return resolveReleases(results)
}

func parseSubGroup(criteria *govalParser.Criteria, re *regexp.Regexp) []string {
	if criteria == nil {
		return nil
	}

	var testIDs []string

	for _, c := range criteria.Criterions {
		if c.TestRef != "" && re.MatchString(c.Comment) {
			testIDs = append(testIDs, c.TestRef)
		}
	}

	for i := range criteria.Criterias {
		testIDs = append(testIDs, parseSubGroup(&criteria.Criterias[i], re)...)
	}

	return testIDs
}

func extractReleaseName(comment string) string {
	matches := slesReleaseRe.FindStringSubmatch(comment)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func extractReleaseVersion(
	testID string,
	tests map[string]rpmTestInfo,
	objects map[string]rpmObjectInfo,
	states map[string]rpmStateInfo,
	majorVersion string,
) string {
	test, ok := tests[testID]
	if !ok {
		return ""
	}

	obj, ok := objects[test.objectRef]
	if !ok {
		return ""
	}

	if state, ok := states[test.stateRef]; ok && state.operation == "equals" {
		ver := extractVersionFromEVR(state.value)
		if ver != "" && strings.HasPrefix(ver, majorVersion) {
			return ver
		}
	}

	matches := platformVerRe.FindStringSubmatch(obj.name)
	if len(matches) >= 2 {
		ver := matches[1]
		if strings.HasPrefix(ver, majorVersion) {
			return ver
		}
	}

	return ""
}

func extractVersionFromEVR(evr string) string {
	evr = strings.TrimSpace(evr)
	parts := strings.SplitN(evr, ":", 2)
	verPart := parts[0]
	if len(parts) > 1 {
		verPart = parts[1]
	}
	verParts := strings.SplitN(verPart, "-", 2)
	return verParts[0]
}

func collectFixes(
	testIDs []string,
	tests map[string]rpmTestInfo,
	objects map[string]rpmObjectInfo,
	states map[string]rpmStateInfo,
) []pkgFix {
	seen := make(map[string]bool)
	var fixes []pkgFix

	for _, testID := range testIDs {
		test, ok := tests[testID]
		if !ok {
			continue
		}

		obj, ok := objects[test.objectRef]
		if !ok {
			continue
		}

		state, ok := states[test.stateRef]
		if !ok {
			continue
		}

		key := obj.name + ":" + state.value
		if seen[key] {
			continue
		}
		seen[key] = true

		if obj.name != "" && state.value != "" {
			fixes = append(fixes, pkgFix{name: obj.name, version: state.value})
		}
	}

	return fixes
}

func resolveReleases(impacts []impactGroup) []impactGroup {
	versionMap := make(map[string]map[string]impactGroup)

	for _, imp := range impacts {
		if _, ok := versionMap[imp.releaseVersion]; !ok {
			versionMap[imp.releaseVersion] = make(map[string]impactGroup)
		}

		if existing, ok := versionMap[imp.releaseVersion][imp.releaseName]; ok {
			existing.fixes = append(existing.fixes, imp.fixes...)
			versionMap[imp.releaseVersion][imp.releaseName] = existing
		} else {
			versionMap[imp.releaseVersion][imp.releaseName] = imp
		}
	}

	var results []impactGroup
	for ver, releaseMap := range versionMap {
		if len(releaseMap) == 1 {
			for _, imp := range releaseMap {
				imp.releaseVersion = ver
				results = append(results, imp)
			}
			continue
		}

		if imp, ok := releaseMap["sles-release"]; ok {
			imp.releaseVersion = ver
			results = append(results, imp)
			continue
		}

		if imp, ok := releaseMap["sles-ltss-release"]; ok {
			imp.releaseVersion = ver
			results = append(results, imp)
			continue
		}
	}

	return results
}

func getSUSEAdvisoryID(def *govalParser.Definition) string {
	if def.Title != "" {
		return strings.TrimSpace(def.Title)
	}
	return def.ID
}

func getSUSELink(def *govalParser.Definition) string {
	for _, ref := range def.References {
		if strings.EqualFold(ref.Source, "SUSE CVE") && ref.RefURL != "" {
			return ref.RefURL
		}
	}
	for _, ref := range def.References {
		if ref.RefURL != "" {
			return ref.RefURL
		}
	}
	return ""
}

func mapSLESSeverity(def *govalParser.Definition) string {
	raw := strings.ToLower(def.Advisory.Severity)
	for _, mapping := range severityMappings {
		if strings.EqualFold(raw, mapping.raw) {
			return mapping.normalized
		}
	}
	if raw != "" {
		return strings.Title(raw)
	}
	return "Unknown"
}

func mergeAdvisories(existing, incoming map[string]interface{}) {
	existingVuln, ok := existing["Vulnerability"].(vulnerability.Vulnerability)
	if !ok {
		return
	}
	incomingVuln, ok := incoming["Vulnerability"].(vulnerability.Vulnerability)
	if !ok {
		return
	}
	existingVuln.FixedIn = append(existingVuln.FixedIn, incomingVuln.FixedIn...)
	existing["Vulnerability"] = existingVuln
}

func mergeIntoPayload(payload map[string]interface{}, vuln vulnerability.Vulnerability) {
	existingVuln, ok := payload["Vulnerability"].(vulnerability.Vulnerability)
	if !ok {
		return
	}

	seen := make(map[string]bool)
	for _, fi := range existingVuln.FixedIn {
		key := fi.Name + ":" + fi.Version
		seen[key] = true
	}

	for _, fi := range vuln.FixedIn {
		key := fi.Name + ":" + fi.Version
		if !seen[key] {
			existingVuln.FixedIn = append(existingVuln.FixedIn, fi)
			seen[key] = true
		}
	}

	payload["Vulnerability"] = existingVuln
}
