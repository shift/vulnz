package oracle

import (
	"bytes"
	"compress/bzip2"
	"context"
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
)

var (
	platformVersionRe = regexp.MustCompile(`Oracle Linux\s+(\d+)`)
	pkgVersionRe      = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._+-]*)\s+is\s+earlier\s+than\s+(.+)$`)
	kspliceRe         = regexp.MustCompile(`ksplice`)
)

const xmlFileName = "com.oracle.elsa-all.xml"

type Manager struct {
	url    string
	config provider.Config
	client *http.Client
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithURL(DefaultURL, config)
}

func NewManagerWithURL(url string, config provider.Config) *Manager {
	return &Manager{
		url:    url,
		config: config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return []string{m.url}
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	xmlPath, err := m.downloadAndDecompress(ctx)
	if err != nil {
		return nil, fmt.Errorf("download OVAL data: %w", err)
	}

	records, err := m.parseOVAL(ctx, xmlPath)
	if err != nil {
		return nil, fmt.Errorf("parse OVAL data: %w", err)
	}

	return records, nil
}

func (m *Manager) downloadAndDecompress(ctx context.Context) (string, error) {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return "", fmt.Errorf("create input directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch OVAL data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bz2Data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	bz2DestPath := filepath.Join(inputDir, "com.oracle.elsa-all.xml.bz2")
	if err := os.WriteFile(bz2DestPath, bz2Data, 0644); err != nil {
		return "", fmt.Errorf("save bz2 data: %w", err)
	}

	xmlReader := bzip2.NewReader(bytes.NewReader(bz2Data))
	xmlData, err := io.ReadAll(xmlReader)
	if err != nil {
		return "", fmt.Errorf("decompress bz2: %w", err)
	}

	xmlPath := filepath.Join(inputDir, xmlFileName)
	if err := os.WriteFile(xmlPath, xmlData, 0644); err != nil {
		return "", fmt.Errorf("save XML data: %w", err)
	}

	return xmlPath, nil
}

func (m *Manager) parseOVAL(ctx context.Context, xmlPath string) (map[string]map[string]interface{}, error) {
	parser := oval.NewParser()
	if err := parser.ParseFile(ctx, xmlPath); err != nil {
		return nil, fmt.Errorf("parse OVAL XML: %w", err)
	}

	definitions := parser.GetDefinitions()
	m.config.Logger.InfoContext(ctx, "parsed OVAL definitions", "count", len(definitions))

	result := make(map[string]map[string]interface{})

	for _, def := range definitions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		advisoryID := GetELSAAdvisoryID(def)
		if advisoryID == "" {
			continue
		}

		cves := oval.ExtractCVEs(def)
		if len(cves) == 0 {
			continue
		}

		severity := GetOracleSeverity(def)
		description := def.Description

		pkgVersions := ExtractPackageVersions(def)
		if len(pkgVersions) == 0 {
			continue
		}

		pkgVersions = FilterKsplice(pkgVersions)

		if len(pkgVersions) == 0 {
			continue
		}

		versions := DetectPlatforms(def)
		if len(versions) == 0 {
			versions = []string{"8"}
		}

		for _, ver := range versions {
			namespace := fmt.Sprintf("ol:%s", ver)

			fixedIn := make([]map[string]interface{}, 0, len(pkgVersions))
			for _, pv := range pkgVersions {
				fixedIn = append(fixedIn, map[string]interface{}{
					"Name":          pv.Name,
					"NamespaceName": namespace,
					"VersionFormat": "rpm",
					"Version":       pv.Version,
				})
			}

			sort.Slice(fixedIn, func(i, j int) bool {
				ni, _ := fixedIn[i]["Name"].(string)
				nj, _ := fixedIn[j]["Name"].(string)
				if ni != nj {
					return ni < nj
				}
				vi, _ := fixedIn[i]["Version"].(string)
				vj, _ := fixedIn[j]["Version"].(string)
				return vi < vj
			})

			link := fmt.Sprintf("https://linux.oracle.com/errata/%s.html", advisoryID)

			for _, cveID := range cves {
				identifier := fmt.Sprintf("%s/%s", namespace, strings.ToLower(cveID))

				vuln := map[string]interface{}{
					"Vulnerability": map[string]interface{}{
						"Name":          cveID,
						"NamespaceName": namespace,
						"Description":   description,
						"Severity":      severity,
						"Link":          link,
						"FixedIn":       fixedIn,
						"CVSS":          []interface{}{},
						"Metadata": map[string]interface{}{
							"source":       "oracle-oval",
							"distro":       "oracle",
							"version":      ver,
							"advisoryID":   advisoryID,
							"format":       "oval",
							"upstream":     m.url,
							"affectedCves": len(cves),
						},
					},
				}

				if existing, ok := result[identifier]; ok {
					existingVuln, _ := existing["Vulnerability"].(map[string]interface{})
					existingFixedIn, _ := existingVuln["FixedIn"].([]map[string]interface{})
					merged := mergeFixedIn(existingFixedIn, fixedIn)
					existingVuln["FixedIn"] = merged
				} else {
					result[identifier] = vuln
				}
			}
		}
	}

	return result, nil
}

type PkgVersion struct {
	Name    string
	Version string
}

func GetELSAAdvisoryID(def *govalParser.Definition) string {
	if def == nil {
		return ""
	}
	for _, ref := range def.References {
		if strings.ToLower(ref.Source) == "elsa" && ref.RefID != "" {
			return ref.RefID
		}
	}
	return ""
}

func GetOracleSeverity(def *govalParser.Definition) string {
	severityMap := map[string]string{
		"n/a":       "Low",
		"low":       "Low",
		"moderate":  "Medium",
		"important": "High",
		"critical":  "Critical",
	}

	raw := def.Advisory.Severity
	if raw == "" {
		return "Unknown"
	}

	if normalized, ok := severityMap[strings.ToLower(raw)]; ok {
		return normalized
	}
	return raw
}

func ExtractPackageVersions(def *govalParser.Definition) []PkgVersion {
	var results []PkgVersion
	seen := make(map[string]bool)

	collectPackageVersions(&def.Criteria, &results, seen)

	return results
}

func collectPackageVersions(criteria *govalParser.Criteria, results *[]PkgVersion, seen map[string]bool) {
	if criteria == nil {
		return
	}

	for _, criterion := range criteria.Criterions {
		comment := strings.TrimSpace(criterion.Comment)
		matches := pkgVersionRe.FindStringSubmatch(comment)
		if len(matches) == 3 {
			pkgName := matches[1]
			version := strings.TrimSpace(matches[2])
			key := pkgName + ":" + version
			if !seen[key] && pkgName != "" && version != "" && version != "None" && version != "0" {
				seen[key] = true
				*results = append(*results, PkgVersion{Name: pkgName, Version: version})
			}
		}
	}

	for i := range criteria.Criterias {
		collectPackageVersions(&criteria.Criterias[i], results, seen)
	}
}

func FilterKsplice(pkgs []PkgVersion) []PkgVersion {
	var filtered []PkgVersion
	for _, pv := range pkgs {
		if !kspliceRe.MatchString(pv.Version) {
			filtered = append(filtered, pv)
		}
	}
	return filtered
}

func DetectPlatforms(def *govalParser.Definition) []string {
	var versions []string
	seen := make(map[string]bool)

	if def.Affecteds != nil {
		for _, affected := range def.Affecteds {
			for _, platform := range affected.Platforms {
				matches := platformVersionRe.FindStringSubmatch(platform)
				if len(matches) == 2 {
					ver := matches[1]
					if !seen[ver] {
						seen[ver] = true
						versions = append(versions, ver)
					}
				}
			}
		}
	}

	if len(versions) == 0 {
		collectPlatformsFromCriteria(&def.Criteria, &versions, seen)
	}

	if len(versions) == 0 {
		versions = []string{"8"}
	}

	sort.Strings(versions)
	return versions
}

func collectPlatformsFromCriteria(criteria *govalParser.Criteria, versions *[]string, seen map[string]bool) {
	if criteria == nil {
		return
	}

	for _, criterion := range criteria.Criterions {
		matches := platformVersionRe.FindStringSubmatch(criterion.Comment)
		if len(matches) == 2 {
			ver := matches[1]
			if !seen[ver] {
				seen[ver] = true
				*versions = append(*versions, ver)
			}
		}
	}

	for i := range criteria.Criterias {
		collectPlatformsFromCriteria(&criteria.Criterias[i], versions, seen)
	}
}

func mergeFixedIn(existing, incoming []map[string]interface{}) []map[string]interface{} {
	merged := make([]map[string]interface{}, len(existing))
	copy(merged, existing)

	for _, fi := range incoming {
		name, _ := fi["Name"].(string)
		version, _ := fi["Version"].(string)
		found := false
		for _, existingFI := range merged {
			existingName, _ := existingFI["Name"].(string)
			existingVer, _ := existingFI["Version"].(string)
			if existingName == name && existingVer == version {
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, fi)
		}
	}

	sort.Slice(merged, func(i, j int) bool {
		ni, _ := merged[i]["Name"].(string)
		nj, _ := merged[j]["Name"].(string)
		if ni != nj {
			return ni < nj
		}
		vi, _ := merged[i]["Version"].(string)
		vj, _ := merged[j]["Version"].(string)
		return vi < vj
	})

	return merged
}
