package debian

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

var distroVersion = map[string]string{
	"buzz":     "11",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forkie":   "14",
	"forky":    "14",
	"duke":     "15",
	"stretch":  "9",
	"jessie":   "8",
	"wheezy":   "7",
	"sid":      "unstable",
}

var severityMap = map[string]string{
	"low":         "Low",
	"low**":       "Low",
	"negligible":  "Negligible",
	"medium":      "Medium",
	"medium**":    "Medium",
	"high":        "High",
	"high**":      "High",
	"unimportant": "Negligible",
}

var (
	dsaInfoRegex     = regexp.MustCompile(`^\[(.+?)\]\s+(DSA-[^\s]+)\s+([^\s]+)[-\s]+(.*)`)
	cveListRegex     = regexp.MustCompile(`^\s+\{(.*)\}`)
	fixedInRegex     = regexp.MustCompile(`^\s+\[(.+?)\][-\s]+(\S*)(.*)`)
	fixedInNoteRegex = regexp.MustCompile(`^\s+NOTE:\s+\[(.+?)\][-\s]+(\S*)(.*)`)
	baseDSAIDRegex   = regexp.MustCompile(`(DSA-[^-]+).*`)
	dsaStartRegex    = regexp.MustCompile(`^\S+.*`)
)

type Manager struct {
	jsonURL string
	dsaURL  string
	config  provider.Config
	client  *http.Client
}

func NewManager(jsonURL, dsaURL string, config provider.Config) *Manager {
	return &Manager{
		jsonURL: jsonURL,
		dsaURL:  dsaURL,
		config:  config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return []string{m.jsonURL, m.dsaURL}
}

type dsaRecord struct {
	ID      string
	Date    string
	Package string
	Summary string
	Link    string
	CVEs    []string
	FixedIn []dsaFixedIn
}

type dsaFixedIn struct {
	DSAID   string
	DSALink string
	Distro  string
	Pkg     string
	Ver     string
}

type dsaCollection struct {
	withCVEs    []*dsaRecord
	withoutCVEs []*dsaRecord
}

func (m *Manager) Get(ctx context.Context) ([]vulnerability.Vulnerability, error) {
	jsonData, err := m.fetchJSON(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JSON: %w", err)
	}

	dsaText, err := m.fetchDSA(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch DSA: %w", err)
	}

	dsaMap := m.parseDSA(dsaText)

	return m.mergeRecords(jsonData, dsaMap), nil
}

func (m *Manager) fetchJSON(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.jsonURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JSON: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "debian.json"), body, 0644); err != nil {
		return nil, fmt.Errorf("save JSON: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}

func (m *Manager) fetchDSA(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.dsaURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch DSA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return "", fmt.Errorf("create input directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "DSA"), body, 0644); err != nil {
		return "", fmt.Errorf("save DSA: %w", err)
	}

	return string(body), nil
}

func (m *Manager) parseDSA(text string) map[string]map[string][]dsaFixedIn {
	dsaMap := make(map[string]*dsaCollection)

	scanner := bufio.NewScanner(strings.NewReader(text))
	var currentLines []string

	for scanner.Scan() {
		line := scanner.Text()

		if dsaStartRegex.MatchString(line) && len(currentLines) > 0 {
			m.processDSABlock(currentLines, dsaMap)
			currentLines = nil
		}

		currentLines = append(currentLines, line)
	}

	if len(currentLines) > 0 {
		m.processDSABlock(currentLines, dsaMap)
	}

	return m.normalizeDSAMap(dsaMap)
}

func (m *Manager) processDSABlock(lines []string, dsaMap map[string]*dsaCollection) {
	dsa := parseDSARecord(lines)
	if dsa == nil {
		return
	}

	baseMatch := baseDSAIDRegex.FindStringSubmatch(dsa.ID)
	baseID := dsa.ID
	if len(baseMatch) > 1 {
		baseID = baseMatch[1]
	}

	if _, ok := dsaMap[baseID]; !ok {
		dsaMap[baseID] = &dsaCollection{}
	}

	if len(dsa.CVEs) > 0 {
		dsaMap[baseID].withCVEs = append(dsaMap[baseID].withCVEs, dsa)
	} else {
		dsaMap[baseID].withoutCVEs = append(dsaMap[baseID].withoutCVEs, dsa)
	}
}

func parseDSARecord(lines []string) *dsaRecord {
	dsa := &dsaRecord{}
	infoMatched := false
	cveMatched := false

	for _, line := range lines {
		if !infoMatched {
			match := dsaInfoRegex.FindStringSubmatch(line)
			if match != nil {
				dsa.Date = match[1]
				dsa.ID = match[2]
				dsa.Package = match[3]
				summary := strings.TrimSpace(match[4])
				dsa.Summary = summary
				dsa.Link = "https://security-tracker.debian.org/tracker/" + dsa.ID
				infoMatched = true
				continue
			}
		}

		if !cveMatched {
			match := cveListRegex.FindStringSubmatch(line)
			if match != nil {
				cves := strings.Fields(match[1])
				dsa.CVEs = cves
				cveMatched = true
				continue
			}
		}

		match := fixedInRegex.FindStringSubmatch(line)
		if match != nil {
			distro := match[1]
			pkg := match[2]
			ver := strings.TrimSpace(match[3])
			dsa.FixedIn = append(dsa.FixedIn, dsaFixedIn{
				DSAID:   dsa.ID,
				DSALink: dsa.Link,
				Distro:  distro,
				Pkg:     pkg,
				Ver:     ver,
			})
			continue
		}

		noteMatch := fixedInNoteRegex.FindStringSubmatch(line)
		if noteMatch != nil {
			distro := noteMatch[1]
			pkg := noteMatch[2]
			ver := strings.TrimSpace(noteMatch[3])
			dsa.FixedIn = append(dsa.FixedIn, dsaFixedIn{
				DSAID:   dsa.ID,
				DSALink: dsa.Link,
				Distro:  distro,
				Pkg:     pkg,
				Ver:     ver,
			})
			continue
		}
	}

	if dsa.ID == "" {
		return nil
	}

	return dsa
}

func (m *Manager) normalizeDSAMap(dsaMap map[string]*dsaCollection) map[string]map[string][]dsaFixedIn {
	nsCVEList := make(map[string]map[string][]dsaFixedIn)

	for _, coll := range dsaMap {
		if len(coll.withoutCVEs) > 0 && len(coll.withCVEs) > 0 {
			cveList := coll.withCVEs[0].CVEs
			for _, dsa := range coll.withoutCVEs {
				dsa.CVEs = make([]string, len(cveList))
				copy(dsa.CVEs, cveList)
			}
			coll.withCVEs = append(coll.withCVEs, coll.withoutCVEs...)
		}

		for _, dsa := range coll.withCVEs {
			for _, fi := range dsa.FixedIn {
				ns := fi.Distro
				for _, cve := range dsa.CVEs {
					if _, ok := nsCVEList[ns]; !ok {
						nsCVEList[ns] = make(map[string][]dsaFixedIn)
					}
					entry := dsaFixedIn{
						DSAID:   fi.DSAID,
						DSALink: fi.DSALink,
						Distro:  fi.Distro,
						Pkg:     fi.Pkg,
						Ver:     fi.Ver,
					}
					nsCVEList[ns][cve] = append(nsCVEList[ns][cve], entry)
				}
			}
		}
	}

	return nsCVEList
}

func (m *Manager) mergeRecords(
	jsonData map[string]interface{},
	dsaMap map[string]map[string][]dsaFixedIn,
) []vulnerability.Vulnerability {
	vulnRecords := make(map[string]map[string]*vulnerability.Vulnerability)

	for pkg, pkgDataRaw := range jsonData {
		pkgData, ok := pkgDataRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for vid, vulnDataRaw := range pkgData {
			if !strings.HasPrefix(vid, "CVE") {
				continue
			}

			vulnData, ok := vulnDataRaw.(map[string]interface{})
			if !ok {
				continue
			}

			releasesRaw, ok := vulnData["releases"]
			if !ok {
				continue
			}
			releases, ok := releasesRaw.(map[string]interface{})
			if !ok || len(releases) == 0 {
				continue
			}

			for rel, distroRecordRaw := range releases {
				relNo, ok := distroVersion[rel]
				if !ok {
					continue
				}

				distRecord, ok := distroRecordRaw.(map[string]interface{})
				if !ok {
					continue
				}

				statusVal, _ := distRecord["status"].(string)
				if statusVal == "undetermined" {
					continue
				}

				if _, ok := vulnRecords[relNo]; !ok {
					vulnRecords[relNo] = make(map[string]*vulnerability.Vulnerability)
				}

				namespace := "debian:" + relNo

				if _, ok := vulnRecords[relNo][vid]; !ok {
					description, _ := vulnData["description"].(string)
					vulnRecords[relNo][vid] = &vulnerability.Vulnerability{
						Name:          vid,
						NamespaceName: namespace,
						Description:   description,
						Severity:      "Unknown",
						Link:          "https://security-tracker.debian.org/tracker/" + vid,
						FixedIn:       []vulnerability.FixedIn{},
						CVSS:          []vulnerability.CVSS{},
						Metadata:      map[string]any{},
					}
				}

				vulnRec := vulnRecords[relNo][vid]

				urgencyVal, hasUrgency := distRecord["urgency"].(string)
				if hasUrgency {
					if sev, ok := severityMap[urgencyVal]; ok {
						if vulnerability.CompareSeverity(sev, vulnRec.Severity) > 0 {
							vulnRec.Severity = sev
						}
					}
				}

				skipFixedIn := false
				fixedIn := vulnerability.NewFixedIn(pkg, namespace, "dpkg", "")

				if fixedVersion, ok := distRecord["fixed_version"].(string); ok {
					fixedIn.Version = fixedVersion
					if fixedVersion == "0" {
						skipFixedIn = true
					}
				} else {
					fixedIn.Version = "None"
				}

				if skipFixedIn {
					continue
				}

				matchedDSAs := m.findDSAMatches(dsaMap, rel, vid, pkg)

				if len(matchedDSAs) > 0 {
					summaries := make([]vulnerability.AdvisorySummary, 0, len(matchedDSAs))
					for _, fi := range matchedDSAs {
						summaries = append(summaries, vulnerability.AdvisorySummary{
							ID:   fi.DSAID,
							Link: fi.DSALink,
						})
					}
					fixedIn.VendorAdvisory = &vulnerability.VendorAdvisory{
						NoAdvisory:      false,
						AdvisorySummary: summaries,
					}
				} else if _, hasNoDSA := distRecord["nodsa"]; hasNoDSA {
					fixedIn.VendorAdvisory = &vulnerability.VendorAdvisory{
						NoAdvisory:      true,
						AdvisorySummary: []vulnerability.AdvisorySummary{},
					}
				} else {
					fixedIn.VendorAdvisory = &vulnerability.VendorAdvisory{
						NoAdvisory:      false,
						AdvisorySummary: []vulnerability.AdvisorySummary{},
					}
				}

				vulnRec.FixedIn = append(vulnRec.FixedIn, fixedIn)
			}
		}
	}

	var result []vulnerability.Vulnerability
	for _, relMap := range vulnRecords {
		for _, vuln := range relMap {
			result = append(result, *vuln)
		}
	}

	return result
}

func (m *Manager) findDSAMatches(
	dsaMap map[string]map[string][]dsaFixedIn,
	rel, cve, pkg string,
) []dsaFixedIn {
	cveDSAs, ok := dsaMap[rel]
	if !ok {
		return nil
	}

	fixedIns, ok := cveDSAs[cve]
	if !ok {
		return nil
	}

	var matches []dsaFixedIn
	for _, fi := range fixedIns {
		if fi.Pkg == pkg {
			matches = append(matches, fi)
		}
	}

	return matches
}
