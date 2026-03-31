package rhel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	vulnzhttp "github.com/shift/vulnz/internal/http"
	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/archive"
	csafutil "github.com/shift/vulnz/internal/utils/csaf"
	"github.com/shift/vulnz/internal/utils/vulnerability"
	"github.com/gocsaf/csaf/v3/csaf"
)

const (
	advisoriesBaseURL       = "https://security.access.redhat.com/data/csaf/v2/advisories/"
	advisoriesLatestURL     = advisoriesBaseURL + "archive_latest.txt"
	advisoriesArchivePrefix = "csaf_advisories_"
	rhelURLPrefix           = "https://access.redhat.com/errata/"
)

var (
	rhelReleasePattern = regexp.MustCompile(`Red Hat Enterprise Linux\s*(\d+)$`)
	rhelEUSPattern     = regexp.MustCompile(`Red Hat Enterprise Linux (\d+\.\d+) Extended Update Support`)
	rhelELSPattern     = regexp.MustCompile(`Red Hat Enterprise Linux (\d+) Extended Lifecycle Support`)
)

type Manager struct {
	config         provider.Config
	client         *http.Client
	urls           []string
	advisoriesPath string
	csafCache      sync.Map
	skipNamespaces map[string]bool
}

func NewManager(config provider.Config) *Manager {
	return &Manager{
		config: config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 20,
				MaxConnsPerHost:     40,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		advisoriesPath: filepath.Join(config.Workspace, "advisories"),
		skipNamespaces: map[string]bool{
			"rhel:3": true,
			"rhel:4": true,
		},
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) Get(ctx context.Context) ([]vulnerability.Vulnerability, []string, error) {
	if err := m.downloadAndSync(ctx); err != nil {
		return nil, nil, fmt.Errorf("download and sync CSAF data: %w", err)
	}

	records, err := m.parseAdvisories(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("parse advisories: %w", err)
	}

	return records, m.urls, nil
}

func (m *Manager) downloadAndSync(ctx context.Context) error {
	if err := os.MkdirAll(m.advisoriesPath, 0755); err != nil {
		return fmt.Errorf("create advisories directory: %w", err)
	}

	archiveURL, archiveDate, err := m.resolveArchiveURL(ctx)
	if err != nil {
		return fmt.Errorf("resolve archive URL: %w", err)
	}

	archiveFilename := filepath.Base(archiveURL)
	localArchivePath := filepath.Join(m.config.Workspace, archiveFilename)

	if _, err := os.Stat(localArchivePath); os.IsNotExist(err) {
		for _, existing := range m.findExistingArchives() {
			os.Remove(existing)
		}

		if err := m.downloadFile(ctx, archiveURL, localArchivePath); err != nil {
			return fmt.Errorf("download archive: %w", err)
		}

		if err := archive.Extract(ctx, localArchivePath, m.advisoriesPath); err != nil {
			return fmt.Errorf("extract archive: %w", err)
		}
	}

	changesPath := filepath.Join(m.config.Workspace, "changes.csv")
	deletionsPath := filepath.Join(m.config.Workspace, "deletions.csv")

	if err := m.downloadFile(ctx, advisoriesBaseURL+"changes.csv", changesPath); err != nil {
		return fmt.Errorf("download changes.csv: %w", err)
	}
	if err := m.downloadFile(ctx, advisoriesBaseURL+"deletions.csv", deletionsPath); err != nil {
		return fmt.Errorf("download deletions.csv: %w", err)
	}

	m.processChangesAndDeletions(ctx, changesPath, deletionsPath, archiveDate)

	return nil
}

func (m *Manager) resolveArchiveURL(ctx context.Context) (string, string, error) {
	latestResp, err := m.httpGet(ctx, advisoriesLatestURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch latest archive name: %w", err)
	}

	latestName, err := vulnzhttp.ReadLimitedBody(latestResp)
	if err != nil {
		return "", "", fmt.Errorf("read latest archive name: %w", err)
	}

	name := strings.TrimSpace(string(latestName))
	archiveURL := advisoriesBaseURL + name

	datePart := strings.TrimPrefix(name, advisoriesArchivePrefix)
	datePart = strings.TrimSuffix(datePart, ".tar.zst")

	return archiveURL, datePart, nil
}

func (m *Manager) findExistingArchives() []string {
	var files []string
	entries, err := os.ReadDir(m.config.Workspace)
	if err != nil {
		return files
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), advisoriesArchivePrefix) {
			files = append(files, filepath.Join(m.config.Workspace, entry.Name()))
		}
	}
	return files
}

func (m *Manager) downloadFile(ctx context.Context, url, dest string) error {
	m.urls = append(m.urls, url)

	resp, err := m.httpGet(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create file %s: %w", dest, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write file %s: %w", dest, err)
	}

	return nil
}

func (m *Manager) httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	return m.client.Do(req)
}

func sanitizeCSVFilename(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty filename")
	}
	if filepath.IsAbs(name) || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("invalid filename: %s", name)
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return "", fmt.Errorf("invalid character in filename: %s", name)
		}
	}
	return name, nil
}

func (m *Manager) processChangesAndDeletions(ctx context.Context, changesPath, deletionsPath, archiveDate string) {
	deletionsData, err := os.ReadFile(deletionsPath)
	if err == nil {
		lines := strings.Split(string(deletionsData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fragment := strings.Trim(line, "\"")
			safe, err := sanitizeCSVFilename(filepath.Base(fragment))
			if err != nil {
				m.config.Logger.WarnContext(ctx, "skipping invalid deletion path", "path", fragment, "error", err)
				continue
			}
			os.Remove(filepath.Join(m.advisoriesPath, safe))
		}
	}

	changesData, err := os.ReadFile(changesPath)
	if err != nil {
		return
	}

	seenFiles := make(map[string]bool)
	years := make(map[string]bool)
	lines := strings.Split(string(changesData), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 2 {
			continue
		}

		changedFile := strings.Trim(parts[0], "\"")
		dateStr := strings.Trim(parts[1], "\"")

		if archiveDate != "" && dateStr < archiveDate {
			break
		}

		seenFiles[changedFile] = true
		safeChanged, err := sanitizeCSVFilename(filepath.Base(changedFile))
		if err == nil {
			yearPart := strings.SplitN(safeChanged, "/", 2)
			if len(yearPart) > 0 {
				years[yearPart[0]] = true
			}
		}
	}

	for year := range years {
		os.MkdirAll(filepath.Join(m.advisoriesPath, year), 0755)
	}

	type dl struct {
		url  string
		path string
	}

	var downloads []dl
	for file := range seenFiles {
		safeFile, err := sanitizeCSVFilename(filepath.Base(file))
		if err != nil {
			m.config.Logger.WarnContext(ctx, "skipping invalid changed file path", "file", file, "error", err)
			continue
		}
		downloads = append(downloads, dl{
			url:  advisoriesBaseURL + file,
			path: filepath.Join(m.advisoriesPath, safeFile),
		})
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	for _, d := range downloads {
		wg.Add(1)
		go func(d dl) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := m.downloadFile(ctx, d.url, d.path); err != nil {
				m.config.Logger.WarnContext(ctx, "failed to download changed file", "file", d.url, "error", err)
			}
		}(d)
	}
	wg.Wait()
}

func (m *Manager) parseAdvisories(ctx context.Context) ([]vulnerability.Vulnerability, error) {
	type fileEntry struct {
		path string
	}

	var allFiles []fileEntry

	yearDirs, err := os.ReadDir(m.advisoriesPath)
	if err != nil {
		return nil, fmt.Errorf("read advisories directory: %w", err)
	}

	for _, yearDir := range yearDirs {
		if !yearDir.IsDir() {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		yearPath := filepath.Join(m.advisoriesPath, yearDir.Name())
		files, err := os.ReadDir(yearPath)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			allFiles = append(allFiles, fileEntry{
				path: filepath.Join(yearPath, file.Name()),
			})
		}
	}

	m.config.Logger.InfoContext(ctx, "parsing CSAF advisories", "total_files", len(allFiles))

	var (
		mu      sync.Mutex
		records []vulnerability.Vulnerability
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 16)
		parsed  int
	)

	for _, fe := range allFiles {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(fp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			doc, err := m.loadCSAFDoc(fp)
			if err != nil {
				m.config.Logger.DebugContext(ctx, "failed to load CSAF document", "path", fp, "error", err)
				return
			}

			vulns := m.parseCSAFDocument(doc)

			mu.Lock()
			records = append(records, vulns...)
			parsed++
			if parsed%1000 == 0 {
				m.config.Logger.InfoContext(ctx, "parsing CSAF advisories progress", "parsed", parsed, "total", len(allFiles))
			}
			mu.Unlock()
		}(fe.path)
	}

	wg.Wait()

	m.config.Logger.InfoContext(ctx, "finished parsing CSAF advisories", "total_parsed", parsed, "total_records", len(records))

	return records, nil
}

func (m *Manager) loadCSAFDoc(path string) (*csaf.Advisory, error) {
	if cached, ok := m.csafCache.Load(path); ok {
		return cached.(*csaf.Advisory), nil
	}

	doc, err := csaf.LoadAdvisory(path)
	if err != nil {
		return nil, err
	}

	m.csafCache.Store(path, doc)
	return doc, nil
}

func (m *Manager) parseCSAFDocument(doc *csaf.Advisory) []vulnerability.Vulnerability {
	if doc == nil || doc.Document == nil || doc.Document.Tracking == nil || doc.Document.Tracking.ID == nil {
		return nil
	}

	advisoryID := string(*doc.Document.Tracking.ID)
	advisoryURL := rhelURLPrefix + advisoryID

	simplified := csafutil.Simplify(doc)
	severity := NormalizeSeverity(simplified.Severity)
	description := simplified.Summary

	cveIDs := csafutil.ExtractCVEs(doc)
	if len(cveIDs) == 0 {
		return nil
	}

	productInfo := m.extractProductInfo(doc)

	var vulns []vulnerability.Vulnerability

	for _, cveID := range cveIDs {
		vulnForCVE := m.buildVulnerabilityForCVE(doc, cveID, advisoryID, advisoryURL, severity, description, productInfo)
		vulns = append(vulns, vulnForCVE...)
	}

	return vulns
}

type productInfo struct {
	cpe      string
	platform string
	module   string
	name     string
	version  string
}

func (m *Manager) extractProductInfo(doc *csaf.Advisory) []productInfo {
	var infos []productInfo

	if doc.ProductTree == nil {
		return infos
	}

	productIDToCPE := m.buildProductIDToCPEMap(doc)
	productIDToPURL := m.buildProductIDToPURLMap(doc)

	if doc.ProductTree.FullProductNames != nil {
		for _, fpn := range *doc.ProductTree.FullProductNames {
			if fpn.ProductID == nil {
				continue
			}
			pid := string(*fpn.ProductID)
			purlStr := productIDToPURL[pid]

			name, version, module := parsePURL(purlStr)

			cpe := productIDToCPE[pid]
			if cpe == "" && fpn.ProductIdentificationHelper != nil && fpn.ProductIdentificationHelper.CPE != nil {
				cpe = string(*fpn.ProductIdentificationHelper.CPE)
			}

			platform := parsePlatformFromCPE(cpe)
			if platform == "" {
				continue
			}

			infos = append(infos, productInfo{
				cpe:      cpe,
				platform: platform,
				module:   module,
				name:     name,
				version:  version,
			})
		}
	}

	return infos
}

func (m *Manager) buildProductIDToCPEMap(doc *csaf.Advisory) map[string]string {
	result := make(map[string]string)
	if doc.ProductTree == nil || doc.ProductTree.Branches == nil {
		return result
	}
	m.collectCPEsFromBranches(doc.ProductTree.Branches, result)
	return result
}

func (m *Manager) collectCPEsFromBranches(branches csaf.Branches, result map[string]string) {
	for _, branch := range branches {
		if branch.Product != nil && branch.Product.ProductID != nil {
			pid := string(*branch.Product.ProductID)
			if branch.Product.ProductIdentificationHelper != nil && branch.Product.ProductIdentificationHelper.CPE != nil {
				result[pid] = string(*branch.Product.ProductIdentificationHelper.CPE)
			}
		}
		if branch.Branches != nil {
			m.collectCPEsFromBranches(branch.Branches, result)
		}
	}
}

func (m *Manager) buildProductIDToPURLMap(doc *csaf.Advisory) map[string]string {
	result := make(map[string]string)
	if doc.ProductTree == nil || doc.ProductTree.Branches == nil {
		return result
	}
	m.collectPURLsFromBranches(doc.ProductTree.Branches, result)
	return result
}

func (m *Manager) collectPURLsFromBranches(branches csaf.Branches, result map[string]string) {
	for _, branch := range branches {
		if branch.Product != nil && branch.Product.ProductID != nil {
			pid := string(*branch.Product.ProductID)
			if branch.Product.ProductIdentificationHelper != nil && branch.Product.ProductIdentificationHelper.PURL != nil {
				result[pid] = string(*branch.Product.ProductIdentificationHelper.PURL)
			}
		}
		if branch.Branches != nil {
			m.collectPURLsFromBranches(branch.Branches, result)
		}
	}
}

func (m *Manager) buildVulnerabilityForCVE(
	doc *csaf.Advisory,
	cveID, advisoryID, advisoryURL, severity, description string,
	productInfos []productInfo,
) []vulnerability.Vulnerability {
	var vulns []vulnerability.Vulnerability

	scores := m.extractCVSSForCVE(doc, cveID)
	remediations := m.extractRemediationsForCVE(doc, cveID)

	platformFixedIn := m.buildPlatformFixedIn(remediations, productInfos, advisoryID)

	for ns, fixedIns := range platformFixedIn {
		if m.skipNamespaces[ns] {
			continue
		}

		cvss := m.convertScores(scores, ns)
		if cvss == nil {
			cvss = []vulnerability.CVSS{}
		}

		vulns = append(vulns, vulnerability.Vulnerability{
			Name:          cveID,
			NamespaceName: ns,
			Description:   description,
			Severity:      severity,
			Link:          advisoryURL,
			CVSS:          cvss,
			FixedIn:       fixedIns,
			Metadata:      map[string]any{},
		})
	}

	return vulns
}

func (m *Manager) extractCVSSForCVE(doc *csaf.Advisory, cveID string) []csafutil.Score {
	if doc == nil || doc.Vulnerabilities == nil {
		return nil
	}

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == nil || string(*vuln.CVE) != cveID {
			continue
		}
		return csafutil.ExtractScores(doc)
	}

	return nil
}

func (m *Manager) extractRemediationsForCVE(doc *csaf.Advisory, cveID string) []csafutil.Remediation {
	if doc == nil || doc.Vulnerabilities == nil {
		return nil
	}

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == nil || string(*vuln.CVE) != cveID {
			continue
		}
		if vuln.Remediations == nil {
			return nil
		}

		var result []csafutil.Remediation
		for _, rem := range vuln.Remediations {
			if rem.Category == nil {
				continue
			}
			cat := string(*rem.Category)
			if cat != "vendor_fix" && cat != "package_fix" {
				continue
			}

			r := csafutil.Remediation{
				Category:   cat,
				ProductIDs: []string{},
			}

			if rem.Details != nil {
				r.Details = *rem.Details
			}
			if rem.URL != nil {
				r.URL = *rem.URL
			}
			if rem.ProductIds != nil {
				for _, pid := range *rem.ProductIds {
					r.ProductIDs = append(r.ProductIDs, string(*pid))
				}
			}

			result = append(result, r)
		}
		return result
	}

	return nil
}

func (m *Manager) buildPlatformFixedIn(
	remediations []csafutil.Remediation,
	productInfos []productInfo,
	advisoryID string,
) map[string][]vulnerability.FixedIn {
	result := make(map[string][]vulnerability.FixedIn)

	productIDToInfo := make(map[string]productInfo)
	for _, pi := range productInfos {
		productIDToInfo[pi.cpe] = pi
		productIDToInfo[pi.platform] = pi
	}

	productIDToPURL := make(map[string]string)
	for _, pi := range productInfos {
		if pi.cpe != "" {
			productIDToPURL[pi.cpe] = pi.name + "-" + pi.version
		}
	}

	seenPackages := make(map[string]bool)

	for _, rem := range remediations {
		for _, fpi := range rem.ProductIDs {
			parts := strings.SplitN(fpi, ":", 2)
			if len(parts) < 2 {
				continue
			}

			platformPrefix := parts[0]
			rest := parts[1]

			platform := parsePlatformFromPrefix(platformPrefix)
			if platform == "" {
				continue
			}

			ns := "rhel:" + platform
			if m.skipNamespaces[ns] {
				continue
			}

			name, version, module := m.parseFullProductID(rest, fpi, productInfos)

			if name == "" {
				continue
			}

			key := ns + ":" + name + ":" + module
			if seenPackages[key] {
				continue
			}
			seenPackages[key] = true

			fi := vulnerability.NewFixedIn(name, ns, "rpm", version)
			if module != "" {
				fi.Module = module
			}
			if advisoryID != "" {
				fi.VendorAdvisory = &vulnerability.VendorAdvisory{
					NoAdvisory:      false,
					AdvisorySummary: []vulnerability.AdvisorySummary{{ID: advisoryID, Link: rhelURLPrefix + advisoryID}},
				}
			}

			result[ns] = append(result[ns], fi)
		}
	}

	return result
}

func (m *Manager) parseFullProductID(rest, fpi string, productInfos []productInfo) (string, string, string) {
	name, version, module := parsePURLFromFPI(rest, productInfos)
	if name != "" {
		return name, version, module
	}

	parts := strings.SplitN(rest, "-", 2)
	if len(parts) >= 2 {
		pkgParts := strings.SplitN(parts[1], "-", 2)
		if len(pkgParts) >= 1 && pkgParts[0] != "" {
			return pkgParts[0], "", ""
		}
	}

	return "", "", ""
}

func parsePURLFromFPI(rest string, productInfos []productInfo) (string, string, string) {
	for _, pi := range productInfos {
		if strings.Contains(rest, pi.name) && pi.version != "" {
			return pi.name, pi.version, pi.module
		}
	}
	return "", "", ""
}

func (m *Manager) convertScores(scores []csafutil.Score, ns string) []vulnerability.CVSS {
	var result []vulnerability.CVSS

	for _, s := range scores {
		cvss := vulnerability.CVSS{
			Version:      s.Version,
			VectorString: s.Vector,
			BaseMetrics: vulnerability.CVSSBaseMetrics{
				BaseScore:    s.BaseScore,
				BaseSeverity: s.Severity,
			},
		}
		result = append(result, cvss)
	}

	return result
}

func parsePlatformFromCPE(cpe string) string {
	if cpe == "" {
		return ""
	}

	match := rhelReleasePattern.FindStringSubmatch(cpe)
	if match != nil {
		return match[1]
	}

	if idx := strings.Index(cpe, "enterprise_linux:"); idx >= 0 {
		after := cpe[idx+len("enterprise_linux:"):]
		version := strings.SplitN(after, ":", 2)[0]
		if strings.Contains(version, ".") {
			version = strings.SplitN(version, ".", 2)[0]
		}
		if _, err := fmt.Sscanf(version, "%d", new(int)); err == nil {
			return version
		}
	}

	return ""
}

func parsePlatformFromPrefix(prefix string) string {
	patterns := []struct {
		re     *regexp.Regexp
		suffix string
	}{
		{regexp.MustCompile(`AppStream-(\d+)`), ""},
		{regexp.MustCompile(`BaseOS-(\d+)`), ""},
		{regexp.MustCompile(`CRB-(\d+)`), ""},
		{regexp.MustCompile(`PowerTools-(\d+)`), ""},
		{regexp.MustCompile(`HighAvailability-(\d+)`), ""},
		{regexp.MustCompile(`ResilientStorage-(\d+)`), ""},
		{regexp.MustCompile(`NFV-(\d+)`), ""},
		{regexp.MustCompile(`RT-(\d+)`), ""},
		{regexp.MustCompile(`SAP-(\d+)`), ""},
		{regexp.MustCompile(`SAPHANA-(\d+)`), ""},
		{regexp.MustCompile(`(\d+)\.\d+\.\d+\.Z\.MAIN\.EUS`), ""},
		{regexp.MustCompile(`(\d+)\.\d+\.\d+\.Z\.EUS`), ""},
		{regexp.MustCompile(`(\d+)\.\d+\.\d+\.Z`), ""},
	}

	for _, p := range patterns {
		match := p.re.FindStringSubmatch(prefix)
		if match != nil {
			return match[1]
		}
	}

	return ""
}

func NormalizeSeverity(sev string) string {
	if sev == "" {
		return "Unknown"
	}
	switch strings.ToLower(sev) {
	case "critical":
		return "Critical"
	case "important", "high":
		return "High"
	case "moderate", "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Unknown"
	}
}

func ParsePlatformFromProductName(productName string) string {
	if productName == "" {
		return ""
	}

	match := rhelReleasePattern.FindStringSubmatch(productName)
	if match != nil {
		return match[1]
	}

	match = rhelEUSPattern.FindStringSubmatch(productName)
	if match != nil {
		return match[1]
	}

	match = rhelELSPattern.FindStringSubmatch(productName)
	if match != nil {
		return match[1]
	}

	return ""
}

func parsePURL(purlStr string) (name, version, module string) {
	if purlStr == "" {
		return "", "", ""
	}

	purlStr = strings.TrimPrefix(purlStr, "pkg:rpm/")
	purlStr = strings.TrimPrefix(purlStr, "pkg:rpmmod/")

	parts := strings.SplitN(purlStr, "@", 2)
	if len(parts) < 2 {
		if len(parts) == 1 {
			nameParts := strings.SplitN(parts[0], "/", 2)
			if len(nameParts) > 1 {
				name = nameParts[1]
			} else {
				name = nameParts[0]
			}
		}
		return name, "", ""
	}

	namePart := parts[0]
	nameParts := strings.SplitN(namePart, "/", 2)
	if len(nameParts) > 1 {
		name = nameParts[1]
	} else {
		name = nameParts[0]
	}

	version = parts[1]

	if idx := strings.Index(version, "?"); idx >= 0 {
		qualifiers := version[idx+1:]
		version = version[:idx]

		for _, q := range strings.Split(qualifiers, "&") {
			qParts := strings.SplitN(q, "=", 2)
			if len(qParts) == 2 {
				switch qParts[0] {
				case "epoch":
					if qParts[1] != "0" {
						version = qParts[1] + ":" + version
					}
				case "rpmmod":
					modParts := strings.SplitN(qParts[1], ":", 3)
					if len(modParts) >= 2 {
						module = modParts[0] + ":" + modParts[1]
					}
				}
			}
		}
	}

	return name, version, module
}
