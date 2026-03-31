package rhel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/shift/vulnz/internal/utils/archive"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

type CSAFDownloader struct {
	advisoriesPath string
	workspacePath  string
	client         *http.Client
	userAgent      string
}

func NewCSAFDownloader(advisoriesPath, workspacePath string, client *http.Client, userAgent string) *CSAFDownloader {
	return &CSAFDownloader{
		advisoriesPath: advisoriesPath,
		workspacePath:  workspacePath,
		client:         client,
		userAgent:      userAgent,
	}
}

type CSAFRecord struct {
	CVEs        []string
	Severity    string
	AdvisoryID  string
	AdvisoryURL string
	Description string
	FixedIn     []CSAFFixInfo
	CVSS        []vulnerability.CVSS
}

type CSAFFixInfo struct {
	PackageName string
	Namespace   string
	Version     string
	Module      string
	AdvisoryID  string
	AdvisoryURL string
}

func (d *CSAFDownloader) DownloadArchive(ctx context.Context) ([]string, error) {
	var urls []string

	if err := os.MkdirAll(d.advisoriesPath, 0755); err != nil {
		return nil, fmt.Errorf("create advisories directory: %w", err)
	}

	latestURL := advisoriesBaseURL + "archive_latest.txt"

	resp, err := d.httpGet(ctx, latestURL)
	if err != nil {
		return nil, fmt.Errorf("fetch latest archive name: %w", err)
	}
	urls = append(urls, latestURL)

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read latest archive name: %w", err)
	}

	latestName := strings.TrimSpace(string(body))
	archiveURL := advisoriesBaseURL + latestName
	urls = append(urls, archiveURL)

	archiveFilename := filepath.Base(archiveURL)
	localArchivePath := filepath.Join(d.workspacePath, archiveFilename)

	if _, err := os.Stat(localArchivePath); os.IsNotExist(err) {
		entries, err := os.ReadDir(d.workspacePath)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasPrefix(entry.Name(), "csaf_advisories_") && strings.HasSuffix(entry.Name(), ".tar.zst") {
					os.Remove(filepath.Join(d.workspacePath, entry.Name()))
				}
			}
		}

		if err := d.downloadFile(ctx, archiveURL, localArchivePath); err != nil {
			return nil, fmt.Errorf("download archive %s: %w", archiveURL, err)
		}

		if err := archive.Extract(ctx, localArchivePath, d.advisoriesPath); err != nil {
			return nil, fmt.Errorf("extract archive: %w", err)
		}
	}

	changesURL := advisoriesBaseURL + "changes.csv"
	deletionsURL := advisoriesBaseURL + "deletions.csv"
	urls = append(urls, changesURL, deletionsURL)

	return urls, nil
}

func (d *CSAFDownloader) ProcessChanges(ctx context.Context, archiveDate string) error {
	changesPath := filepath.Join(d.workspacePath, "changes.csv")
	deletionsPath := filepath.Join(d.workspacePath, "deletions.csv")

	if err := d.downloadFile(ctx, advisoriesBaseURL+"changes.csv", changesPath); err != nil {
		return fmt.Errorf("download changes.csv: %w", err)
	}
	if err := d.downloadFile(ctx, advisoriesBaseURL+"deletions.csv", deletionsPath); err != nil {
		return fmt.Errorf("download deletions.csv: %w", err)
	}

	deletionsData, err := os.ReadFile(deletionsPath)
	if err == nil {
		for _, line := range strings.Split(string(deletionsData), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fragment := strings.Trim(line, "\"")
			target := filepath.Join(d.advisoriesPath, fragment)
			os.Remove(target)
		}
	}

	changesData, err := os.ReadFile(changesPath)
	if err != nil {
		return nil
	}

	seenFiles := make(map[string]bool)
	years := make(map[string]bool)

	for _, line := range strings.Split(string(changesData), "\n") {
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

		if archiveDate != "" && strings.Compare(dateStr, archiveDate) < 0 {
			break
		}

		seenFiles[changedFile] = true
		yearPart := strings.SplitN(changedFile, "/", 2)
		if len(yearPart) > 0 {
			years[yearPart[0]] = true
		}
	}

	for year := range years {
		os.MkdirAll(filepath.Join(d.advisoriesPath, year), 0755)
	}

	for file := range seenFiles {
		url := advisoriesBaseURL + file
		path := filepath.Join(d.advisoriesPath, file)
		if err := d.downloadFile(ctx, url, path); err != nil {
			continue
		}
	}

	return nil
}

func (d *CSAFDownloader) ParseDirectory(ctx context.Context) ([]CSAFRecord, error) {
	var records []CSAFRecord

	yearDirs, err := os.ReadDir(d.advisoriesPath)
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

		yearPath := filepath.Join(d.advisoriesPath, yearDir.Name())
		files, err := os.ReadDir(yearPath)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			filePath := filepath.Join(yearPath, file.Name())
			record, err := d.parseCSAFFile(filePath)
			if err != nil {
				continue
			}

			records = append(records, record...)
		}
	}

	return records, nil
}

func (d *CSAFDownloader) parseCSAFFile(path string) ([]CSAFRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc csaf.Advisory
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	return d.documentToRecords(&doc), nil
}

func (d *CSAFDownloader) documentToRecords(doc *csaf.Advisory) []CSAFRecord {
	if doc.Document == nil || doc.Document.Tracking == nil || doc.Document.Tracking.ID == nil {
		return nil
	}

	advisoryID := string(*doc.Document.Tracking.ID)
	advisoryURL := "https://access.redhat.com/errata/" + advisoryID

	severity := "Unknown"
	if doc.Document.AggregateSeverity != nil && doc.Document.AggregateSeverity.Text != nil {
		severity = NormalizeSeverity(string(*doc.Document.AggregateSeverity.Text))
	}

	description := ""
	if doc.Document.Notes != nil {
		for _, note := range doc.Document.Notes {
			if note.NoteCategory != nil && string(*note.NoteCategory) == "summary" && note.Text != nil {
				description = *note.Text
				break
			}
		}
	}

	var cveIDs []string
	if doc.Vulnerabilities != nil {
		seen := make(map[string]bool)
		for _, vuln := range doc.Vulnerabilities {
			if vuln.CVE != nil && *vuln.CVE != "" {
				cve := string(*vuln.CVE)
				if !seen[cve] {
					seen[cve] = true
					cveIDs = append(cveIDs, cve)
				}
			}
		}
	}

	if len(cveIDs) == 0 {
		return nil
	}

	productMap := d.extractProducts(doc)

	var records []CSAFRecord

	for _, cveID := range cveIDs {
		var vulnCVSS []vulnerability.CVSS
		var fixInfos []CSAFFixInfo

		if doc.Vulnerabilities != nil {
			for _, vuln := range doc.Vulnerabilities {
				if vuln.CVE == nil || string(*vuln.CVE) != cveID {
					continue
				}

				if vuln.Scores != nil {
					for _, scoreSet := range vuln.Scores {
						if scoreSet.CVSS3 != nil && scoreSet.CVSS3.BaseScore != nil && scoreSet.CVSS3.VectorString != nil {
							sev := "Unknown"
							if scoreSet.CVSS3.BaseSeverity != nil {
								sev = string(*scoreSet.CVSS3.BaseSeverity)
							}
							vulnCVSS = append(vulnCVSS, vulnerability.CVSS{
								Version:      "3.1",
								VectorString: string(*scoreSet.CVSS3.VectorString),
								BaseMetrics: vulnerability.CVSSBaseMetrics{
									BaseScore:    float64(*scoreSet.CVSS3.BaseScore),
									BaseSeverity: sev,
								},
							})
						}
						if scoreSet.CVSS2 != nil && scoreSet.CVSS2.BaseScore != nil && scoreSet.CVSS2.VectorString != nil {
							vulnCVSS = append(vulnCVSS, vulnerability.CVSS{
								Version:      "2.0",
								VectorString: string(*scoreSet.CVSS2.VectorString),
								BaseMetrics: vulnerability.CVSSBaseMetrics{
									BaseScore:    float64(*scoreSet.CVSS2.BaseScore),
									BaseSeverity: "Unknown",
								},
							})
						}
					}
				}

				if vuln.Remediations != nil {
					for _, rem := range vuln.Remediations {
						if rem.Category == nil {
							continue
						}
						cat := string(*rem.Category)
						if cat != "vendor_fix" && cat != "package_fix" {
							continue
						}

						if rem.ProductIds != nil {
							for _, pid := range *rem.ProductIds {
								pidStr := string(*pid)
								if pInfo, ok := productMap[pidStr]; ok {
									fixInfos = append(fixInfos, CSAFFixInfo{
										PackageName: pInfo.name,
										Namespace:   pInfo.namespace,
										Version:     pInfo.version,
										Module:      pInfo.module,
										AdvisoryID:  advisoryID,
										AdvisoryURL: advisoryURL,
									})
								}
							}
						}
					}
				}
			}
		}

		nsFixes := groupFixesByNamespace(fixInfos)
		for _, fixes := range nsFixes {
			records = append(records, CSAFRecord{
				CVEs:        []string{cveID},
				Severity:    severity,
				AdvisoryID:  advisoryID,
				AdvisoryURL: advisoryURL,
				Description: description,
				FixedIn:     fixes,
				CVSS:        vulnCVSS,
			})
		}
	}

	return records
}

type extractedProduct struct {
	name      string
	namespace string
	version   string
	module    string
}

type branchProduct struct {
	pid    string
	cpe    string
	purl   string
	parent string
}

func (d *CSAFDownloader) extractProducts(doc *csaf.Advisory) map[string]extractedProduct {
	result := make(map[string]extractedProduct)
	if doc.ProductTree == nil {
		return result
	}

	var branchProducts []branchProduct

	if doc.ProductTree.Branches != nil {
		collectBranchProducts(doc.ProductTree.Branches, "", &branchProducts)
	}

	pidToProduct := make(map[string]branchProduct)
	for _, bp := range branchProducts {
		pidToProduct[bp.pid] = bp
	}

	if doc.ProductTree.FullProductNames != nil {
		for _, fpn := range *doc.ProductTree.FullProductNames {
			if fpn.ProductID == nil {
				continue
			}
			pid := string(*fpn.ProductID)

			cpe := ""
			purl := ""
			matchedParentPID := ""

			if bp, ok := pidToProduct[pid]; ok {
				cpe = bp.cpe
				purl = bp.purl
				matchedParentPID = bp.parent
			}

			if cpe == "" || purl == "" {
				for _, bp := range branchProducts {
					if strings.Contains(pid, bp.pid) {
						if cpe == "" {
							cpe = bp.cpe
						}
						if purl == "" {
							purl = bp.purl
						}
						if matchedParentPID == "" {
							matchedParentPID = bp.parent
						}
						if cpe != "" && purl != "" {
							break
						}
					}
				}
			}

			if (cpe == "" || purl == "") && matchedParentPID != "" {
				if parentBP, ok := pidToProduct[matchedParentPID]; ok {
					if cpe == "" {
						cpe = parentBP.cpe
					}
					if purl == "" {
						purl = parentBP.purl
					}
				}
			}

			platform := parsePlatformFromCPE(cpe)
			if platform == "" {
				if fpn.Name != nil {
					platform = ParsePlatformFromProductName(*fpn.Name)
				}
			}
			if platform == "" {
				continue
			}

			name, version, module := parsePURL(purl)
			if name == "" && fpn.Name != nil {
				name = extractNameFromFullProductID(*fpn.Name)
			}
			ns := "rhel:" + platform

			result[pid] = extractedProduct{
				name:      name,
				namespace: ns,
				version:   version,
				module:    module,
			}
		}
	}

	return result
}

func collectBranchProducts(branches csaf.Branches, parentPID string, products *[]branchProduct) {
	for _, branch := range branches {
		if branch.Product != nil && branch.Product.ProductID != nil {
			pid := string(*branch.Product.ProductID)
			cpe := ""
			purl := ""
			if branch.Product.ProductIdentificationHelper != nil {
				if branch.Product.ProductIdentificationHelper.CPE != nil {
					cpe = string(*branch.Product.ProductIdentificationHelper.CPE)
				}
				if branch.Product.ProductIdentificationHelper.PURL != nil {
					purl = string(*branch.Product.ProductIdentificationHelper.PURL)
				}
			}
			*products = append(*products, branchProduct{pid: pid, cpe: cpe, purl: purl, parent: parentPID})
			if branch.Branches != nil {
				collectBranchProducts(branch.Branches, pid, products)
			}
		} else if branch.Branches != nil {
			collectBranchProducts(branch.Branches, parentPID, products)
		}
	}
}

func extractNameFromFullProductID(name string) string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) > 1 {
		rest := parts[1]
		dashParts := strings.SplitN(rest, "-", 2)
		if len(dashParts) > 0 && dashParts[0] != "" {
			return dashParts[0]
		}
	}
	return ""
}

func groupFixesByNamespace(fixes []CSAFFixInfo) map[string][]CSAFFixInfo {
	result := make(map[string][]CSAFFixInfo)
	for _, fix := range fixes {
		result[fix.Namespace] = append(result[fix.Namespace], fix)
	}
	return result
}

func (d *CSAFDownloader) httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", d.userAgent)
	return d.client.Do(req)
}

func (d *CSAFDownloader) downloadFile(ctx context.Context, url, dest string) error {
	resp, err := d.httpGet(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func RecordsToVulnerabilities(records []CSAFRecord) []vulnerability.Vulnerability {
	var vulns []vulnerability.Vulnerability

	for _, record := range records {
		for _, cveID := range record.CVEs {
			var fixedIn []vulnerability.FixedIn
			for _, fix := range record.FixedIn {
				fi := vulnerability.NewFixedIn(fix.PackageName, fix.Namespace, "rpm", fix.Version)
				if fix.Module != "" {
					fi.Module = fix.Module
				}
				if fix.AdvisoryID != "" {
					fi.VendorAdvisory = &vulnerability.VendorAdvisory{
						NoAdvisory:      false,
						AdvisorySummary: []vulnerability.AdvisorySummary{{ID: fix.AdvisoryID, Link: fix.AdvisoryURL}},
					}
				}
				fixedIn = append(fixedIn, fi)
			}

			cvss := record.CVSS
			if cvss == nil {
				cvss = []vulnerability.CVSS{}
			}

			vulns = append(vulns, vulnerability.Vulnerability{
				Name:          cveID,
				NamespaceName: record.FixedIn[0].Namespace,
				Description:   record.Description,
				Severity:      record.Severity,
				Link:          record.AdvisoryURL,
				CVSS:          cvss,
				FixedIn:       fixedIn,
				Metadata:      map[string]any{},
			})
		}
	}

	return vulns
}
