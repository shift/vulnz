package ubuntu

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

type Manager struct {
	config   provider.Config
	git      *GitManager
	logger   *slog.Logger
	versions map[string]string
}

func NewManager(config provider.Config) *Manager {
	versions := make(map[string]string)
	for k, v := range ubuntuReleases {
		versions[k] = v
	}

	return &Manager{
		config:   config,
		git:      NewGitManager(config.Workspace, "", "", config.Logger),
		logger:   config.Logger,
		versions: versions,
	}
}

func (m *Manager) URLs() []string {
	return []string{m.git.URL()}
}

func (m *Manager) Get(ctx context.Context) ([]vulnerability.Vulnerability, error) {
	if err := m.git.EnsureRepo(ctx); err != nil {
		return nil, fmt.Errorf("ensure git repo: %w", err)
	}

	repoPath := m.git.RepoPath()
	var allVulns []vulnerability.Vulnerability

	for _, dir := range []string{"active", "retired"} {
		cveDir := filepath.Join(repoPath, dir)
		entries, err := os.ReadDir(cveDir)
		if err != nil {
			if os.IsNotExist(err) {
				m.logger.Warn("CVE directory does not exist", "dir", cveDir)
				continue
			}
			return nil, fmt.Errorf("read CVE directory %s: %w", dir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !cveFilenameRegex.MatchString(name) {
				continue
			}

			filePath := filepath.Join(cveDir, name)
			content, err := os.ReadFile(filePath)
			if err != nil {
				m.logger.Warn("failed to read CVE file", "file", filePath, "error", err)
				continue
			}

			cveFile := parseCVEFile(name, string(content))
			vulns := MapParsed(cveFile, m.logger)
			allVulns = append(allVulns, vulns...)
		}
	}

	return allVulns, nil
}

func MapParsed(cveFile CVEFile, logger *slog.Logger) []vulnerability.Vulnerability {
	if cveFile.Name == "" {
		logger.Error("could not find a Name for parsed CVE")
		return nil
	}

	vulns := make(map[string]*vulnerability.Vulnerability)

	for _, p := range cveFile.Patches {
		namespaceName := mapNamespace(p.Distro)
		if namespaceName == "" {
			continue
		}

		r, ok := vulns[namespaceName]
		if !ok {
			r = &vulnerability.Vulnerability{
				Name:          cveFile.Name,
				NamespaceName: namespaceName,
				Description:   cveFile.Description,
				Severity:      mapSeverity(cveFile.Priority),
				Link:          fmt.Sprintf("https://ubuntu.com/security/cves/%s", cveFile.Name),
				FixedIn:       []vulnerability.FixedIn{},
				CVSS:          []vulnerability.CVSS{},
				Metadata:      map[string]any{},
			}
			vulns[namespaceName] = r
		}

		if !checkState(p.Status) {
			continue
		}

		pkg := vulnerability.NewFixedIn(p.Package, namespaceName, "dpkg", "")

		if p.Status == "released" {
			pkg.Version = p.Version
			if pkg.Version == "" {
				logger.Debug("released status with no version", "cve", r.Name, "namespace", namespaceName, "package", p.Package)
				continue
			}
		} else {
			pkg.Version = "None"
			if p.Status == "ignored" {
				pkg.VendorAdvisory = &vulnerability.VendorAdvisory{
					NoAdvisory:      true,
					AdvisorySummary: []vulnerability.AdvisorySummary{},
				}
			}
		}

		if pkg.VendorAdvisory == nil {
			pkg.VendorAdvisory = &vulnerability.VendorAdvisory{
				NoAdvisory:      false,
				AdvisorySummary: []vulnerability.AdvisorySummary{},
			}
		}

		r.FixedIn = append(r.FixedIn, pkg)

		if p.Priority != "" {
			pkgSev := mapSeverity(p.Priority)
			if vulnerability.CompareSeverity(pkgSev, r.Severity) > 0 {
				r.Severity = pkgSev
			}
		}
	}

	result := make([]vulnerability.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		result = append(result, *v)
	}
	return result
}

func ParseCVEFilesFromDir(dir string, logger *slog.Logger) ([]vulnerability.Vulnerability, error) {
	var allVulns []vulnerability.Vulnerability

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDir := filepath.Join(dir, entry.Name())
			subVulns, err := ParseCVEFilesFromDir(subDir, logger)
			if err != nil {
				return nil, err
			}
			allVulns = append(allVulns, subVulns...)
			continue
		}

		name := entry.Name()
		if !cveFilenameRegex.MatchString(name) {
			continue
		}

		filePath := filepath.Join(dir, name)
		content, err := os.ReadFile(filePath)
		if err != nil {
			logger.Warn("failed to read CVE file", "file", filePath, "error", err)
			continue
		}

		cveFile := parseCVEFile(name, string(content))
		vulns := MapParsed(cveFile, logger)
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func IsCVEFile(name string) bool {
	return cveFilenameRegex.MatchString(name)
}

func NormalizeNamespace(ns string) string {
	return strings.ToLower(ns)
}
