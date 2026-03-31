package alma

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/vulnz/internal/provider"
	"github.com/go-git/go-git/v5"
)

type Manager struct {
	config   provider.Config
	versions []int
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithVersions(config, defaultVersions)
}

func NewManagerWithVersions(config provider.Config, versions []int) *Manager {
	return &Manager{
		config:   config,
		versions: versions,
	}
}

func (m *Manager) URLs() []string {
	return []string{DefaultRepoURL}
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	repoDir := filepath.Join(m.config.Workspace, "input", "osv-database")

	if err := m.cloneRepo(ctx, repoDir); err != nil {
		return nil, fmt.Errorf("clone repository: %w", err)
	}

	return m.WalkAdvisories(ctx, repoDir)
}

func (m *Manager) cloneRepo(ctx context.Context, destDir string) error {
	if _, err := os.Stat(destDir); err == nil {
		return nil
	}

	inputDir := filepath.Dir(destDir)
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return fmt.Errorf("create input directory: %w", err)
	}

	_, err := git.PlainCloneContext(ctx, destDir, false, &git.CloneOptions{
		URL:          DefaultRepoURL,
		SingleBranch: true,
		Depth:        1,
	})
	if err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	return nil
}

func (m *Manager) WalkAdvisories(ctx context.Context, repoDir string) (map[string]map[string]interface{}, error) {
	advisoriesDir := filepath.Join(repoDir, "advisories")

	result := make(map[string]map[string]interface{})

	for _, ver := range m.versions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		versionDir := filepath.Join(advisoriesDir, fmt.Sprintf("almalinux%d", ver))
		if _, err := os.Stat(versionDir); os.IsNotExist(err) {
			continue
		}

		err := filepath.WalkDir(versionDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".json") {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}

			var advisory map[string]interface{}
			if err := json.Unmarshal(data, &advisory); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}

			id, ok := advisory["id"].(string)
			if !ok || id == "" {
				return nil
			}

			normalized := m.normalizeAdvisory(advisory, ver)

			identifier := fmt.Sprintf("alma:%d/%s", ver, strings.ToLower(id))
			result[identifier] = normalized

			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("walk almalinux%d advisories: %w", ver, err)
		}
	}

	return result, nil
}

func (m *Manager) normalizeAdvisory(advisory map[string]interface{}, version int) map[string]interface{} {
	normalized := make(map[string]interface{})

	for k, v := range advisory {
		normalized[k] = v
	}

	if affected, ok := advisory["affected"].([]interface{}); ok {
		normalizedAffected := make([]interface{}, len(affected))
		for i, a := range affected {
			if aff, ok := a.(map[string]interface{}); ok {
				normalizedAffected[i] = m.normalizeAffected(aff)
			} else {
				normalizedAffected[i] = a
			}
		}
		normalized["affected"] = normalizedAffected
	}

	normalized["namespace"] = fmt.Sprintf("alma:%d", version)
	normalized["metadata"] = map[string]interface{}{
		"source":   "almalinux-osv",
		"distro":   "alma",
		"version":  version,
		"format":   "osv",
		"upstream": DefaultRepoURL,
	}

	return normalized
}

func (m *Manager) normalizeAffected(aff map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range aff {
		result[k] = v
	}

	if pkg, ok := aff["package"].(map[string]interface{}); ok {
		normalizedPkg := make(map[string]interface{})
		for k, v := range pkg {
			if k == "ecosystem" {
				if eco, ok := v.(string); ok {
					normalizedPkg[k] = NormalizeEcosystem(eco)
				} else {
					normalizedPkg[k] = v
				}
			} else {
				normalizedPkg[k] = v
			}
		}
		result["package"] = normalizedPkg
	}

	return result
}

func NormalizeEcosystem(ecosystem string) string {
	return strings.ReplaceAll(strings.ToLower(ecosystem), "almalinux", "alma")
}
