package bitnami

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/shift/vulnz/internal/provider"
)

type Manager struct {
	repoURL string
	config  provider.Config
}

func NewManager(repoURL string, config provider.Config) *Manager {
	return &Manager{
		repoURL: repoURL,
		config:  config,
	}
}

func (m *Manager) CloneRepo(ctx context.Context) error {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return fmt.Errorf("create input directory: %w", err)
	}

	destDir := filepath.Join(inputDir, "vulndb")

	if _, err := os.Stat(destDir); err == nil {
		m.config.Logger.Info("vulndb already cloned, skipping")
		return nil
	}

	m.config.Logger.Info("cloning bitnami vulndb", "url", m.repoURL, "dest", destDir)

	_, err := git.PlainCloneContext(ctx, destDir, false, &git.CloneOptions{
		URL:          m.repoURL,
		SingleBranch: true,
		Depth:        1,
	})
	if err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	return nil
}

func (m *Manager) WalkAdvisories() (map[string]map[string]interface{}, error) {
	dataDir := filepath.Join(m.config.Workspace, "input", "vulndb", "data")

	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("data directory not found: %s", dataDir)
	}

	result := make(map[string]map[string]interface{})

	err := filepath.WalkDir(dataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		advisoryID, ok := raw["id"].(string)
		if !ok || advisoryID == "" {
			return nil
		}

		result[advisoryID] = raw
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	if err := m.CloneRepo(ctx); err != nil {
		return nil, fmt.Errorf("clone repo: %w", err)
	}

	return m.WalkAdvisories()
}
