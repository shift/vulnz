package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	MetadataFilename = "metadata.json"
	ChecksumFilename = "checksums"
	InputDir = "input"
	ResultsDir = "results"
)


// Workspace defines the interface for workspace operations.
type Workspace interface {
	Initialize(providerName string) error
	GetState(providerName string) (*State, error)
	UpdateState(providerName string, state *State) error
	GetPath(providerName string) string
	GetInputPath(providerName string) string
	GetResultsPath(providerName string) string
	GetMetadataPath(providerName string) string
	GetChecksumPath(providerName string) string
	Clear(providerName string) error
	ClearInput(providerName string) error
	ClearResults(providerName string) error
	Exists(providerName string) bool
	HasState(providerName string) bool
	ListProviders() ([]string, error)
}

type manager struct {
	root string
}

func NewManager(root string) Workspace {
	return &manager{root: root}
}

func (m *manager) Initialize(providerName string) error {
	dirs := []string{
		m.GetInputPath(providerName),
		m.GetResultsPath(providerName),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

func (m *manager) GetState(providerName string) (*State, error) {
	metadataPath := filepath.Join(m.GetPath(providerName), MetadataFilename)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	return &state, nil
}

func (m *manager) UpdateState(providerName string, state *State) error {
	workspacePath := m.GetPath(providerName)
	metadataPath := filepath.Join(workspacePath, MetadataFilename)
	tempPath := metadataPath + ".tmp"
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tempPath, metadataPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func (m *manager) GetPath(providerName string) string {
	return filepath.Join(m.root, providerName)
}

func (m *manager) GetInputPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), InputDir)
}

func (m *manager) GetResultsPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), ResultsDir)
}

func (m *manager) GetMetadataPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), MetadataFilename)
}

func (m *manager) GetChecksumPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), ChecksumFilename)
}

func (m *manager) Clear(providerName string) error {
	workspacePath := m.GetPath(providerName)
	if err := os.RemoveAll(workspacePath); err != nil {
		return fmt.Errorf("remove workspace: %w", err)
	}
	return nil
}

func (m *manager) ClearInput(providerName string) error {
	inputPath := m.GetInputPath(providerName)
	if err := os.RemoveAll(inputPath); err != nil {
		return fmt.Errorf("remove input: %w", err)
	}
	return os.MkdirAll(inputPath, 0755)
}

func (m *manager) ClearResults(providerName string) error {
	resultsPath := m.GetResultsPath(providerName)
	if err := os.RemoveAll(resultsPath); err != nil {
		return fmt.Errorf("remove results: %w", err)
	}
	return os.MkdirAll(resultsPath, 0755)
}

func (m *manager) Exists(providerName string) bool {
	workspacePath := m.GetPath(providerName)
	info, err := os.Stat(workspacePath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func (m *manager) HasState(providerName string) bool {
	metadataPath := m.GetMetadataPath(providerName)
	info, err := os.Stat(metadataPath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func (m *manager) ListProviders() ([]string, error) {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read workspace root: %w", err)
	}
	var providers []string
	for _, entry := range entries {
		if entry.IsDir() {
			providers = append(providers, entry.Name())
		}
	}
	return providers, nil
}
