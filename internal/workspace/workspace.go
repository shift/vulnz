package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// MetadataFilename is the name of the workspace state file
	MetadataFilename = "metadata.json"

	// ChecksumFilename is the name of the checksums listing file
	ChecksumFilename = "checksums"

	// InputDir is the subdirectory for downloaded source data
	InputDir = "input"

	// ResultsDir is the subdirectory for processed results
	ResultsDir = "results"
)

// Manager handles workspace operations for vulnerability data providers.
// Each provider gets its own isolated workspace directory containing:
//   - input/: Downloaded source data
//   - results/: Processed vulnerability records
//   - metadata.json: State tracking
//   - checksums: File integrity listing
type Manager struct {
	root string // Root workspace directory (e.g., "./data")
}

// NewManager creates a new workspace manager with the given root directory.
// The root directory will contain subdirectories for each provider.
func NewManager(root string) *Manager {
	return &Manager{
		root: root,
	}
}

// Initialize creates the workspace directory structure for a provider.
// This creates:
//   - {root}/{providerName}/
//   - {root}/{providerName}/input/
//   - {root}/{providerName}/results/
//
// It is safe to call this multiple times - existing directories are preserved.
func (m *Manager) Initialize(providerName string) error {
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

// GetState reads the provider's state from metadata.json.
// Returns an error if the file doesn't exist or can't be parsed.
func (m *Manager) GetState(providerName string) (*State, error) {
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

// UpdateState writes the provider's state to metadata.json.
// The write is atomic - it writes to a temp file and then renames.
func (m *Manager) UpdateState(providerName string, state *State) error {
	workspacePath := m.GetPath(providerName)
	metadataPath := filepath.Join(workspacePath, MetadataFilename)
	tempPath := metadataPath + ".tmp"

	// Ensure the workspace directory exists
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}

	// Marshal state to JSON with pretty printing
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// Write to temporary file
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, metadataPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// GetPath returns the workspace root path for a provider.
// Example: /data/alpine
func (m *Manager) GetPath(providerName string) string {
	return filepath.Join(m.root, providerName)
}

// GetInputPath returns the input directory path for a provider.
// Example: /data/alpine/input
func (m *Manager) GetInputPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), InputDir)
}

// GetResultsPath returns the results directory path for a provider.
// Example: /data/alpine/results
func (m *Manager) GetResultsPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), ResultsDir)
}

// GetMetadataPath returns the metadata file path for a provider.
// Example: /data/alpine/metadata.json
func (m *Manager) GetMetadataPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), MetadataFilename)
}

// GetChecksumPath returns the checksums file path for a provider.
// Example: /data/alpine/checksums
func (m *Manager) GetChecksumPath(providerName string) string {
	return filepath.Join(m.GetPath(providerName), ChecksumFilename)
}

// Clear removes all workspace data for a provider.
// This deletes the entire provider directory including input, results, and state.
func (m *Manager) Clear(providerName string) error {
	workspacePath := m.GetPath(providerName)
	if err := os.RemoveAll(workspacePath); err != nil {
		return fmt.Errorf("remove workspace: %w", err)
	}
	return nil
}

// ClearInput removes only the input directory for a provider.
// The results and state are preserved.
func (m *Manager) ClearInput(providerName string) error {
	inputPath := m.GetInputPath(providerName)
	if err := os.RemoveAll(inputPath); err != nil {
		return fmt.Errorf("remove input: %w", err)
	}
	return os.MkdirAll(inputPath, 0755)
}

// ClearResults removes only the results directory for a provider.
// The input and state are preserved.
func (m *Manager) ClearResults(providerName string) error {
	resultsPath := m.GetResultsPath(providerName)
	if err := os.RemoveAll(resultsPath); err != nil {
		return fmt.Errorf("remove results: %w", err)
	}
	return os.MkdirAll(resultsPath, 0755)
}

// Exists checks if a workspace exists for the given provider.
// It only checks for the existence of the workspace directory.
func (m *Manager) Exists(providerName string) bool {
	workspacePath := m.GetPath(providerName)
	info, err := os.Stat(workspacePath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// HasState checks if a provider has valid state (metadata.json exists).
func (m *Manager) HasState(providerName string) bool {
	metadataPath := m.GetMetadataPath(providerName)
	info, err := os.Stat(metadataPath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ListProviders returns a list of all provider names that have workspaces.
func (m *Manager) ListProviders() ([]string, error) {
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
