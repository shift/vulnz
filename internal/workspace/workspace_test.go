package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManager_Initialize(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)

	providerName := "test-provider"

	// Initialize workspace
	err := manager.Initialize(providerName)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify directories were created
	dirs := []string{
		manager.GetPath(providerName),
		manager.GetInputPath(providerName),
		manager.GetResultsPath(providerName),
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Directory %s not created: %v", dir, err)
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}

	// Initialize again should be safe (idempotent)
	err = manager.Initialize(providerName)
	if err != nil {
		t.Errorf("Second Initialize failed: %v", err)
	}
}

func TestManager_GetPaths(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "alpine"

	tests := []struct {
		name     string
		getPath  func() string
		expected string
	}{
		{
			name:     "workspace path",
			getPath:  func() string { return manager.GetPath(providerName) },
			expected: filepath.Join(tmpDir, providerName),
		},
		{
			name:     "input path",
			getPath:  func() string { return manager.GetInputPath(providerName) },
			expected: filepath.Join(tmpDir, providerName, InputDir),
		},
		{
			name:     "results path",
			getPath:  func() string { return manager.GetResultsPath(providerName) },
			expected: filepath.Join(tmpDir, providerName, ResultsDir),
		},
		{
			name:     "metadata path",
			getPath:  func() string { return manager.GetMetadataPath(providerName) },
			expected: filepath.Join(tmpDir, providerName, MetadataFilename),
		},
		{
			name:     "checksum path",
			getPath:  func() string { return manager.GetChecksumPath(providerName) },
			expected: filepath.Join(tmpDir, providerName, ChecksumFilename),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.getPath()
			if actual != tt.expected {
				t.Errorf("got %s, want %s", actual, tt.expected)
			}
		})
	}
}

func TestManager_StateOperations(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "test-provider"

	// Initialize workspace first
	if err := manager.Initialize(providerName); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create a state
	state := &State{
		Provider:            providerName,
		URLs:                []string{"http://example.com/data.json"},
		Store:               "sqlite",
		Timestamp:           time.Now().UTC(),
		Version:             1,
		DistributionVersion: 1,
		Stale:               false,
		Processor:           "vulnz-go@1.0.0",
	}

	// Write state
	err := manager.UpdateState(providerName, state)
	if err != nil {
		t.Fatalf("UpdateState failed: %v", err)
	}

	// Verify state file exists
	if !manager.HasState(providerName) {
		t.Error("HasState returned false after UpdateState")
	}

	// Read state back
	readState, err := manager.GetState(providerName)
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}

	// Verify state fields
	if readState.Provider != state.Provider {
		t.Errorf("Provider mismatch: got %s, want %s", readState.Provider, state.Provider)
	}
	if readState.Store != state.Store {
		t.Errorf("Store mismatch: got %s, want %s", readState.Store, state.Store)
	}
	if len(readState.URLs) != len(state.URLs) {
		t.Errorf("URLs length mismatch: got %d, want %d", len(readState.URLs), len(state.URLs))
	}
	if readState.Version != state.Version {
		t.Errorf("Version mismatch: got %d, want %d", readState.Version, state.Version)
	}
	if readState.Stale != state.Stale {
		t.Errorf("Stale mismatch: got %v, want %v", readState.Stale, state.Stale)
	}
}

func TestManager_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "test-provider"

	// Initialize workspace
	if err := manager.Initialize(providerName); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create some test files
	inputFile := filepath.Join(manager.GetInputPath(providerName), "test.json")
	if err := os.WriteFile(inputFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Verify workspace exists
	if !manager.Exists(providerName) {
		t.Error("Exists returned false for initialized workspace")
	}

	// Clear workspace
	if err := manager.Clear(providerName); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify workspace is gone
	if manager.Exists(providerName) {
		t.Error("Exists returned true after Clear")
	}
}

func TestManager_ClearInput(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "test-provider"

	// Initialize workspace
	if err := manager.Initialize(providerName); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create test files in both input and results
	inputFile := filepath.Join(manager.GetInputPath(providerName), "input.json")
	resultsFile := filepath.Join(manager.GetResultsPath(providerName), "result.json")

	if err := os.WriteFile(inputFile, []byte("input data"), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}
	if err := os.WriteFile(resultsFile, []byte("result data"), 0644); err != nil {
		t.Fatalf("Failed to create results file: %v", err)
	}

	// Clear only input
	if err := manager.ClearInput(providerName); err != nil {
		t.Fatalf("ClearInput failed: %v", err)
	}

	// Verify input is cleared
	if _, err := os.Stat(inputFile); !os.IsNotExist(err) {
		t.Error("Input file still exists after ClearInput")
	}

	// Verify results still exist
	if _, err := os.Stat(resultsFile); err != nil {
		t.Errorf("Results file was deleted: %v", err)
	}

	// Verify input directory was recreated
	if _, err := os.Stat(manager.GetInputPath(providerName)); err != nil {
		t.Errorf("Input directory not recreated: %v", err)
	}
}

func TestManager_ClearResults(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "test-provider"

	// Initialize workspace
	if err := manager.Initialize(providerName); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create test files in both input and results
	inputFile := filepath.Join(manager.GetInputPath(providerName), "input.json")
	resultsFile := filepath.Join(manager.GetResultsPath(providerName), "result.json")

	if err := os.WriteFile(inputFile, []byte("input data"), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}
	if err := os.WriteFile(resultsFile, []byte("result data"), 0644); err != nil {
		t.Fatalf("Failed to create results file: %v", err)
	}

	// Clear only results
	if err := manager.ClearResults(providerName); err != nil {
		t.Fatalf("ClearResults failed: %v", err)
	}

	// Verify results are cleared
	if _, err := os.Stat(resultsFile); !os.IsNotExist(err) {
		t.Error("Results file still exists after ClearResults")
	}

	// Verify input still exists
	if _, err := os.Stat(inputFile); err != nil {
		t.Errorf("Input file was deleted: %v", err)
	}

	// Verify results directory was recreated
	if _, err := os.Stat(manager.GetResultsPath(providerName)); err != nil {
		t.Errorf("Results directory not recreated: %v", err)
	}
}

func TestManager_ListProviders(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)

	// List empty workspace
	providers, err := manager.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("Expected empty list, got %d providers", len(providers))
	}

	// Create some provider workspaces
	providerNames := []string{"alpine", "ubuntu", "debian"}
	for _, name := range providerNames {
		if err := manager.Initialize(name); err != nil {
			t.Fatalf("Initialize %s failed: %v", name, err)
		}
	}

	// List providers
	providers, err = manager.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}

	if len(providers) != len(providerNames) {
		t.Errorf("Expected %d providers, got %d", len(providerNames), len(providers))
	}

	// Verify all providers are in the list
	providerMap := make(map[string]bool)
	for _, p := range providers {
		providerMap[p] = true
	}

	for _, name := range providerNames {
		if !providerMap[name] {
			t.Errorf("Provider %s not in list", name)
		}
	}
}

func TestManager_NonexistentWorkspace(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "nonexistent"

	// Exists should return false
	if manager.Exists(providerName) {
		t.Error("Exists returned true for nonexistent workspace")
	}

	// HasState should return false
	if manager.HasState(providerName) {
		t.Error("HasState returned true for nonexistent workspace")
	}

	// GetState should return error
	_, err := manager.GetState(providerName)
	if err == nil {
		t.Error("GetState should return error for nonexistent workspace")
	}

	// Clear should not error (safe to call)
	if err := manager.Clear(providerName); err != nil && !os.IsNotExist(err) {
		t.Errorf("Clear returned unexpected error: %v", err)
	}
}

func TestManager_StateAtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	manager := NewManager(tmpDir)
	providerName := "test-provider"

	// Initialize workspace
	if err := manager.Initialize(providerName); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	state := &State{
		Provider:  providerName,
		Version:   1,
		Timestamp: time.Now().UTC(),
	}

	// Write state
	if err := manager.UpdateState(providerName, state); err != nil {
		t.Fatalf("UpdateState failed: %v", err)
	}

	// Verify no temp file remains
	tempFile := manager.GetMetadataPath(providerName) + ".tmp"
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Error("Temporary file was not cleaned up")
	}
}
