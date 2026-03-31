package workspace_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/shift/vulnz/internal/workspace"
)

// Example_basicUsage demonstrates the basic workspace management operations.
func Example_basicUsage() {
	// Create workspace manager
	manager := workspace.NewManager("./data")

	// Initialize provider workspace
	providerName := "alpine"
	if err := manager.Initialize(providerName); err != nil {
		log.Fatal(err)
	}

	// Get paths
	fmt.Println("Workspace path:", manager.GetPath(providerName))
	fmt.Println("Input path:", manager.GetInputPath(providerName))
	fmt.Println("Results path:", manager.GetResultsPath(providerName))

	// Create and save state
	state := &workspace.State{
		Provider:            providerName,
		URLs:                []string{"https://secdb.alpinelinux.org/v3.19/main.json"},
		Store:               "sqlite",
		Timestamp:           time.Now(),
		Version:             1,
		DistributionVersion: 1,
		Processor:           "vulnz-go@1.0.0",
	}

	if err := manager.UpdateState(providerName, state); err != nil {
		log.Fatal(err)
	}

	// Read state back
	readState, err := manager.GetState(providerName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Provider:", readState.Provider)
	fmt.Println("Store:", readState.Store)
	fmt.Println("Version:", readState.Version)

	// Clean up
	manager.Clear(providerName)
}

// Example_checksums demonstrates checksum operations.
func Example_checksums() {
	tmpDir, err := os.MkdirTemp("", "workspace-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.json")
	content := []byte(`{"id": "CVE-2023-1234", "severity": "high"}`)
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		log.Fatal(err)
	}

	// Compute checksum
	checksum, err := workspace.ComputeChecksum(testFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Checksum: %s\n", checksum)

	// Verify checksum
	valid, err := workspace.VerifyChecksum(testFile, checksum)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Valid: %v\n", valid)

	// Create checksums file
	checksums := &workspace.ChecksumFile{
		Files: map[string]string{
			"results/CVE-2023-1234.json": checksum,
			"results/CVE-2023-5678.json": "abcdef0123456789",
		},
	}

	checksumsPath := filepath.Join(tmpDir, "checksums")
	if err := workspace.WriteChecksums(checksumsPath, checksums); err != nil {
		log.Fatal(err)
	}

	// Read checksums back
	readChecksums, err := workspace.ReadChecksums(checksumsPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Checksums count: %d\n", len(readChecksums.Files))
}

// Example_locking demonstrates workspace locking for concurrent access.
func Example_locking() {
	locker := workspace.NewLocker()
	providerName := "alpine"

	// Lock workspace before modifications
	locker.Lock(providerName)
	defer locker.Unlock(providerName)

	fmt.Println("Workspace locked, performing operations...")

	// Try to lock again (would block if called from another goroutine)
	if locker.TryLock(providerName) {
		fmt.Println("Lock acquired")
		locker.Unlock(providerName)
	} else {
		fmt.Println("Lock already held")
	}

	// Output:
	// Workspace locked, performing operations...
	// Lock already held
}

// Example_multipleProviders demonstrates managing multiple provider workspaces.
func Example_multipleProviders() {
	tmpDir, err := os.MkdirTemp("", "workspace-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	manager := workspace.NewManager(tmpDir)

	// Initialize multiple providers
	providers := []string{"alpine", "ubuntu", "debian"}
	for _, provider := range providers {
		if err := manager.Initialize(provider); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Initialized workspace: %s\n", provider)
	}

	// List all providers
	allProviders, err := manager.ListProviders()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Total providers: %d\n", len(allProviders))

	// Output:
	// Initialized workspace: alpine
	// Initialized workspace: ubuntu
	// Initialized workspace: debian
	// Total providers: 3
}

// Example_clearOperations demonstrates selective clearing operations.
func Example_clearOperations() {
	tmpDir, err := os.MkdirTemp("", "workspace-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	manager := workspace.NewManager(tmpDir)
	providerName := "alpine"

	// Initialize workspace
	if err := manager.Initialize(providerName); err != nil {
		log.Fatal(err)
	}

	// Create test files
	inputFile := filepath.Join(manager.GetInputPath(providerName), "input.json")
	resultsFile := filepath.Join(manager.GetResultsPath(providerName), "result.json")

	os.WriteFile(inputFile, []byte("input data"), 0644)
	os.WriteFile(resultsFile, []byte("result data"), 0644)

	// Clear only input
	if err := manager.ClearInput(providerName); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Input cleared")

	// Results still exist
	if _, err := os.Stat(resultsFile); err == nil {
		fmt.Println("Results still exist")
	}

	// Clear only results
	if err := manager.ClearResults(providerName); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Results cleared")

	// Clear entire workspace
	if err := manager.Clear(providerName); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Workspace cleared")

	// Output:
	// Input cleared
	// Results still exist
	// Results cleared
	// Workspace cleared
}
