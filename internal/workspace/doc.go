// Package workspace provides workspace management for vulnerability data providers.
//
// # Overview
//
// Each provider gets an isolated workspace directory containing:
//   - input/: Downloaded source data
//   - results/: Processed vulnerability records
//   - metadata.json: State tracking (timestamps, URLs, version)
//   - checksums: File integrity listing using xxHash64
//
// # Workspace Structure
//
// The workspace structure follows this layout:
//
//	data/                          # Root workspace
//	└── {provider-name}/           # Per-provider workspace
//	    ├── metadata.json          # Workspace state
//	    ├── checksums              # File integrity listing (xxHash64)
//	    ├── input/                 # Downloaded source data
//	    │   └── raw-data.json
//	    └── results/               # Processed vulnerabilities
//	        ├── results.db         # SQLite (if using sqlite)
//	        └── {namespace}/       # Flat files (if using flat-file)
//	            └── {vuln-id}.json
//
// # Usage Example
//
//	// Create workspace manager
//	manager := workspace.NewManager("./data")
//
//	// Initialize provider workspace
//	if err := manager.Initialize("alpine"); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get paths
//	inputPath := manager.GetInputPath("alpine")
//	resultsPath := manager.GetResultsPath("alpine")
//
//	// Update state after processing
//	state := &workspace.State{
//	    Provider:  "alpine",
//	    URLs:      []string{"https://secdb.alpinelinux.org/v3.19/main.json"},
//	    Store:     "sqlite",
//	    Timestamp: time.Now(),
//	    Version:   1,
//	}
//	if err := manager.UpdateState("alpine", state); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Read state later
//	state, err := manager.GetState("alpine")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Thread Safety
//
// The Manager type is thread-safe for operations on different providers.
// For concurrent access to the same provider workspace, use the Locker:
//
//	locker := workspace.NewLocker()
//	locker.Lock("alpine")
//	defer locker.Unlock("alpine")
//
//	// Perform workspace operations...
//
// # Checksums
//
// File integrity is tracked using xxHash64 checksums:
//
//	// Compute checksum for a file
//	checksum, err := workspace.ComputeChecksum("results/CVE-2023-1234.json")
//
//	// Verify a file
//	valid, err := workspace.VerifyChecksum("results/CVE-2023-1234.json", expectedChecksum)
//
//	// Write checksums file
//	checksums := &workspace.ChecksumFile{
//	    Files: map[string]string{
//	        "results/CVE-2023-1234.json": "a1b2c3d4e5f6g7h8",
//	    },
//	}
//	workspace.WriteChecksums("checksums", checksums)
package workspace
