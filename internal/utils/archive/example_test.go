package archive_test

import (
	"context"
	"fmt"
	"log"

	"github.com/shift/vulnz/internal/utils/archive"
)

// Example demonstrates basic archive extraction
func Example() {
	ctx := context.Background()

	// Extract a gzip-compressed tar archive
	err := archive.Extract(ctx, "/path/to/data.tar.gz", "/path/to/destination")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Archive extracted successfully")
}

// Example_zstd demonstrates extracting a zstd-compressed archive
func Example_zstd() {
	ctx := context.Background()

	// Extract a zstd-compressed tar archive
	err := archive.Extract(ctx, "/path/to/data.tar.zst", "/path/to/destination")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Zstd archive extracted successfully")
}

// Example_pathTraversalProtection demonstrates the built-in security
func Example_pathTraversalProtection() {
	ctx := context.Background()

	// This will fail if the archive contains path traversal attempts
	err := archive.Extract(ctx, "/path/to/malicious.tar", "/path/to/destination")
	if err != nil {
		// Error will contain "path traversal" if an attack was detected
		fmt.Printf("Security violation detected: %v\n", err)
	}
}
