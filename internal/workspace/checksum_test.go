package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComputeChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Hello, World!")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute checksum
	checksum, err := ComputeChecksum(context.Background(), testFile)
	if err != nil {
		t.Fatalf("ComputeChecksum failed: %v", err)
	}

	// Verify checksum is a hex string
	if len(checksum) != 16 {
		t.Errorf("Expected 16 character hex string, got %d characters", len(checksum))
	}

	// Verify checksum contains only hex characters
	for _, c := range checksum {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("Checksum contains non-hex character: %c", c)
		}
	}

	// Compute again, should get same result
	checksum2, err := ComputeChecksum(context.Background(), testFile)
	if err != nil {
		t.Fatalf("Second ComputeChecksum failed: %v", err)
	}
	if checksum != checksum2 {
		t.Errorf("Checksums don't match: %s != %s", checksum, checksum2)
	}
}

func TestComputeChecksum_DifferentContent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two files with different content
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")

	if err := os.WriteFile(file1, []byte("Content A"), 0644); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("Content B"), 0644); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	// Compute checksums
	checksum1, err := ComputeChecksum(context.Background(), file1)
	if err != nil {
		t.Fatalf("ComputeChecksum file1 failed: %v", err)
	}

	checksum2, err := ComputeChecksum(context.Background(), file2)
	if err != nil {
		t.Fatalf("ComputeChecksum file2 failed: %v", err)
	}

	// Checksums should be different
	if checksum1 == checksum2 {
		t.Error("Checksums should be different for different content")
	}
}

func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Test content for verification")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute expected checksum
	expected, err := ComputeChecksum(context.Background(), testFile)
	if err != nil {
		t.Fatalf("ComputeChecksum failed: %v", err)
	}

	// Verify with correct checksum
	valid, err := VerifyChecksum(context.Background(), testFile, expected)
	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}
	if !valid {
		t.Error("VerifyChecksum returned false for correct checksum")
	}

	// Verify with incorrect checksum
	valid, err = VerifyChecksum(context.Background(), testFile, "0000000000000000")
	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}
	if valid {
		t.Error("VerifyChecksum returned true for incorrect checksum")
	}
}

func TestWriteChecksums(t *testing.T) {
	tmpDir := t.TempDir()
	checksumsPath := filepath.Join(tmpDir, "checksums")

	checksums := &ChecksumFile{
		Files: map[string]string{
			"results/CVE-2023-1234.json": "a1b2c3d4e5f6g7h8",
			"results/CVE-2023-5678.json": "1234567890abcdef",
			"results/CVE-2023-9999.json": "fedcba0987654321",
		},
	}

	// Write checksums file
	err := WriteChecksums(checksumsPath, checksums)
	if err != nil {
		t.Fatalf("WriteChecksums failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(checksumsPath); err != nil {
		t.Errorf("Checksums file not created: %v", err)
	}

	// Read and verify content
	content, err := os.ReadFile(checksumsPath)
	if err != nil {
		t.Fatalf("Failed to read checksums file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	// Filter out empty lines
	var nonEmptyLines []string
	for _, line := range lines {
		if line != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}

	if len(nonEmptyLines) != len(checksums.Files) {
		t.Errorf("Expected %d lines, got %d", len(checksums.Files), len(nonEmptyLines))
	}

	// Verify each line has correct format
	for _, line := range nonEmptyLines {
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Errorf("Invalid line format: %s", line)
			continue
		}

		path := parts[0]
		checksum := parts[1]

		expectedChecksum, ok := checksums.Files[path]
		if !ok {
			t.Errorf("Unexpected path in checksums file: %s", path)
			continue
		}

		if checksum != expectedChecksum {
			t.Errorf("Checksum mismatch for %s: got %s, want %s", path, checksum, expectedChecksum)
		}
	}
}

func TestReadChecksums(t *testing.T) {
	tmpDir := t.TempDir()
	checksumsPath := filepath.Join(tmpDir, "checksums")

	// Create checksums file manually
	content := `results/CVE-2023-1234.json	a1b2c3d4e5f6g7h8
results/CVE-2023-5678.json	1234567890abcdef
results/CVE-2023-9999.json	fedcba0987654321
`
	if err := os.WriteFile(checksumsPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create checksums file: %v", err)
	}

	// Read checksums
	checksums, err := ReadChecksums(checksumsPath)
	if err != nil {
		t.Fatalf("ReadChecksums failed: %v", err)
	}

	// Verify checksums
	expected := map[string]string{
		"results/CVE-2023-1234.json": "a1b2c3d4e5f6g7h8",
		"results/CVE-2023-5678.json": "1234567890abcdef",
		"results/CVE-2023-9999.json": "fedcba0987654321",
	}

	if len(checksums.Files) != len(expected) {
		t.Errorf("Expected %d checksums, got %d", len(expected), len(checksums.Files))
	}

	for path, expectedChecksum := range expected {
		actualChecksum, ok := checksums.Files[path]
		if !ok {
			t.Errorf("Missing checksum for %s", path)
			continue
		}
		if actualChecksum != expectedChecksum {
			t.Errorf("Checksum mismatch for %s: got %s, want %s", path, actualChecksum, expectedChecksum)
		}
	}
}

func TestReadChecksums_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	checksumsPath := filepath.Join(tmpDir, "checksums")

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "too many fields",
			content: "path\tchecksum\textra\n",
			wantErr: true,
		},
		{
			name:    "too few fields",
			content: "pathonly\n",
			wantErr: true,
		},
		{
			name:    "empty lines ignored",
			content: "path\tchecksum\n\npath2\tchecksum2\n",
			wantErr: false,
		},
		{
			name:    "valid format",
			content: "path\tchecksum\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(checksumsPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			_, err := ReadChecksums(checksumsPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadChecksums() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChecksums_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	checksumsPath := filepath.Join(tmpDir, "checksums")

	original := &ChecksumFile{
		Files: map[string]string{
			"results/file1.json": "aaaaaaaaaaaaaaaa",
			"results/file2.json": "bbbbbbbbbbbbbbbb",
			"results/file3.json": "cccccccccccccccc",
		},
	}

	// Write
	if err := WriteChecksums(checksumsPath, original); err != nil {
		t.Fatalf("WriteChecksums failed: %v", err)
	}

	// Read back
	read, err := ReadChecksums(checksumsPath)
	if err != nil {
		t.Fatalf("ReadChecksums failed: %v", err)
	}

	// Verify they match
	if len(read.Files) != len(original.Files) {
		t.Errorf("Length mismatch: got %d, want %d", len(read.Files), len(original.Files))
	}

	for path, checksum := range original.Files {
		if read.Files[path] != checksum {
			t.Errorf("Mismatch for %s: got %s, want %s", path, read.Files[path], checksum)
		}
	}
}

func TestComputeChecksum_NonexistentFile(t *testing.T) {
	_, err := ComputeChecksum(context.Background(), "/nonexistent/file.txt")
	if err == nil {
		t.Error("ComputeChecksum should fail for nonexistent file")
	}
}

func TestReadChecksums_NonexistentFile(t *testing.T) {
	_, err := ReadChecksums("/nonexistent/checksums")
	if err == nil {
		t.Error("ReadChecksums should fail for nonexistent file")
	}
}

func TestComputeChecksumReader(t *testing.T) {
	content := []byte("Test data for reader checksum")
	checksum, err := ComputeChecksumReader(context.Background(), strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("ComputeChecksumReader failed: %v", err)
	}

	// Verify checksum is a hex string
	if len(checksum) != 16 {
		t.Errorf("Expected 16 character hex string, got %d characters", len(checksum))
	}

	// Compute again, should get same result
	checksum2, err := ComputeChecksumReader(context.Background(), strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("Second ComputeChecksumReader failed: %v", err)
	}
	if checksum != checksum2 {
		t.Errorf("Checksums don't match: %s != %s", checksum, checksum2)
	}
}
