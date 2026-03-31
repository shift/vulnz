package workspace

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// ChecksumFile represents the checksums file format.
// It maps relative file paths to their xxHash64 checksums.
type ChecksumFile struct {
	// Files maps relative paths to xxHash64 checksums
	Files map[string]string
}

// WriteChecksums writes a checksums file in tab-delimited format.
// Format: path\tchecksum
//
// Example:
//
//	results/CVE-2023-1234.json	a1b2c3d4e5f6g7h8
//	results/CVE-2023-5678.json	1234567890abcdef
func WriteChecksums(path string, checksums *ChecksumFile) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create checksums file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	// Write in deterministic order (sorted by path)
	for path, checksum := range checksums.Files {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", path, checksum); err != nil {
			return fmt.Errorf("write checksum entry: %w", err)
		}
	}

	return w.Flush()
}

// ReadChecksums reads a checksums file in tab-delimited format.
// Each line should be: path\tchecksum
func ReadChecksums(path string) (*ChecksumFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open checksums file: %w", err)
	}
	defer f.Close()

	checksums := &ChecksumFile{
		Files: make(map[string]string),
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format at line %d: expected 2 fields, got %d", lineNum, len(parts))
		}

		path := parts[0]
		checksum := parts[1]
		checksums.Files[path] = checksum
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksums file: %w", err)
	}

	return checksums, nil
}

// ComputeChecksum computes the xxHash64 checksum for a file.
// Returns the checksum as a hexadecimal string.
func ComputeChecksum(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := xxhash.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("compute hash: %w", err)
	}

	return fmt.Sprintf("%016x", h.Sum64()), nil
}

// VerifyChecksum verifies that a file matches the expected checksum.
// Returns true if the checksums match, false otherwise.
func VerifyChecksum(filePath string, expected string) (bool, error) {
	actual, err := ComputeChecksum(filePath)
	if err != nil {
		return false, err
	}
	return actual == expected, nil
}

// ComputeChecksumReader computes the xxHash64 checksum from a reader.
// This is useful for computing checksums of in-memory data.
func ComputeChecksumReader(r io.Reader) (string, error) {
	h := xxhash.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("compute hash: %w", err)
	}
	return fmt.Sprintf("%016x", h.Sum64()), nil
}
