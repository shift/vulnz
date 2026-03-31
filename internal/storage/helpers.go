package storage

import (
	"os"
	"path/filepath"
	"strings"
)

// ExtractNamespace gets namespace from identifier.
// Examples:
//   - "CVE-2023-1234" -> "nvd"
//   - "GHSA-xxxx-yyyy-zzzz" -> "github"
//   - "alpine:3.18:CVE-2023-1234" -> "alpine"
//
// This is used by the flat-file backend to organize files into subdirectories.
func ExtractNamespace(identifier string) string {
	// Check known ID prefixes first (before colon/slash checks,
	// since identifiers like "RHSA-2023:1234" or "CVE:2023:1234"
	// contain colons as part of their format, not as namespace separators).
	if strings.HasPrefix(identifier, "CVE-") || strings.HasPrefix(identifier, "CVE:") {
		return "nvd"
	}
	if strings.HasPrefix(identifier, "GHSA-") {
		return "github"
	}
	if strings.HasPrefix(identifier, "RHSA-") {
		return "redhat"
	}
	if strings.HasPrefix(identifier, "DSA-") {
		return "debian"
	}

	// Check for colon-separated format (e.g., "alpine:3.18:CVE-2023-1234")
	if strings.Contains(identifier, ":") {
		parts := strings.Split(identifier, ":")
		return parts[0]
	}

	// Check for slash-separated format (e.g., "debian/bookworm/CVE-2023-1234")
	if strings.Contains(identifier, "/") {
		parts := strings.Split(identifier, "/")
		return parts[0]
	}

	// Default namespace
	return "unknown"
}

// SanitizeFilename removes invalid path characters from a filename.
// This ensures the filename is safe to use across different operating systems.
func SanitizeFilename(name string) string {
	// Replace invalid characters with underscores
	replacer := strings.NewReplacer(
		"<", "_",
		">", "_",
		":", "_",
		"\"", "_",
		"|", "_",
		"?", "_",
		"*", "_",
		"\x00", "_",
		"/", "_",
		"\\", "_",
	)
	return replacer.Replace(name)
}

// EnsureDir creates a directory if it doesn't exist.
// Returns an error if directory creation fails.
func EnsureDir(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(path, 0755)
}

// fileExists checks if a file exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// dirExists checks if a directory exists.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// joinPath safely joins path components and cleans the result.
func joinPath(elem ...string) string {
	return filepath.Clean(filepath.Join(elem...))
}
