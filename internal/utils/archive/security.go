// Package archive provides secure archive extraction utilities with path traversal protection.
package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// filterPathTraversal validates that the target path is within destDir.
// It prevents path traversal attacks by rejecting:
//   - Absolute paths (starting with /)
//   - Paths containing ".." that escape destDir
//
// Returns the sanitized absolute path within destDir, or an error if the path is unsafe.
//
// Examples:
//   - filterPathTraversal("/tmp/dest", "file.txt") -> "/tmp/dest/file.txt", nil
//   - filterPathTraversal("/tmp/dest", "dir/file.txt") -> "/tmp/dest/dir/file.txt", nil
//   - filterPathTraversal("/tmp/dest", "/etc/passwd") -> "", error (absolute path)
//   - filterPathTraversal("/tmp/dest", "../../etc/passwd") -> "", error (escapes destDir)
func filterPathTraversal(destDir, targetPath string) (string, error) {
	// Reject absolute paths
	if filepath.IsAbs(targetPath) {
		logrus.WithFields(logrus.Fields{
			"target_path": targetPath,
			"dest_dir":    destDir,
			"violation":   "absolute_path",
		}).Warn("path traversal attack detected: absolute path")
		return "", fmt.Errorf("path traversal detected: absolute paths not allowed: %s", targetPath)
	}

	// Clean the target path to resolve any .. or . segments
	cleanTarget := filepath.Clean(targetPath)

	// Check if the cleaned path tries to escape using ..
	if strings.HasPrefix(cleanTarget, ".."+string(filepath.Separator)) || cleanTarget == ".." {
		logrus.WithFields(logrus.Fields{
			"target_path":  targetPath,
			"clean_target": cleanTarget,
			"dest_dir":     destDir,
			"violation":    "parent_directory_escape",
		}).Warn("path traversal attack detected: parent directory escape")
		return "", fmt.Errorf("path traversal detected: path escapes destination: %s", targetPath)
	}

	// Get absolute path of destination directory
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("resolve destination directory: %w", err)
	}

	// Construct the full target path
	fullTargetPath := filepath.Join(absDestDir, cleanTarget)

	// Resolve to absolute path (handles symlinks)
	absTargetPath := fullTargetPath // We can't use filepath.EvalSymlinks before the file exists

	// Verify the target path is within destination directory
	// We need to check if absTargetPath starts with absDestDir
	relPath, err := filepath.Rel(absDestDir, absTargetPath)
	if err != nil {
		return "", fmt.Errorf("compute relative path: %w", err)
	}

	// If the relative path starts with "..", it's trying to escape
	if strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || relPath == ".." {
		logrus.WithFields(logrus.Fields{
			"target_path": targetPath,
			"abs_target":  absTargetPath,
			"dest_dir":    absDestDir,
			"rel_path":    relPath,
			"violation":   "directory_escape",
		}).Warn("path traversal attack detected: directory escape")
		return "", fmt.Errorf("path traversal detected: path escapes destination: %s", targetPath)
	}

	return absTargetPath, nil
}

// isValidPath checks if a path is safe for extraction.
// It returns true if the path passes security checks.
func isValidPath(destDir, targetPath string) bool {
	_, err := filterPathTraversal(destDir, targetPath)
	return err == nil
}

// ensureDir creates a directory and all parent directories if they don't exist.
// It's equivalent to mkdir -p.
func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}
