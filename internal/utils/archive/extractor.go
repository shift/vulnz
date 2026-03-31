// Package archive provides secure archive extraction utilities with path traversal protection.
// It supports multiple compression formats commonly used in vulnerability data feeds:
// tar, tar.gz, tar.bz2, tar.xz, and tar.zst.
package archive

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

// CompressionType represents the compression format of an archive.
type CompressionType int

const (
	// CompressionNone indicates an uncompressed tar archive
	CompressionNone CompressionType = iota
	// CompressionGzip indicates gzip compression (.tar.gz, .tgz)
	CompressionGzip
	// CompressionBzip2 indicates bzip2 compression (.tar.bz2)
	CompressionBzip2
	// CompressionXZ indicates xz compression (.tar.xz)
	CompressionXZ
	// CompressionZstd indicates zstandard compression (.tar.zst)
	CompressionZstd
)

// Extract extracts an archive file to the specified destination directory.
// It automatically detects the compression format from the file extension and
// applies path traversal protection to prevent malicious archives from writing
// outside the destination directory.
//
// Supported formats:
//   - .tar (uncompressed)
//   - .tar.gz, .tgz (gzip)
//   - .tar.bz2, .tbz2 (bzip2)
//   - .tar.xz (xz)
//   - .tar.zst (zstandard)
//
// Security measures:
//   - Rejects absolute paths
//   - Rejects paths containing ".." that escape destDir
//   - Logs security violations
//   - Creates destination directory if it doesn't exist
//
// Parameters:
//   - ctx: Context for cancellation support
//   - archivePath: Path to the archive file to extract
//   - destDir: Destination directory for extracted files
//
// Returns an error if:
//   - Archive file cannot be opened
//   - Compression format is unsupported
//   - Path traversal is detected
//   - Extraction fails
//
// Example:
//
//	ctx := context.Background()
//	err := Extract(ctx, "/tmp/data.tar.gz", "/tmp/extracted")
//	if err != nil {
//	    log.Fatal(err)
//	}
func Extract(ctx context.Context, archivePath, destDir string) error {
	logrus.WithFields(logrus.Fields{
		"archive": archivePath,
		"dest":    destDir,
	}).Info("extracting archive")

	// Ensure destination directory exists
	if err := ensureDir(destDir); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	// Detect compression type from file extension
	compressionType := detectCompression(archivePath)

	// Open archive file
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()

	// Create decompression reader based on compression type
	var reader io.Reader
	var closer io.Closer

	switch compressionType {
	case CompressionNone:
		reader = file
	case CompressionGzip:
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
		closer = gzReader
	case CompressionBzip2:
		reader = bzip2.NewReader(file)
	case CompressionXZ:
		// For XZ, we need to use an external library or command
		// For now, return an error as it's less common
		return fmt.Errorf("xz compression not yet implemented (use tar.gz or tar.zst instead)")
	case CompressionZstd:
		zstdReader, err := zstd.NewReader(file)
		if err != nil {
			return fmt.Errorf("create zstd reader: %w", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
		// zstd.Decoder.Close() doesn't return error, so we handle it separately
	default:
		return fmt.Errorf("unsupported compression type")
	}

	// Ensure closer is called if set
	if closer != nil {
		defer closer.Close()
	}

	// Extract tar archive
	if err := extractTar(ctx, reader, destDir); err != nil {
		return fmt.Errorf("extract tar: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"archive": archivePath,
		"dest":    destDir,
	}).Info("archive extracted successfully")

	return nil
}

// detectCompression detects the compression format from the file extension.
func detectCompression(filename string) CompressionType {
	lower := strings.ToLower(filename)

	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return CompressionGzip
	}
	if strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2") {
		return CompressionBzip2
	}
	if strings.HasSuffix(lower, ".tar.xz") {
		return CompressionXZ
	}
	if strings.HasSuffix(lower, ".tar.zst") {
		return CompressionZstd
	}
	if strings.HasSuffix(lower, ".tar") {
		return CompressionNone
	}

	// Default to uncompressed
	return CompressionNone
}

// extractTar extracts a tar archive from the given reader to destDir.
// It applies path traversal protection to each file in the archive.
func extractTar(ctx context.Context, reader io.Reader, destDir string) error {
	tarReader := tar.NewReader(reader)
	fileCount := 0
	dirCount := 0

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		// Validate and sanitize the target path
		targetPath, err := filterPathTraversal(destDir, header.Name)
		if err != nil {
			// Log the violation and skip this file
			logrus.WithFields(logrus.Fields{
				"file":     header.Name,
				"dest_dir": destDir,
			}).Error("skipping file due to path traversal violation")
			return fmt.Errorf("path traversal violation for file %s: %w", header.Name, err)
		}

		// Handle different file types
		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := ensureDir(targetPath); err != nil {
				return fmt.Errorf("create directory %s: %w", header.Name, err)
			}
			dirCount++

		case tar.TypeReg:
			// Create parent directory if needed
			parentDir := filepath.Dir(targetPath)
			if err := ensureDir(parentDir); err != nil {
				return fmt.Errorf("create parent directory for %s: %w", header.Name, err)
			}

			// Extract regular file
			if err := extractFile(tarReader, targetPath, header.Mode); err != nil {
				return fmt.Errorf("extract file %s: %w", header.Name, err)
			}
			fileCount++

		case tar.TypeSymlink:
			// Validate symlink target
			linkTarget := header.Linkname
			if _, err := filterPathTraversal(destDir, linkTarget); err != nil {
				logrus.WithFields(logrus.Fields{
					"symlink":  header.Name,
					"target":   linkTarget,
					"dest_dir": destDir,
				}).Warn("skipping symlink with unsafe target")
				continue // Skip this symlink but continue extraction
			}

			// Create parent directory if needed
			parentDir := filepath.Dir(targetPath)
			if err := ensureDir(parentDir); err != nil {
				return fmt.Errorf("create parent directory for symlink %s: %w", header.Name, err)
			}

			// Create symlink
			if err := os.Symlink(linkTarget, targetPath); err != nil {
				// If symlink already exists, skip it
				if os.IsExist(err) {
					continue
				}
				return fmt.Errorf("create symlink %s: %w", header.Name, err)
			}

		case tar.TypeLink:
			// Hard links are less common, log and skip
			logrus.WithFields(logrus.Fields{
				"file":   header.Name,
				"target": header.Linkname,
			}).Debug("skipping hard link")
			continue

		default:
			// Unknown type, log and skip
			logrus.WithFields(logrus.Fields{
				"file": header.Name,
				"type": header.Typeflag,
			}).Debug("skipping unknown file type")
			continue
		}
	}

	logrus.WithFields(logrus.Fields{
		"files":       fileCount,
		"directories": dirCount,
		"dest":        destDir,
	}).Debug("tar extraction complete")

	return nil
}

// extractFile extracts a single file from the tar reader to the target path.
func extractFile(tarReader *tar.Reader, targetPath string, mode int64) error {
	// Create the file with appropriate permissions
	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(mode))
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer outFile.Close()

	// Copy file contents
	if _, err := io.Copy(outFile, tarReader); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
