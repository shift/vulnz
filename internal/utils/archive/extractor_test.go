package archive_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/klauspost/compress/zstd"
	"github.com/shift/vulnz/internal/utils/archive"
)

var _ = Describe("Archive Extractor", func() {
	var (
		ctx        context.Context
		tempDir    string
		archiveDir string
		extractDir string
	)

	BeforeEach(func() {
		ctx = context.Background()

		// Create temporary directories for tests
		var err error
		tempDir, err = os.MkdirTemp("", "archive-test-*")
		Expect(err).ToNot(HaveOccurred())

		archiveDir = filepath.Join(tempDir, "archives")
		extractDir = filepath.Join(tempDir, "extracted")

		err = os.MkdirAll(archiveDir, 0755)
		Expect(err).ToNot(HaveOccurred())
		err = os.MkdirAll(extractDir, 0755)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		if tempDir != "" {
			os.RemoveAll(tempDir)
		}
	})

	// Helper function to create a test tar archive
	createTestTarArchive := func(compressionType string, files map[string]string) string {
		var archivePath string
		var writer io.Writer
		var file *os.File
		var err error

		// Create archive file
		switch compressionType {
		case "none":
			archivePath = filepath.Join(archiveDir, "test.tar")
		case "gzip":
			archivePath = filepath.Join(archiveDir, "test.tar.gz")
		case "bzip2":
			archivePath = filepath.Join(archiveDir, "test.tar.bz2")
		case "zstd":
			archivePath = filepath.Join(archiveDir, "test.tar.zst")
		default:
			Fail("unsupported compression type: " + compressionType)
		}

		file, err = os.Create(archivePath)
		Expect(err).ToNot(HaveOccurred())
		defer file.Close()

		// Create compression writer
		switch compressionType {
		case "none":
			writer = file
		case "gzip":
			gzWriter := gzip.NewWriter(file)
			defer gzWriter.Close()
			writer = gzWriter
		case "bzip2":
			// Note: bzip2 writer is not in standard library, skip for creation
			Fail("bzip2 writer not available in standard library")
		case "zstd":
			zstdWriter, err := zstd.NewWriter(file)
			Expect(err).ToNot(HaveOccurred())
			defer zstdWriter.Close()
			writer = zstdWriter
		}

		// Create tar writer
		tarWriter := tar.NewWriter(writer)
		defer tarWriter.Close()

		// Add files to archive
		for name, content := range files {
			header := &tar.Header{
				Name:     name,
				Mode:     0644,
				Size:     int64(len(content)),
				Typeflag: tar.TypeReg,
			}
			err = tarWriter.WriteHeader(header)
			Expect(err).ToNot(HaveOccurred())

			_, err = tarWriter.Write([]byte(content))
			Expect(err).ToNot(HaveOccurred())
		}

		return archivePath
	}

	Describe("Basic extraction", func() {
		Context("when extracting an uncompressed tar archive", func() {
			It("should extract all files successfully", func() {
				files := map[string]string{
					"file1.txt":     "content1",
					"file2.txt":     "content2",
					"dir/file3.txt": "content3",
				}
				archivePath := createTestTarArchive("none", files)

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				// Verify extracted files
				content, err := os.ReadFile(filepath.Join(extractDir, "file1.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("content1"))

				content, err = os.ReadFile(filepath.Join(extractDir, "file2.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("content2"))

				content, err = os.ReadFile(filepath.Join(extractDir, "dir/file3.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("content3"))
			})

			It("should create nested directories", func() {
				files := map[string]string{
					"a/b/c/file.txt": "nested",
				}
				archivePath := createTestTarArchive("none", files)

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				content, err := os.ReadFile(filepath.Join(extractDir, "a/b/c/file.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("nested"))
			})
		})

		Context("when extracting a gzip compressed archive", func() {
			It("should extract all files successfully", func() {
				files := map[string]string{
					"file1.txt": "gzip content 1",
					"file2.txt": "gzip content 2",
				}
				archivePath := createTestTarArchive("gzip", files)

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				content, err := os.ReadFile(filepath.Join(extractDir, "file1.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("gzip content 1"))
			})
		})

		Context("when extracting a zstd compressed archive", func() {
			It("should extract all files successfully", func() {
				files := map[string]string{
					"file1.txt": "zstd content 1",
					"file2.txt": "zstd content 2",
				}
				archivePath := createTestTarArchive("zstd", files)

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				content, err := os.ReadFile(filepath.Join(extractDir, "file1.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("zstd content 1"))
			})
		})
	})

	Describe("Destination directory handling", func() {
		Context("when destination directory does not exist", func() {
			It("should create the destination directory", func() {
				nonExistentDir := filepath.Join(tempDir, "new-dir", "nested")
				files := map[string]string{
					"file.txt": "content",
				}
				archivePath := createTestTarArchive("none", files)

				err := archive.Extract(ctx, archivePath, nonExistentDir)
				Expect(err).ToNot(HaveOccurred())

				// Verify directory was created
				info, err := os.Stat(nonExistentDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())

				// Verify file was extracted
				content, err := os.ReadFile(filepath.Join(nonExistentDir, "file.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("content"))
			})
		})
	})

	Describe("Path traversal protection", func() {
		// Helper to create malicious tar archive
		createMaliciousTar := func(filename string) string {
			archivePath := filepath.Join(archiveDir, "malicious.tar")
			file, err := os.Create(archivePath)
			Expect(err).ToNot(HaveOccurred())
			defer file.Close()

			tarWriter := tar.NewWriter(file)
			defer tarWriter.Close()

			content := "malicious content"
			header := &tar.Header{
				Name:     filename,
				Mode:     0644,
				Size:     int64(len(content)),
				Typeflag: tar.TypeReg,
			}
			err = tarWriter.WriteHeader(header)
			Expect(err).ToNot(HaveOccurred())

			_, err = tarWriter.Write([]byte(content))
			Expect(err).ToNot(HaveOccurred())

			return archivePath
		}

		Context("when archive contains absolute paths", func() {
			It("should reject the extraction", func() {
				archivePath := createMaliciousTar("/etc/passwd")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("path traversal"))
				Expect(err.Error()).To(ContainSubstring("absolute"))
			})
		})

		Context("when archive contains parent directory references", func() {
			It("should reject ../../etc/passwd", func() {
				archivePath := createMaliciousTar("../../etc/passwd")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("path traversal"))
			})

			It("should reject ../../../etc/passwd", func() {
				archivePath := createMaliciousTar("../../../etc/passwd")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("path traversal"))
			})

			It("should reject dir/../../etc/passwd", func() {
				archivePath := createMaliciousTar("dir/../../etc/passwd")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("path traversal"))
			})
		})

		Context("when archive contains valid relative paths", func() {
			It("should allow ./file.txt", func() {
				archivePath := createMaliciousTar("./file.txt")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				_, err = os.Stat(filepath.Join(extractDir, "file.txt"))
				Expect(err).ToNot(HaveOccurred())
			})

			It("should allow dir/../file.txt (resolves to file.txt)", func() {
				archivePath := createMaliciousTar("dir/../file.txt")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				_, err = os.Stat(filepath.Join(extractDir, "file.txt"))
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Context cancellation", func() {
		Context("when context is cancelled during extraction", func() {
			It("should stop extraction and return error", func() {
				// Create a large archive
				files := make(map[string]string)
				for i := 0; i < 100; i++ {
					files[filepath.Join("dir", fmt.Sprintf("file%03d.txt", i))] = "content"
				}
				archivePath := createTestTarArchive("none", files)

				// Create a context that cancels immediately
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel() // Cancel immediately

				err := archive.Extract(cancelCtx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context canceled"))
			})
		})
	})

	Describe("Error handling", func() {
		Context("when archive file does not exist", func() {
			It("should return an error", func() {
				err := archive.Extract(ctx, filepath.Join(archiveDir, "nonexistent.tar"), extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("open archive"))
			})
		})

		Context("when archive is corrupted", func() {
			It("should return an error for corrupted gzip", func() {
				corruptedPath := filepath.Join(archiveDir, "corrupted.tar.gz")
				err := os.WriteFile(corruptedPath, []byte("not a gzip file"), 0644)
				Expect(err).ToNot(HaveOccurred())

				err = archive.Extract(ctx, corruptedPath, extractDir)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Special file types", func() {
		// Helper to create tar with directory entries
		createTarWithDirectories := func() string {
			archivePath := filepath.Join(archiveDir, "with-dirs.tar")
			file, err := os.Create(archivePath)
			Expect(err).ToNot(HaveOccurred())
			defer file.Close()

			tarWriter := tar.NewWriter(file)
			defer tarWriter.Close()

			// Add directory entry
			dirHeader := &tar.Header{
				Name:     "testdir/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
			}
			err = tarWriter.WriteHeader(dirHeader)
			Expect(err).ToNot(HaveOccurred())

			// Add file in directory
			content := "file in dir"
			fileHeader := &tar.Header{
				Name:     "testdir/file.txt",
				Mode:     0644,
				Size:     int64(len(content)),
				Typeflag: tar.TypeReg,
			}
			err = tarWriter.WriteHeader(fileHeader)
			Expect(err).ToNot(HaveOccurred())
			_, err = tarWriter.Write([]byte(content))
			Expect(err).ToNot(HaveOccurred())

			return archivePath
		}

		Context("when archive contains directory entries", func() {
			It("should create directories", func() {
				archivePath := createTarWithDirectories()

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				info, err := os.Stat(filepath.Join(extractDir, "testdir"))
				Expect(err).ToNot(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())

				content, err := os.ReadFile(filepath.Join(extractDir, "testdir/file.txt"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(content)).To(Equal("file in dir"))
			})
		})
	})

	Describe("File permissions", func() {
		Context("when extracting files with different permissions", func() {
			It("should preserve file permissions", func() {
				archivePath := filepath.Join(archiveDir, "perms.tar")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				defer file.Close()

				tarWriter := tar.NewWriter(file)
				defer tarWriter.Close()

				// Create file with specific permissions
				content := "executable content"
				header := &tar.Header{
					Name:     "executable.sh",
					Mode:     0755, // rwxr-xr-x
					Size:     int64(len(content)),
					Typeflag: tar.TypeReg,
				}
				err = tarWriter.WriteHeader(header)
				Expect(err).ToNot(HaveOccurred())
				_, err = tarWriter.Write([]byte(content))
				Expect(err).ToNot(HaveOccurred())

				err = archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				info, err := os.Stat(filepath.Join(extractDir, "executable.sh"))
				Expect(err).ToNot(HaveOccurred())
				// Check that executable bit is set
				Expect(info.Mode() & 0111).ToNot(Equal(0))
			})
		})
	})
})
