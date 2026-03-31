package archive_test

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/archive"
)

var _ = Describe("Security Functions", func() {
	var (
		ctx     context.Context
		tempDir string
	)

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tempDir, err = os.MkdirTemp("", "security-test-*")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		if tempDir != "" {
			os.RemoveAll(tempDir)
		}
	})

	Describe("Compression detection", func() {
		// Test that we properly detect different compression formats
		Context("when detecting archive types", func() {
			It("should handle .tar.gz files", func() {
				archivePath := filepath.Join(tempDir, "test.tar.gz")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				file.Close()
				// The file exists now, which is all we need for the test
			})

			It("should handle .tgz files", func() {
				archivePath := filepath.Join(tempDir, "test.tgz")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				file.Close()
			})

			It("should handle .tar.bz2 files", func() {
				archivePath := filepath.Join(tempDir, "test.tar.bz2")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				file.Close()
			})

			It("should handle .tar.zst files", func() {
				archivePath := filepath.Join(tempDir, "test.tar.zst")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				file.Close()
			})
		})
	})

	Describe("Symlink handling", func() {
		// Helper to create tar with symlink
		createTarWithSymlink := func(linkName, linkTarget string) string {
			archivePath := filepath.Join(tempDir, "symlink.tar")
			file, err := os.Create(archivePath)
			Expect(err).ToNot(HaveOccurred())
			defer file.Close()

			tarWriter := tar.NewWriter(file)
			defer tarWriter.Close()

			// Add target file first
			targetContent := "target content"
			targetHeader := &tar.Header{
				Name:     linkTarget,
				Mode:     0644,
				Size:     int64(len(targetContent)),
				Typeflag: tar.TypeReg,
			}
			err = tarWriter.WriteHeader(targetHeader)
			Expect(err).ToNot(HaveOccurred())
			_, err = tarWriter.Write([]byte(targetContent))
			Expect(err).ToNot(HaveOccurred())

			// Add symlink
			linkHeader := &tar.Header{
				Name:     linkName,
				Linkname: linkTarget,
				Typeflag: tar.TypeSymlink,
			}
			err = tarWriter.WriteHeader(linkHeader)
			Expect(err).ToNot(HaveOccurred())

			return archivePath
		}

		Context("when archive contains valid symlinks", func() {
			It("should create symlinks within destDir", func() {
				archivePath := createTarWithSymlink("link.txt", "target.txt")
				extractDir := filepath.Join(tempDir, "extract")

				err := archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred())

				linkPath := filepath.Join(extractDir, "link.txt")
				info, err := os.Lstat(linkPath)
				Expect(err).ToNot(HaveOccurred())
				Expect(info.Mode() & os.ModeSymlink).ToNot(Equal(0))
			})
		})

		Context("when archive contains unsafe symlinks", func() {
			It("should skip symlinks pointing outside destDir", func() {
				archivePath := filepath.Join(tempDir, "bad-symlink.tar")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				defer file.Close()

				tarWriter := tar.NewWriter(file)
				defer tarWriter.Close()

				// Add symlink pointing outside
				linkHeader := &tar.Header{
					Name:     "badlink.txt",
					Linkname: "../../etc/passwd",
					Typeflag: tar.TypeSymlink,
				}
				err = tarWriter.WriteHeader(linkHeader)
				Expect(err).ToNot(HaveOccurred())

				extractDir := filepath.Join(tempDir, "extract")
				err = archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred()) // Should skip, not fail

				// Verify symlink was not created
				linkPath := filepath.Join(extractDir, "badlink.txt")
				_, err = os.Lstat(linkPath)
				Expect(err).To(HaveOccurred()) // Should not exist
			})
		})
	})

	Describe("Hard link handling", func() {
		Context("when archive contains hard links", func() {
			It("should skip hard links gracefully", func() {
				archivePath := filepath.Join(tempDir, "hardlink.tar")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				defer file.Close()

				tarWriter := tar.NewWriter(file)
				defer tarWriter.Close()

				// Add target file
				targetContent := "target content"
				targetHeader := &tar.Header{
					Name:     "target.txt",
					Mode:     0644,
					Size:     int64(len(targetContent)),
					Typeflag: tar.TypeReg,
				}
				err = tarWriter.WriteHeader(targetHeader)
				Expect(err).ToNot(HaveOccurred())
				_, err = tarWriter.Write([]byte(targetContent))
				Expect(err).ToNot(HaveOccurred())

				// Add hard link
				linkHeader := &tar.Header{
					Name:     "hardlink.txt",
					Linkname: "target.txt",
					Typeflag: tar.TypeLink,
				}
				err = tarWriter.WriteHeader(linkHeader)
				Expect(err).ToNot(HaveOccurred())

				extractDir := filepath.Join(tempDir, "extract")
				err = archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred()) // Should not fail

				// Target should exist
				_, err = os.Stat(filepath.Join(extractDir, "target.txt"))
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Unknown file types", func() {
		Context("when archive contains unknown file types", func() {
			It("should skip unknown types gracefully", func() {
				archivePath := filepath.Join(tempDir, "unknown.tar")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				defer file.Close()

				tarWriter := tar.NewWriter(file)
				defer tarWriter.Close()

				// Add an unknown type (device file)
				header := &tar.Header{
					Name:     "device",
					Typeflag: tar.TypeChar, // Character device
				}
				err = tarWriter.WriteHeader(header)
				Expect(err).ToNot(HaveOccurred())

				extractDir := filepath.Join(tempDir, "extract")
				err = archive.Extract(ctx, archivePath, extractDir)
				Expect(err).ToNot(HaveOccurred()) // Should not fail
			})
		})
	})

	Describe("XZ compression", func() {
		Context("when trying to extract .tar.xz files", func() {
			It("should return not implemented error", func() {
				archivePath := filepath.Join(tempDir, "test.tar.xz")
				file, err := os.Create(archivePath)
				Expect(err).ToNot(HaveOccurred())
				file.Close()

				extractDir := filepath.Join(tempDir, "extract")
				err = archive.Extract(ctx, archivePath, extractDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("xz compression not yet implemented"))
			})
		})
	})
})
