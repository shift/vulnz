package workspace_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/workspace"
)

var _ = Describe("Checksum Operations", func() {
	var (
		tempDir string
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
	})

	Describe("ComputeChecksum", func() {
		Context("with valid files", func() {
			It("should compute xxHash64 checksum for a file", func() {
				testFile := filepath.Join(tempDir, "test.txt")
				content := []byte("test content")
				err := os.WriteFile(testFile, content, 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(checksum).NotTo(BeEmpty())
				Expect(checksum).To(HaveLen(16)) // xxHash64 produces 16 hex chars
			})

			It("should produce consistent checksums for same content", func() {
				testFile := filepath.Join(tempDir, "test.txt")
				content := []byte("consistent content")
				err := os.WriteFile(testFile, content, 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum1, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())

				checksum2, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())

				Expect(checksum1).To(Equal(checksum2))
			})

			It("should produce different checksums for different content", func() {
				file1 := filepath.Join(tempDir, "file1.txt")
				err := os.WriteFile(file1, []byte("content 1"), 0644)
				Expect(err).NotTo(HaveOccurred())

				file2 := filepath.Join(tempDir, "file2.txt")
				err = os.WriteFile(file2, []byte("content 2"), 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum1, err := workspace.ComputeChecksum(file1)
				Expect(err).NotTo(HaveOccurred())

				checksum2, err := workspace.ComputeChecksum(file2)
				Expect(err).NotTo(HaveOccurred())

				Expect(checksum1).NotTo(Equal(checksum2))
			})

			It("should handle empty files", func() {
				testFile := filepath.Join(tempDir, "empty.txt")
				err := os.WriteFile(testFile, []byte{}, 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(checksum).NotTo(BeEmpty())
			})

			It("should handle large files", func() {
				testFile := filepath.Join(tempDir, "large.bin")
				// Create 10MB file
				largeContent := bytes.Repeat([]byte("x"), 10*1024*1024)
				err := os.WriteFile(testFile, largeContent, 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(checksum).NotTo(BeEmpty())
			})

			It("should handle binary files", func() {
				testFile := filepath.Join(tempDir, "binary.bin")
				binaryContent := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
				err := os.WriteFile(testFile, binaryContent, 0644)
				Expect(err).NotTo(HaveOccurred())

				checksum, err := workspace.ComputeChecksum(testFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(checksum).NotTo(BeEmpty())
			})
		})

		Context("with invalid files", func() {
			It("should return error for non-existent file", func() {
				checksum, err := workspace.ComputeChecksum(filepath.Join(tempDir, "non-existent.txt"))
				Expect(err).To(HaveOccurred())
				Expect(checksum).To(BeEmpty())
			})

			It("should return error for directory", func() {
				dirPath := filepath.Join(tempDir, "testdir")
				err := os.Mkdir(dirPath, 0755)
				Expect(err).NotTo(HaveOccurred())

				checksum, err := workspace.ComputeChecksum(dirPath)
				Expect(err).To(HaveOccurred())
				Expect(checksum).To(BeEmpty())
			})
		})
	})

	Describe("ComputeChecksumReader", func() {
		It("should compute checksum from reader", func() {
			content := []byte("test content from reader")
			reader := bytes.NewReader(content)

			checksum, err := workspace.ComputeChecksumReader(reader)
			Expect(err).NotTo(HaveOccurred())
			Expect(checksum).NotTo(BeEmpty())
			Expect(checksum).To(HaveLen(16))
		})

		It("should match file checksum for same content", func() {
			content := []byte("matching content")

			// Compute from file
			testFile := filepath.Join(tempDir, "test.txt")
			err := os.WriteFile(testFile, content, 0644)
			Expect(err).NotTo(HaveOccurred())

			fileChecksum, err := workspace.ComputeChecksum(testFile)
			Expect(err).NotTo(HaveOccurred())

			// Compute from reader
			reader := bytes.NewReader(content)
			readerChecksum, err := workspace.ComputeChecksumReader(reader)
			Expect(err).NotTo(HaveOccurred())

			Expect(readerChecksum).To(Equal(fileChecksum))
		})

		It("should handle empty reader", func() {
			reader := bytes.NewReader([]byte{})
			checksum, err := workspace.ComputeChecksumReader(reader)
			Expect(err).NotTo(HaveOccurred())
			Expect(checksum).NotTo(BeEmpty())
		})
	})

	Describe("VerifyChecksum", func() {
		var testFile string
		var expectedChecksum string

		BeforeEach(func() {
			testFile = filepath.Join(tempDir, "verify.txt")
			content := []byte("content to verify")
			err := os.WriteFile(testFile, content, 0644)
			Expect(err).NotTo(HaveOccurred())

			expectedChecksum, err = workspace.ComputeChecksum(testFile)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return true for matching checksum", func() {
			valid, err := workspace.VerifyChecksum(testFile, expectedChecksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())
		})

		It("should return false for non-matching checksum", func() {
			wrongChecksum := "0000000000000000"
			valid, err := workspace.VerifyChecksum(testFile, wrongChecksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeFalse())
		})

		It("should return error for non-existent file", func() {
			valid, err := workspace.VerifyChecksum(filepath.Join(tempDir, "non-existent.txt"), expectedChecksum)
			Expect(err).To(HaveOccurred())
			Expect(valid).To(BeFalse())
		})

		It("should detect file modification", func() {
			// Verify original
			valid, err := workspace.VerifyChecksum(testFile, expectedChecksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// Modify file
			err = os.WriteFile(testFile, []byte("modified content"), 0644)
			Expect(err).NotTo(HaveOccurred())

			// Should no longer match
			valid, err = workspace.VerifyChecksum(testFile, expectedChecksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeFalse())
		})
	})

	Describe("WriteChecksums and ReadChecksums", func() {
		var checksumFile string

		BeforeEach(func() {
			checksumFile = filepath.Join(tempDir, "checksums")
		})

		Context("with valid checksum data", func() {
			It("should write and read checksums file", func() {
				checksums := &workspace.ChecksumFile{
					Files: map[string]string{
						"file1.json": "abcdef1234567890",
						"file2.json": "1234567890abcdef",
						"file3.json": "fedcba0987654321",
					},
				}

				err := workspace.WriteChecksums(checksumFile, checksums)
				Expect(err).NotTo(HaveOccurred())

				// Verify file exists
				_, err = os.Stat(checksumFile)
				Expect(err).NotTo(HaveOccurred())

				// Read back
				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Files).To(HaveLen(3))
				Expect(read.Files["file1.json"]).To(Equal("abcdef1234567890"))
				Expect(read.Files["file2.json"]).To(Equal("1234567890abcdef"))
				Expect(read.Files["file3.json"]).To(Equal("fedcba0987654321"))
			})

			It("should use tab-delimited format", func() {
				checksums := &workspace.ChecksumFile{
					Files: map[string]string{
						"test.json": "abcd1234",
					},
				}

				err := workspace.WriteChecksums(checksumFile, checksums)
				Expect(err).NotTo(HaveOccurred())

				// Read raw content
				content, err := os.ReadFile(checksumFile)
				Expect(err).NotTo(HaveOccurred())

				// Should contain tab character
				Expect(string(content)).To(ContainSubstring("\t"))
			})

			It("should handle empty checksum map", func() {
				checksums := &workspace.ChecksumFile{
					Files: map[string]string{},
				}

				err := workspace.WriteChecksums(checksumFile, checksums)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Files).To(BeEmpty())
			})

			It("should handle paths with slashes", func() {
				checksums := &workspace.ChecksumFile{
					Files: map[string]string{
						"results/nvd/CVE-2023-1234.json":     "checksum1",
						"results/github/GHSA-xxxx-yyyy.json": "checksum2",
					},
				}

				err := workspace.WriteChecksums(checksumFile, checksums)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Files).To(HaveLen(2))
				Expect(read.Files["results/nvd/CVE-2023-1234.json"]).To(Equal("checksum1"))
			})

			It("should handle many entries", func() {
				checksums := &workspace.ChecksumFile{
					Files: make(map[string]string),
				}

				// Add 1000 entries
				for i := 0; i < 1000; i++ {
					path := fmt.Sprintf("file%04d.json", i)
					checksums.Files[path] = fmt.Sprintf("checksum%016d", i)
				}

				err := workspace.WriteChecksums(checksumFile, checksums)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Files).To(HaveLen(1000))
			})
		})

		Context("with invalid data", func() {
			It("should return error for non-existent file", func() {
				read, err := workspace.ReadChecksums(filepath.Join(tempDir, "non-existent"))
				Expect(err).To(HaveOccurred())
				Expect(read).To(BeNil())
			})

			It("should handle empty lines gracefully", func() {
				content := "file1.json\tchecksum1\n\nfile2.json\tchecksum2\n"
				err := os.WriteFile(checksumFile, []byte(content), 0644)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Files).To(HaveLen(2))
			})

			It("should return error for malformed lines", func() {
				// Missing tab separator
				content := "file1.json checksum1\n"
				err := os.WriteFile(checksumFile, []byte(content), 0644)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).To(HaveOccurred())
				Expect(read).To(BeNil())
			})

			It("should return error for lines with too many fields", func() {
				content := "file1.json\tchecksum1\textra\n"
				err := os.WriteFile(checksumFile, []byte(content), 0644)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).To(HaveOccurred())
				Expect(read).To(BeNil())
			})
		})

		Context("round-trip integrity", func() {
			It("should preserve all data through write-read cycle", func() {
				original := &workspace.ChecksumFile{
					Files: map[string]string{
						"results/CVE-2023-0001.json": "1111111111111111",
						"results/CVE-2023-0002.json": "2222222222222222",
						"results/GHSA-xxxx.json":     "3333333333333333",
						"metadata.json":              "4444444444444444",
					},
				}

				err := workspace.WriteChecksums(checksumFile, original)
				Expect(err).NotTo(HaveOccurred())

				read, err := workspace.ReadChecksums(checksumFile)
				Expect(err).NotTo(HaveOccurred())

				Expect(read.Files).To(HaveLen(len(original.Files)))
				for path, checksum := range original.Files {
					Expect(read.Files[path]).To(Equal(checksum))
				}
			})
		})
	})

	Describe("Integration with real files", func() {
		It("should compute and verify checksums for actual JSON files", func() {
			// Create test JSON files
			file1 := filepath.Join(tempDir, "vuln1.json")
			content1 := []byte(`{"id": "CVE-2023-1234", "severity": "HIGH"}`)
			err := os.WriteFile(file1, content1, 0644)
			Expect(err).NotTo(HaveOccurred())

			file2 := filepath.Join(tempDir, "vuln2.json")
			content2 := []byte(`{"id": "CVE-2023-5678", "severity": "MEDIUM"}`)
			err = os.WriteFile(file2, content2, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Compute checksums
			checksum1, err := workspace.ComputeChecksum(file1)
			Expect(err).NotTo(HaveOccurred())

			checksum2, err := workspace.ComputeChecksum(file2)
			Expect(err).NotTo(HaveOccurred())

			// Write checksums file
			checksumFile := filepath.Join(tempDir, "checksums")
			checksums := &workspace.ChecksumFile{
				Files: map[string]string{
					"vuln1.json": checksum1,
					"vuln2.json": checksum2,
				},
			}

			err = workspace.WriteChecksums(checksumFile, checksums)
			Expect(err).NotTo(HaveOccurred())

			// Read and verify
			read, err := workspace.ReadChecksums(checksumFile)
			Expect(err).NotTo(HaveOccurred())

			valid1, err := workspace.VerifyChecksum(file1, read.Files["vuln1.json"])
			Expect(err).NotTo(HaveOccurred())
			Expect(valid1).To(BeTrue())

			valid2, err := workspace.VerifyChecksum(file2, read.Files["vuln2.json"])
			Expect(err).NotTo(HaveOccurred())
			Expect(valid2).To(BeTrue())
		})

		It("should detect file tampering", func() {
			// Create and checksum file
			testFile := filepath.Join(tempDir, "important.json")
			originalContent := []byte(`{"important": "data"}`)
			err := os.WriteFile(testFile, originalContent, 0644)
			Expect(err).NotTo(HaveOccurred())

			originalChecksum, err := workspace.ComputeChecksum(testFile)
			Expect(err).NotTo(HaveOccurred())

			// Tamper with file
			tamperedContent := []byte(`{"important": "tampered"}`)
			err = os.WriteFile(testFile, tamperedContent, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Verification should fail
			valid, err := workspace.VerifyChecksum(testFile, originalChecksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeFalse())
		})
	})

	Describe("Edge cases", func() {
		It("should handle files with special characters in name", func() {
			specialFile := filepath.Join(tempDir, "file-with-special_chars (123).json")
			err := os.WriteFile(specialFile, []byte("test"), 0644)
			Expect(err).NotTo(HaveOccurred())

			checksum, err := workspace.ComputeChecksum(specialFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(checksum).NotTo(BeEmpty())

			valid, err := workspace.VerifyChecksum(specialFile, checksum)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())
		})

		It("should handle very long file paths", func() {
			// Create nested directory structure
			longPath := tempDir
			for i := 0; i < 10; i++ {
				longPath = filepath.Join(longPath, "nested")
			}
			err := os.MkdirAll(longPath, 0755)
			Expect(err).NotTo(HaveOccurred())

			longFile := filepath.Join(longPath, "file.json")
			err = os.WriteFile(longFile, []byte("test"), 0644)
			Expect(err).NotTo(HaveOccurred())

			checksum, err := workspace.ComputeChecksum(longFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(checksum).NotTo(BeEmpty())
		})

		It("should handle checksums file with Windows line endings", func() {
			checksumFile := filepath.Join(tempDir, "checksums")
			// Use Windows CRLF line endings
			content := "file1.json\tchecksum1\r\nfile2.json\tchecksum2\r\n"
			err := os.WriteFile(checksumFile, []byte(content), 0644)
			Expect(err).NotTo(HaveOccurred())

			read, err := workspace.ReadChecksums(checksumFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(read.Files).To(HaveLen(2))
		})
	})
})
