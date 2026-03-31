package schema

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed schemas/*.json
var embeddedSchemas embed.FS

// LoadFromFS loads schemas from a filesystem.
// Returns a map of schema URL to schema JSON data.
func LoadFromFS(fsys fs.FS, path string) (map[string][]byte, error) {
	schemas := make(map[string][]byte)

	err := fs.WalkDir(fsys, path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}

		// Read schema file
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("read schema file %s: %w", p, err)
		}

		// Derive schema URL from filename
		// e.g., "schemas/vulnerability-1.0.3.json" -> schema-1.0.3.json
		filename := filepath.Base(p)
		schemaURL := deriveSchemaURL(filename)
		schemas[schemaURL] = data

		return nil
	})

	if err != nil {
		return nil, err
	}

	return schemas, nil
}

// LoadFromDir loads schemas from a directory on disk.
// Returns a map of schema URL to schema JSON data.
func LoadFromDir(dir string) (map[string][]byte, error) {
	schemas := make(map[string][]byte)

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Read schema file
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open schema file %s: %w", path, err)
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			return fmt.Errorf("read schema file %s: %w", path, err)
		}

		// Derive schema URL from filename
		filename := filepath.Base(path)
		schemaURL := deriveSchemaURL(filename)
		schemas[schemaURL] = data

		return nil
	})

	if err != nil {
		return nil, err
	}

	return schemas, nil
}

// deriveSchemaURL converts a filename to a schema URL.
// e.g., "vulnerability-1.0.3.json" -> "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/schema-1.0.3.json"
func deriveSchemaURL(filename string) string {
	// Extract version using regex: schemaname-X.Y.Z.json
	re := regexp.MustCompile(`^([a-z-]+)-(\d+\.\d+\.\d+)\.json$`)
	matches := re.FindStringSubmatch(filename)

	if len(matches) != 3 {
		// No match, return as-is
		return filename
	}

	// matches[1] is schema name (e.g., "vulnerability")
	// matches[2] is version (e.g., "1.0.3")
	version := matches[2]

	// Construct standard vunnel schema URL
	return fmt.Sprintf(
		"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/schema-%s.json",
		version,
	)
}
