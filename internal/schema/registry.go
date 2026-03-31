package schema

import (
	"fmt"
	"regexp"
)

// Built-in schema URLs for vulnerability data.
const (
	VulnerabilitySchema_1_0_0 = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/schema-1.0.0.json"
	VulnerabilitySchema_1_0_3 = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/schema-1.0.3.json"
)

// RegisterBuiltinSchemas loads all built-in schemas from embedded data.
// This includes vulnerability schema versions 1.0.0 and 1.0.3.
func (v *Validator) RegisterBuiltinSchemas() error {
	// Load schemas from embedded filesystem
	schemas, err := LoadFromFS(embeddedSchemas, "schemas")
	if err != nil {
		return fmt.Errorf("failed to load embedded schemas: %w", err)
	}

	// Register each schema
	for url, data := range schemas {
		if err := v.LoadSchema(url, data); err != nil {
			return fmt.Errorf("failed to load schema %s: %w", url, err)
		}
	}

	return nil
}

// GetSchemaVersion extracts version from schema URL.
// Returns the version string (e.g., "1.0.3") or an error if the URL is invalid.
func GetSchemaVersion(schemaURL string) (string, error) {
	// Match pattern: schema-X.Y.Z.json
	re := regexp.MustCompile(`schema-(\d+\.\d+\.\d+)\.json`)
	matches := re.FindStringSubmatch(schemaURL)
	if len(matches) < 2 {
		return "", fmt.Errorf("invalid schema URL format: %s", schemaURL)
	}
	return matches[1], nil
}
