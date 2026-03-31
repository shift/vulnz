// Package schema provides JSON schema validation for vulnerability data.
// It supports multiple schema versions and validates data against registered schemas.
package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Validator validates JSON data against schemas.
// It maintains a cache of compiled schemas for efficient reuse.
type Validator struct {
	compiler *jsonschema.Compiler
	schemas  map[string]*jsonschema.Schema // Schema URL -> compiled schema
	mu       sync.RWMutex
}

// Config for validator initialization.
type Config struct {
	SchemaDir string // Directory containing JSON schemas (optional, uses embedded schemas if empty)
}

// NewValidator creates a new validator instance.
// It initializes the JSON schema compiler and prepares for schema loading.
func NewValidator(config Config) (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	// Set default draft to Draft7 to avoid network requests
	compiler.DefaultDraft(jsonschema.Draft7)

	v := &Validator{
		compiler: compiler,
		schemas:  make(map[string]*jsonschema.Schema),
	}

	return v, nil
}

// Validate validates data against a schema URL.
// The schema must be loaded via LoadSchema or RegisterBuiltinSchemas first.
func (v *Validator) Validate(ctx context.Context, schemaURL string, data interface{}) error {
	v.mu.RLock()
	schema, exists := v.schemas[schemaURL]
	v.mu.RUnlock()

	if !exists {
		return &ValidationError{
			SchemaURL: schemaURL,
			Errors:    []string{fmt.Sprintf("schema not loaded: %s", schemaURL)},
		}
	}

	// Convert data to JSON for validation
	jsonData, err := json.Marshal(data)
	if err != nil {
		return &ValidationError{
			SchemaURL: schemaURL,
			Errors:    []string{fmt.Sprintf("failed to marshal data: %v", err)},
		}
	}

	var v2 interface{}
	if err := json.Unmarshal(jsonData, &v2); err != nil {
		return &ValidationError{
			SchemaURL: schemaURL,
			Errors:    []string{fmt.Sprintf("failed to unmarshal data: %v", err)},
		}
	}

	// Validate against schema
	if err := schema.Validate(v2); err != nil {
		return FormatValidationError(schemaURL, err)
	}

	return nil
}

// ValidateEnvelope validates a storage.Envelope.
// It extracts the schema URL and item data from the envelope and validates the item.
func (v *Validator) ValidateEnvelope(ctx context.Context, envelope interface{}) error {
	// Type assert to get the envelope structure
	env, ok := envelope.(map[string]interface{})
	if !ok {
		// Try to convert via JSON
		jsonData, err := json.Marshal(envelope)
		if err != nil {
			return &ValidationError{
				SchemaURL: "",
				Errors:    []string{fmt.Sprintf("failed to marshal envelope: %v", err)},
			}
		}
		if err := json.Unmarshal(jsonData, &env); err != nil {
			return &ValidationError{
				SchemaURL: "",
				Errors:    []string{fmt.Sprintf("failed to unmarshal envelope: %v", err)},
			}
		}
	}

	schemaURL, ok := env["schema"].(string)
	if !ok {
		return &ValidationError{
			SchemaURL: "",
			Errors:    []string{"envelope missing 'schema' field"},
		}
	}

	item, ok := env["item"]
	if !ok {
		return &ValidationError{
			SchemaURL: schemaURL,
			Errors:    []string{"envelope missing 'item' field"},
		}
	}

	return v.Validate(ctx, schemaURL, item)
}

// LoadSchema loads and compiles a schema from raw JSON data.
// The schema is registered by its URL for future validations.
func (v *Validator) LoadSchema(schemaURL string, schemaData []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Parse the schema JSON
	var schemaObj interface{}
	if err := json.Unmarshal(schemaData, &schemaObj); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	// Add schema to compiler (pass parsed object, not bytes)
	if err := v.compiler.AddResource(schemaURL, schemaObj); err != nil {
		return fmt.Errorf("failed to add schema resource: %w", err)
	}

	// Compile the schema
	schema, err := v.compiler.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("failed to compile schema: %w", err)
	}

	v.schemas[schemaURL] = schema
	return nil
}
