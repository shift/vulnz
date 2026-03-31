package schema

import (
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidationError contains schema validation failures.
// It provides detailed information about what validation rules were violated.
type ValidationError struct {
	SchemaURL string
	Errors    []string
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("validation failed for schema %s", e.SchemaURL)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("validation failed for schema %s:\n", e.SchemaURL))
	for i, err := range e.Errors {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, err))
	}
	return sb.String()
}

// FormatValidationError converts jsonschema error to readable format.
// It extracts all validation errors and returns a structured ValidationError.
func FormatValidationError(schemaURL string, err error) *ValidationError {
	if err == nil {
		return nil
	}

	verr := &ValidationError{
		SchemaURL: schemaURL,
		Errors:    make([]string, 0),
	}

	// Check if it's a validation error from jsonschema
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		verr.Errors = append(verr.Errors, formatSchemaError(ve))

		// Add detailed errors if available
		for _, cause := range ve.Causes {
			verr.Errors = append(verr.Errors, formatSchemaError(cause))
		}
	} else {
		// Generic error
		verr.Errors = append(verr.Errors, err.Error())
	}

	return verr
}

// formatSchemaError formats a single jsonschema validation error.
func formatSchemaError(err *jsonschema.ValidationError) string {
	if err == nil {
		return ""
	}

	// Use the built-in Error() method which provides a formatted message
	return err.Error()
}
