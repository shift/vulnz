// Package csaf provides utilities for parsing and working with CSAF (Common Security Advisory Framework) documents.
package csaf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gocsaf/csaf/v3/csaf"
)

// Parser wraps gocsaf functionality for parsing CSAF documents.
type Parser struct {
	doc *csaf.Advisory
}

// NewParser creates a new CSAF parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile parses a CSAF JSON file from the given path.
// Returns an error if the file cannot be read or parsed.
func (p *Parser) ParseFile(ctx context.Context, path string) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}

	// Use gocsaf's built-in LoadAdvisory function
	doc, err := csaf.LoadAdvisory(path)
	if err != nil {
		return fmt.Errorf("failed to parse CSAF file: %w", err)
	}

	p.doc = doc
	return nil
}

// ParseBytes parses CSAF JSON from a byte slice.
// Returns an error if the data cannot be parsed.
func (p *Parser) ParseBytes(ctx context.Context, data []byte) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check for empty input
	if len(data) == 0 {
		return fmt.Errorf("empty input data")
	}

	// Parse JSON into Advisory struct
	var doc csaf.Advisory
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse CSAF JSON: %w", err)
	}

	p.doc = &doc
	return nil
}

// GetDocument returns the parsed CSAF advisory.
// Returns nil if no document has been parsed yet.
func (p *Parser) GetDocument() *csaf.Advisory {
	return p.doc
}

// Validate validates the CSAF document against the schema.
// Returns an error if the document is invalid or hasn't been parsed yet.
func (p *Parser) Validate() error {
	if p.doc == nil {
		return fmt.Errorf("no document loaded")
	}

	// Use gocsaf's built-in validation
	if err := p.doc.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	return nil
}
