// Package oval provides utilities for parsing OVAL (Open Vulnerability and Assessment Language) XML files.
// It wraps the goval-parser library and provides simplified interfaces for common operations.
package oval

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	govalParser "github.com/quay/goval-parser/oval"
)

// Parser wraps goval-parser functionality for parsing OVAL XML files.
// It maintains an in-memory collection of parsed definitions for efficient querying.
type Parser struct {
	definitions map[string]*govalParser.Definition
}

// NewParser creates a new OVAL parser instance.
// Returns a parser ready to parse OVAL XML files or bytes.
func NewParser() *Parser {
	return &Parser{
		definitions: make(map[string]*govalParser.Definition),
	}
}

// ParseFile parses an OVAL XML file from the given path.
// The context can be used to cancel long-running parse operations.
//
// Example:
//
//	parser := oval.NewParser()
//	if err := parser.ParseFile(ctx, "rhel-8.oval.xml"); err != nil {
//	    log.Fatal(err)
//	}
func (p *Parser) ParseFile(ctx context.Context, path string) error {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse the bytes
	return p.ParseBytes(ctx, data)
}

// ParseBytes parses OVAL XML from byte slice.
// The context can be used to cancel long-running parse operations.
//
// Example:
//
//	parser := oval.NewParser()
//	data, _ := os.ReadFile("oval.xml")
//	if err := parser.ParseBytes(ctx, data); err != nil {
//	    log.Fatal(err)
//	}
func (p *Parser) ParseBytes(ctx context.Context, data []byte) error {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("empty input data")
	}

	// Parse using goval-parser
	var root govalParser.Root
	if err := xml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("failed to parse OVAL XML: %w", err)
	}

	// Store definitions by ID
	for i := range root.Definitions.Definitions {
		def := &root.Definitions.Definitions[i]
		p.definitions[def.ID] = def
	}

	return nil
}

// GetDefinition retrieves an OVAL definition by its ID.
// Returns the definition and true if found, nil and false otherwise.
//
// Example:
//
//	if def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001"); ok {
//	    fmt.Printf("Found: %s\n", def.Title)
//	}
func (p *Parser) GetDefinition(id string) (*govalParser.Definition, bool) {
	def, ok := p.definitions[id]
	return def, ok
}

// GetDefinitions returns all parsed OVAL definitions.
// The returned slice contains pointers to the original definitions.
//
// Example:
//
//	defs := parser.GetDefinitions()
//	fmt.Printf("Parsed %d definitions\n", len(defs))
func (p *Parser) GetDefinitions() []*govalParser.Definition {
	result := make([]*govalParser.Definition, 0, len(p.definitions))
	for _, def := range p.definitions {
		result = append(result, def)
	}
	return result
}

// FilterBySeverity filters definitions by severity level.
// Severity matching is case-insensitive and supports common values:
// - Critical
// - Important / High
// - Moderate / Medium
// - Low
//
// Example:
//
//	critical := parser.FilterBySeverity("Critical")
//	for _, def := range critical {
//	    fmt.Printf("Critical issue: %s\n", def.Title)
//	}
func (p *Parser) FilterBySeverity(severity string) []*govalParser.Definition {
	result := make([]*govalParser.Definition, 0)
	severityLower := strings.ToLower(severity)

	for _, def := range p.definitions {
		defSeverity := GetSeverity(def)
		if strings.ToLower(defSeverity) == severityLower {
			result = append(result, def)
		}
	}

	return result
}

// FilterByFamily filters definitions by operating system family.
// Family matching is case-insensitive and supports common values:
// - unix (matches all Unix-like systems)
// - linux
// - windows
// - macos
//
// The function checks the platform family field in the definition metadata.
//
// Example:
//
//	rhel := parser.FilterByFamily("unix")
//	fmt.Printf("Found %d Unix definitions\n", len(rhel))
func (p *Parser) FilterByFamily(family string) []*govalParser.Definition {
	result := make([]*govalParser.Definition, 0)
	familyLower := strings.ToLower(family)

	for _, def := range p.definitions {
		defFamily := GetFamily(def)
		if strings.ToLower(defFamily) == familyLower {
			result = append(result, def)
		}
	}

	return result
}
