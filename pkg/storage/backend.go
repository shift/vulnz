// Package storage defines the unified storage interface for vulnerability and GRC data.
// This interface is used by both vulnz and enrichment-engine.
package storage

import "context"

// Backend defines the unified storage interface for vulnerability and GRC data.
// It combines operations needed by both vulnz and enrichment-engine.
type Backend interface {
	// Vulnerability operations (from vulnz internal/storage)
	WriteVulnerability(ctx context.Context, id string, record interface{}) error
	ReadVulnerability(ctx context.Context, id string) ([]byte, error)
	ListAllVulnerabilities(ctx context.Context) ([]VulnerabilityRow, error)

	// GRC Control operations (from pkg/storage)
	WriteControl(ctx context.Context, id string, control interface{}) error
	ReadControl(ctx context.Context, id string) ([]byte, error)
	ListAllControls(ctx context.Context) ([]ControlRow, error)
	ListControlsByCWE(ctx context.Context, cwe string) ([]ControlRow, error)
	ListControlsByCPE(ctx context.Context, cpe string) ([]ControlRow, error)
	ListControlsByFramework(ctx context.Context, framework string) ([]ControlRow, error)
	ListControlsByTag(ctx context.Context, tag string) ([]ControlRow, error)

	// Mapping operations
	WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error
	ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error)

	// Lifecycle
	Close(ctx context.Context) error
}

// VulnerabilityRow represents a row from the vulnerabilities table.
type VulnerabilityRow struct {
	ID    string `json:"id"`
	Data  []byte `json:"data"`
}

// ControlRow represents a row from the grc_controls table.
type ControlRow struct {
	ID        string  `json:"id"`
	Framework string  `json:"framework"`
	Data      []byte  `json:"data"`
}

// MappingRow represents a row from the vulnerability_grc_mappings table.
type MappingRow struct {
	VulnerabilityID string  `json:"vulnerability_id"`
	ControlID       string  `json:"control_id"`
	Framework       string  `json:"framework"`
	MappingType     string  `json:"mapping_type"`
	Confidence      float64 `json:"confidence"`
	Evidence        string  `json:"evidence"`
}
