package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// Backend is the storage interface for vulnerabilities, GRC controls, and mappings.
type Backend interface {
	WriteVulnerability(ctx context.Context, id string, record interface{}) error
	WriteControl(ctx context.Context, id string, control interface{}) error
	WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error
	ReadVulnerability(ctx context.Context, id string) ([]byte, error)
	ReadControl(ctx context.Context, id string) ([]byte, error)
	ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error)
	Close(ctx context.Context) error
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

// SQLiteBackend implements Backend using SQLite.
type SQLiteBackend struct {
	db       *sql.DB
	path     string
	tempPath string
	mu       sync.Mutex
	closed   bool
}

// NewSQLiteBackend creates a new SQLite backend with GRC tables.
func NewSQLiteBackend(path string) (*SQLiteBackend, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	tempPath := path + ".tmp"
	os.Remove(tempPath)

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	b := &SQLiteBackend{
		db:       db,
		path:     path,
		tempPath: tempPath,
	}

	if err := b.initialize(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	return b, nil
}

func (s *SQLiteBackend) initialize() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA temp_store=MEMORY",
	}
	for _, pragma := range pragmas {
		if _, err := s.db.Exec(pragma); err != nil {
			return fmt.Errorf("execute %s: %w", pragma, err)
		}
	}

	schema := `
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			record BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(id);

		CREATE TABLE IF NOT EXISTS grc_controls (
			id TEXT PRIMARY KEY,
			framework TEXT NOT NULL,
			control_id TEXT NOT NULL,
			title TEXT NOT NULL,
			family TEXT,
			description TEXT,
			related_cwes TEXT,
			related_cves TEXT,
			record BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_grc_framework ON grc_controls(framework);
		CREATE INDEX IF NOT EXISTS idx_grc_control_id ON grc_controls(control_id);

		CREATE TABLE IF NOT EXISTS vulnerability_grc_mappings (
			vulnerability_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			framework TEXT NOT NULL,
			mapping_type TEXT NOT NULL,
			confidence REAL NOT NULL,
			evidence TEXT,
			PRIMARY KEY (vulnerability_id, control_id, framework)
		);
		CREATE INDEX IF NOT EXISTS idx_mapping_vuln ON vulnerability_grc_mappings(vulnerability_id);
		CREATE INDEX IF NOT EXISTS idx_mapping_control ON vulnerability_grc_mappings(control_id);
		CREATE INDEX IF NOT EXISTS idx_mapping_framework ON vulnerability_grc_mappings(framework);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	return nil
}

func (s *SQLiteBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	_, err = s.db.ExecContext(ctx, "INSERT OR REPLACE INTO vulnerabilities (id, record) VALUES (?, ?)", id, data)
	if err != nil {
		return fmt.Errorf("insert vulnerability %s: %w", id, err)
	}
	return nil
}

func (s *SQLiteBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(control)
	if err != nil {
		return fmt.Errorf("marshal control: %w", err)
	}

	_, err = s.db.ExecContext(ctx, "INSERT OR REPLACE INTO grc_controls (id, framework, control_id, title, family, description, record) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, id, id, id, "", "", data)
	if err != nil {
		return fmt.Errorf("insert control %s: %w", id, err)
	}
	return nil
}

func (s *SQLiteBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO vulnerability_grc_mappings (vulnerability_id, control_id, framework, mapping_type, confidence, evidence)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		vulnID, controlID, framework, mappingType, confidence, evidence)
	if err != nil {
		return fmt.Errorf("insert mapping %s -> %s: %w", vulnID, controlID, err)
	}
	return nil
}

func (s *SQLiteBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM vulnerabilities WHERE id = ?", id).Scan(&data)
	if err != nil {
		return nil, fmt.Errorf("read vulnerability %s: %w", id, err)
	}
	return data, nil
}

func (s *SQLiteBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM grc_controls WHERE id = ?", id).Scan(&data)
	if err != nil {
		return nil, fmt.Errorf("read control %s: %w", id, err)
	}
	return data, nil
}

func (s *SQLiteBackend) ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT vulnerability_id, control_id, framework, mapping_type, confidence, evidence FROM vulnerability_grc_mappings WHERE vulnerability_id = ?",
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("query mappings for %s: %w", vulnID, err)
	}
	defer rows.Close()

	var mappings []MappingRow
	for rows.Next() {
		var m MappingRow
		if err := rows.Scan(&m.VulnerabilityID, &m.ControlID, &m.Framework, &m.MappingType, &m.Confidence, &m.Evidence); err != nil {
			return nil, fmt.Errorf("scan mapping row: %w", err)
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func (s *SQLiteBackend) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint wal: %w", err)
	}

	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		os.Remove(s.tempPath + suffix)
	}

	if _, err := os.Stat(s.tempPath); err == nil {
		if err := os.Rename(s.tempPath, s.path); err != nil {
			return fmt.Errorf("move database: %w", err)
		}
	}

	return nil
}
