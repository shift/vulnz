package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SQLiteBackend stores vulnerability data in a SQLite database.
// It uses WAL mode for concurrent reads and batch inserts for performance.
type SQLiteBackend struct {
	db        *sql.DB
	dbPath    string
	tempPath  string
	batch     []*Envelope
	batchSize int
	mu        sync.Mutex
	closed    bool
}

// NewSQLiteBackend creates a new SQLite storage backend.
// If the final database path already exists, it is opened directly.
// Otherwise, a temporary database is created and moved to the final path on Close.
// WAL mode is enabled for concurrent read access.
func NewSQLiteBackend(path string, batchSize int) (*SQLiteBackend, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// Clean up orphaned files from previous killed executions
	cleanupOrphanedFiles(dir)

	var dbPath, tempPath string
	if fileExists(path) {
		// Final database exists from a previous Close — open it directly
		dbPath = path
	} else {
		// Fresh start — write to temp, move to final on Close
		tempPath = path + ".tmp"
		if fileExists(tempPath) {
			if err := os.Remove(tempPath); err != nil {
				return nil, fmt.Errorf("remove existing temp database: %w", err)
			}
		}
		dbPath = tempPath
	}

	// Open database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool for single writer
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	backend := &SQLiteBackend{
		db:        db,
		dbPath:    path,
		tempPath:  tempPath,
		batch:     make([]*Envelope, 0, batchSize),
		batchSize: batchSize,
	}

	// Initialize database schema
	if err := backend.initialize(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	return backend, nil
}

// initialize sets up the database schema and configuration.
func (s *SQLiteBackend) initialize() error {
	// Enable WAL mode for concurrent reads
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA wal_autocheckpoint=10000",
	}

	for _, pragma := range pragmas {
		if _, err := s.db.Exec(pragma); err != nil {
			return fmt.Errorf("execute %s: %w", pragma, err)
		}
	}

	// Create vulnerabilities table
	schema := `
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			record BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_id ON vulnerabilities(id);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	return nil
}

// Write stores a vulnerability record.
// Records are accumulated in a batch and committed when the batch size is reached.
func (s *SQLiteBackend) Write(ctx context.Context, envelope *Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("backend is closed")
	}

	// Add to batch
	s.batch = append(s.batch, envelope)

	// Auto-flush when batch size reached
	if len(s.batch) >= s.batchSize {
		return s.flushBatchLocked(ctx)
	}

	return nil
}

// flushBatchLocked commits the current batch to the database.
// Caller must hold s.mu.
func (s *SQLiteBackend) flushBatchLocked(ctx context.Context) error {
	if len(s.batch) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, "INSERT OR REPLACE INTO vulnerabilities (id, record) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, envelope := range s.batch {
		recordJSON, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("marshal envelope %s: %w", envelope.Identifier, err)
		}

		if _, err := stmt.ExecContext(ctx, envelope.Identifier, recordJSON); err != nil {
			return fmt.Errorf("insert record %s: %w", envelope.Identifier, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	// Clear batch
	s.batch = s.batch[:0]

	return nil
}

// Read retrieves a vulnerability record by ID.
func (s *SQLiteBackend) Read(ctx context.Context, id string) (*Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.flushBatchLocked(ctx); err != nil {
		return nil, err
	}

	var recordJSON []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM vulnerabilities WHERE id = ?", id).Scan(&recordJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("record not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("query record: %w", err)
	}

	var envelope Envelope
	if err := json.Unmarshal(recordJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}

	return &envelope, nil
}

// List returns all vulnerability IDs.
func (s *SQLiteBackend) List(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.flushBatchLocked(ctx); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT id FROM vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("query ids: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return ids, nil
}

// Count returns the total number of records.
func (s *SQLiteBackend) Count(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.flushBatchLocked(ctx); err != nil {
		return 0, err
	}

	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count records: %w", err)
	}

	return count, nil
}

// Close finalizes storage by flushing any remaining batch and moving the database to its final location.
func (s *SQLiteBackend) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	// Flush remaining batch
	if err := s.flushBatchLocked(ctx); err != nil {
		return fmt.Errorf("flush batch: %w", err)
	}

	// Checkpoint WAL to fold all data into main DB file
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint wal: %w", err)
	}

	// Close database
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	// Remove WAL sidecar files
	s.removeWALSidecarFiles(s.tempPath)

	// Move temp database to final location
	if fileExists(s.tempPath) {
		if err := os.Rename(s.tempPath, s.dbPath); err != nil {
			return fmt.Errorf("move database to final location: %w", err)
		}
	}

	return nil
}

// removeWALSidecarFiles removes WAL sidecar files (-wal and -shm).
func (s *SQLiteBackend) removeWALSidecarFiles(dbPath string) {
	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := dbPath + suffix
		if fileExists(sidecar) {
			os.Remove(sidecar)
		}
	}
}

// cleanupOrphanedFiles removes temporary SQLite files left by killed executions.
func cleanupOrphanedFiles(dir string) {
	patterns := []string{
		filepath.Join(dir, "*.tmp"),
		filepath.Join(dir, "*.tmp-wal"),
		filepath.Join(dir, "*.tmp-shm"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			os.Remove(match)
		}
	}
}
