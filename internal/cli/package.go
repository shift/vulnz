package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/vulnz/internal/storage"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

var (
	pkgWorkspace string
	pkgOutput    string
	pkgBatchSize int
)

var packageCmd = &cobra.Command{
	Use:   "package",
	Short: "Package vulnerability data into a single shippable SQLite database",
	Long: `Package reads all provider flat-file storage directories under the workspace
and writes every vulnerability record into a single compacted SQLite database
suitable for distribution to customers.

The output database is WAL-checkpointed, vacuumed, and closed before writing
to disk, producing a single self-contained .sqlite file with no sidecar files.`,
	RunE: runPackage,
}

func init() {
	packageCmd.Flags().StringVarP(&pkgWorkspace, "workspace", "w", "./data", "workspace root directory containing provider data")
	packageCmd.Flags().StringVarP(&pkgOutput, "output", "o", "./vulnz.sqlite", "output SQLite database file path")
	packageCmd.Flags().IntVar(&pkgBatchSize, "batch-size", 1000, "SQLite write batch size")

	rootCmd.AddCommand(packageCmd)
}

func runPackage(cmd *cobra.Command, args []string) error {
	storageRoot := pkgWorkspace
	if _, err := os.Stat(storageRoot); os.IsNotExist(err) {
		return fmt.Errorf("no data found at %s — run providers first", storageRoot)
	}

	outputPath := pkgOutput
	outputDir := filepath.Dir(outputPath)
	if err := storage.EnsureDir(outputDir); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
		printWarning("could not remove existing output: %v", err)
	}

	// Collect all JSON envelope files across all providers
	var files []string
	err := filepath.Walk(storageRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		// Only include files under a "storage" directory
		rel, err := filepath.Rel(storageRoot, path)
		if err != nil {
			return nil
		}
		if !strings.Contains(rel, string(os.PathSeparator)+"storage"+string(os.PathSeparator)) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan storage directories: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no JSON records found under %s", storageRoot)
	}

	printInfo("Found %d vulnerability records across %s", len(files), storageRoot)

	// Open SQLite database
	db, err := sql.Open("sqlite3", outputPath)
	if err != nil {
		return fmt.Errorf("open output database: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Configure for bulk import
	pragmas := []string{
		"PRAGMA journal_mode=OFF",
		"PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-256000",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA locking_mode=EXCLUSIVE",
		"PRAGMA page_size=4096",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("execute %s: %w", p, err)
		}
	}

	// Create schema
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		record BLOB NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, "INSERT INTO vulnerabilities (id, record) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	var count int
	for i, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			printWarning("skipped %s: %v", filePath, err)
			continue
		}

		var envelope storage.Envelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			printWarning("skipped %s: invalid JSON: %v", filePath, err)
			continue
		}

		recordJSON, err := json.Marshal(envelope)
		if err != nil {
			printWarning("skipped %s: marshal error: %v", envelope.Identifier, err)
			continue
		}

		if _, err := stmt.ExecContext(ctx, envelope.Identifier, recordJSON); err != nil {
			printWarning("skipped %s: insert error: %v", envelope.Identifier, err)
			continue
		}
		count++

		if (i+1)%pkgBatchSize == 0 {
			if err := stmt.Close(); err != nil {
				return fmt.Errorf("close statement: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit batch: %w", err)
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("begin transaction: %w", err)
			}
			stmt, err = tx.PrepareContext(ctx, "INSERT INTO vulnerabilities (id, record) VALUES (?, ?)")
			if err != nil {
				return fmt.Errorf("prepare statement: %w", err)
			}
		}
	}

	// Final commit
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit final batch: %w", err)
	}

	printInfo("Inserted %d records", count)

	// Create index
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_id ON vulnerabilities(id)"); err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	// VACUUM to compact
	printInfo("Compacting database...")
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}

	db.Close()

	// Report final size
	info, _ := os.Stat(outputPath)
	if info != nil {
		sizeMB := float64(info.Size()) / (1024 * 1024)
		printSuccess("Packaged %d records into %s (%.1f MB)", count, outputPath, sizeMB)
	} else {
		printSuccess("Packaged %d records into %s", count, outputPath)
	}

	return nil
}
