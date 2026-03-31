package storage_test

import (
	"context"
	"fmt"
	"log"

	"github.com/shift/vulnz/internal/storage"
)

// ExampleSQLiteBackend demonstrates basic usage of the SQLite backend.
func ExampleSQLiteBackend() {
	ctx := context.Background()

	// Create SQLite backend
	backend, err := storage.New(storage.Config{
		Type:      "sqlite",
		Path:      "data/nvd/results.db",
		BatchSize: 5000,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close(ctx)

	// Write a record
	envelope := &storage.Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "CVE-2023-1234",
		Item: map[string]interface{}{
			"severity":    "HIGH",
			"description": "Buffer overflow vulnerability",
		},
	}
	if err := backend.Write(ctx, envelope); err != nil {
		log.Fatal(err)
	}

	// Read the record
	retrieved, err := backend.Read(ctx, "CVE-2023-1234")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Retrieved: %s\n", retrieved.Identifier)

	// Count all records
	count, err := backend.Count(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Total records: %d\n", count)
}

// ExampleFlatFileBackend demonstrates basic usage of the flat-file backend.
func ExampleFlatFileBackend() {
	ctx := context.Background()

	// Create flat-file backend
	backend, err := storage.New(storage.Config{
		Type: "flat-file",
		Path: "data/alpine/results",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close(ctx)

	// Write a record
	envelope := &storage.Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "alpine:3.18:CVE-2023-1234",
		Item: map[string]interface{}{
			"package":      "openssl",
			"fixedVersion": "3.0.8-r0",
		},
	}
	if err := backend.Write(ctx, envelope); err != nil {
		log.Fatal(err)
	}

	// List all records
	ids, err := backend.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d records\n", len(ids))
}

// ExampleNew demonstrates how to create backends using the factory function.
func ExampleNew() {
	ctx := context.Background()

	// SQLite backend
	sqliteBackend, err := storage.New(storage.Config{
		Type:      "sqlite",
		Path:      "results.db",
		BatchSize: 5000,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sqliteBackend.Close(ctx)

	// Flat-file backend
	flatFileBackend, err := storage.New(storage.Config{
		Type: "flat-file",
		Path: "results/",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer flatFileBackend.Close(ctx)

	fmt.Println("Both backends created successfully")
}

// ExampleBackend_Write shows how to write records with different identifier formats.
func ExampleBackend_Write() {
	ctx := context.Background()
	backend, _ := storage.New(storage.Config{
		Type: "flat-file",
		Path: "results/",
	})
	defer backend.Close(ctx)

	// Simple CVE identifier
	backend.Write(ctx, &storage.Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "CVE-2023-1234",
		Item:       map[string]interface{}{"severity": "HIGH"},
	})

	// Namespace with colon separator
	backend.Write(ctx, &storage.Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "alpine:3.18:CVE-2023-1234",
		Item:       map[string]interface{}{"package": "openssl"},
	})

	// Namespace with path separator
	backend.Write(ctx, &storage.Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "debian/bookworm/CVE-2023-1234",
		Item:       map[string]interface{}{"package": "nginx"},
	})

	fmt.Println("Records written successfully")
}
