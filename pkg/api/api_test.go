package api_test

import (
	"context"
	"testing"

	"github.com/shift/vulnz/pkg/api"
)

// TestIngest_InvalidWorkspace verifies that Ingest returns a non-nil error
// when given a workspace path that does not exist and cannot be created
// (e.g. a path beneath a non-existent root with no write permission).
// Rather than exercising real network calls we verify that an invalid
// workspace path (empty string) is rejected immediately.
func TestIngest_InvalidWorkspace(t *testing.T) {
	err := api.Ingest(context.Background(), api.IngestOptions{
		WorkspacePath: "", // deliberately invalid
	})
	if err == nil {
		t.Fatal("expected non-nil error for empty WorkspacePath, got nil")
	}
}
