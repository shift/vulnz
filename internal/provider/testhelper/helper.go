// Package testhelper provides shared test utilities for provider tests.
//
// This package eliminates the provider.Config setup boilerplate that was
// duplicated across ~45 provider test files (task c643b5a0). Import it in
// any provider test package to get a pre-configured Config and a mock HTTP
// server factory.
package testhelper

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/shift/vulnz/internal/provider"
)

// NewConfig returns a provider.Config suitable for unit tests.
// It creates a temporary directory (cleaned up when t ends) and fills in
// sensible HTTP defaults. Pass the name of the provider under test as name.
func NewConfig(t testing.TB, name string) provider.Config {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", name+"-test-*")
	if err != nil {
		t.Fatalf("testhelper.NewConfig: create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // suppress noise in tests
	}))

	return provider.Config{
		Name:      name,
		Workspace: tmpDir,
		HTTP: provider.HTTPConfig{
			Timeout:      10 * time.Second,
			UserAgent:    "vulnz-go-test/1.0",
			MaxRetries:   3,
			RateLimitRPS: 10,
		},
		Logger: logger,
	}
}

// MockBackend is a minimal HTTP test server that returns a fixed response.
// It wraps httptest.Server to give tests a single place to configure what
// the mock endpoint returns.
type MockBackend struct {
	Server  *httptest.Server
	URL     string
	handler http.HandlerFunc
}

// NewMockBackend starts a new test server that calls handler for every
// incoming request. The server is closed automatically when t ends.
func NewMockBackend(t testing.TB, handler http.HandlerFunc) *MockBackend {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &MockBackend{
		Server:  srv,
		URL:     srv.URL,
		handler: handler,
	}
}

// NewStaticJSONBackend starts a test server that always returns body with
// Content-Type: application/json and a 200 OK status. This covers the
// most common provider test case.
func NewStaticJSONBackend(t testing.TB, body []byte) *MockBackend {
	t.Helper()
	return NewMockBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})
}

// NewErrorBackend starts a test server that always returns the given HTTP
// status code with no body.
func NewErrorBackend(t testing.TB, statusCode int) *MockBackend {
	t.Helper()
	return NewMockBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
	})
}
