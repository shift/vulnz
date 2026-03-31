package echo_test

import (
	"testing"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/echo"
)

// TestCompilation is a simple test to verify the package compiles
func TestCompilation(t *testing.T) {
	config := echo.DefaultConfig()
	if config.Namespace != "echo" {
		t.Errorf("expected namespace 'echo', got %s", config.Namespace)
	}
}

// TestProviderRegistration tests that the provider is registered
func TestProviderRegistration(t *testing.T) {
	factory, ok := provider.Get("echo")
	if !ok {
		t.Fatal("echo provider not registered")
	}
	if factory == nil {
		t.Fatal("echo factory is nil")
	}
}
