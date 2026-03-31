// Package echo provides a test provider with mock vulnerability data
// for validating the vulnz-go framework integration.
package echo

import (
	"time"

	"github.com/shift/vulnz/internal/provider"
)

// Config holds Echo provider configuration.
type Config struct {
	// Provider is the base provider configuration
	Provider provider.Config

	// URL is the source URL for Echo vulnerability data
	URL string

	// RequestTimeout is the HTTP request timeout
	RequestTimeout time.Duration

	// Namespace is the provider namespace
	Namespace string
}

// DefaultConfig returns the default Echo provider configuration.
func DefaultConfig() Config {
	return Config{
		URL:            "https://advisory.echohq.com/data.json",
		RequestTimeout: 125 * time.Second,
		Namespace:      "echo",
	}
}
