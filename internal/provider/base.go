package provider

import (
	"log/slog"
)

// Base provides common functionality for providers.
// Providers can embed Base to get access to configuration, logging, and workspace management.
//
// Example usage:
//
//	type AlpineProvider struct {
//	    *provider.Base
//	    // alpine-specific fields
//	}
//
//	func NewAlpineProvider(config provider.Config) (*AlpineProvider, error) {
//	    return &AlpineProvider{
//	        Base: provider.NewBase(config),
//	    }, nil
//	}
type Base struct {
	config Config
}

// NewBase creates a new Base instance with the given configuration.
func NewBase(config Config) *Base {
	return &Base{config: config}
}

// Config returns the provider configuration.
func (b *Base) Config() Config {
	return b.config
}

// Logger returns the logger instance for this provider.
func (b *Base) Logger() *slog.Logger {
	return b.config.Logger
}

// Workspace returns the workspace root directory for this provider.
func (b *Base) Workspace() string {
	return b.config.Workspace
}

// Name returns the provider name from configuration.
func (b *Base) Name() string {
	return b.config.Name
}
