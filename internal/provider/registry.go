package provider

import (
	"fmt"
	"sort"
	"sync"
)

// Factory is a function that creates a provider instance with the given configuration.
// Providers register a factory function during initialization to enable dynamic discovery.
type Factory func(config Config) (Provider, error)

// registry holds all registered provider factories.
var registry = &providerRegistry{
	factories: make(map[string]Factory),
}

// providerRegistry manages provider registration and discovery.
type providerRegistry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// Register registers a provider factory with the given name.
// This should be called from the provider's init() function.
//
// Example:
//
//	func init() {
//	    provider.Register("alpine", NewAlpineProvider)
//	}
//
// Panics if a provider with the same name is already registered.
func Register(name string, factory Factory) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if _, exists := registry.factories[name]; exists {
		panic(fmt.Sprintf("provider %q is already registered", name))
	}

	registry.factories[name] = factory
}

// Get retrieves a provider factory by name.
// Returns an error if the provider is not registered.
func Get(name string) (Factory, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	factory, ok := registry.factories[name]
	return factory, ok
}

// List returns all registered provider names in alphabetical order.
func List() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]string, 0, len(registry.factories))
	for name := range registry.factories {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// Count returns the number of registered providers.
func Count() int {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	return len(registry.factories)
}

// Reset clears all registered providers.
// This is primarily useful for testing.
func Reset() {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.factories = make(map[string]Factory)
}
