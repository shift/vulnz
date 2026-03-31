package provider

import (
	"testing"
)

// TestRegister tests provider registration.
func TestRegister(t *testing.T) {
	// Reset registry for clean test
	Reset()

	// Create a test factory
	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	// Test successful registration
	Register("test-provider", testFactory)

	factory, ok := Get("test-provider")
	if !ok {
		t.Fatal("expected provider to be registered")
	}

	if factory == nil {
		t.Error("expected non-nil factory")
	}
}

// TestRegisterDuplicate tests that registering a duplicate provider panics.
func TestRegisterDuplicate(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	Register("duplicate", testFactory)

	// Registering duplicate should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for duplicate registration")
		}
	}()

	Register("duplicate", testFactory)
}

// TestGet tests retrieving registered providers.
func TestGet(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	Register("test1", testFactory)
	Register("test2", testFactory)

	// Test existing provider
	factory, ok := Get("test1")
	if !ok {
		t.Error("expected test1 to be registered")
	}
	if factory == nil {
		t.Error("expected non-nil factory")
	}

	// Test non-existent provider
	_, ok = Get("nonexistent")
	if ok {
		t.Error("expected nonexistent provider to not be found")
	}
}

// TestList tests listing all registered providers.
func TestList(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	// Test empty registry
	if list := List(); len(list) != 0 {
		t.Errorf("expected empty list, got %v", list)
	}

	// Register providers
	Register("zebra", testFactory)
	Register("alpha", testFactory)
	Register("beta", testFactory)

	list := List()

	// Verify count
	if len(list) != 3 {
		t.Errorf("expected 3 providers, got %d", len(list))
	}

	// Verify alphabetical order
	expected := []string{"alpha", "beta", "zebra"}
	for i, name := range expected {
		if list[i] != name {
			t.Errorf("expected list[%d] = %q, got %q", i, name, list[i])
		}
	}
}

// TestCount tests counting registered providers.
func TestCount(t *testing.T) {
	Reset()

	if count := Count(); count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	Register("provider1", testFactory)
	if count := Count(); count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	Register("provider2", testFactory)
	if count := Count(); count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

// TestReset tests resetting the registry.
func TestReset(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	Register("provider1", testFactory)
	Register("provider2", testFactory)

	if count := Count(); count != 2 {
		t.Errorf("expected count 2 before reset, got %d", count)
	}

	Reset()

	if count := Count(); count != 0 {
		t.Errorf("expected count 0 after reset, got %d", count)
	}

	if list := List(); len(list) != 0 {
		t.Errorf("expected empty list after reset, got %v", list)
	}
}

// TestConcurrentRegistration tests thread-safe registration.
func TestConcurrentRegistration(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	// Register providers concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			defer func() {
				// Recover from potential panics in concurrent registration
				recover()
				done <- true
			}()

			name := "provider" + string(rune('0'+n))
			Register(name, testFactory)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify registry is still functional
	list := List()
	if len(list) == 0 {
		t.Error("expected at least one provider to be registered")
	}
}

// TestConcurrentAccess tests thread-safe access to registry.
func TestConcurrentAccess(t *testing.T) {
	Reset()

	testFactory := func(config Config) (Provider, error) {
		return nil, nil
	}

	// Pre-register providers
	for i := 0; i < 5; i++ {
		name := "provider" + string(rune('0'+i))
		Register(name, testFactory)
	}

	// Access registry concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			List()
			Count()
			Get("provider0")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
