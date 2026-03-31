package schema

import (
	"context"
	"testing"
)

func TestValidatorBasic(t *testing.T) {
	ctx := context.Background()

	// Create validator
	validator, err := NewValidator(Config{})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Load built-in schemas
	err = validator.RegisterBuiltinSchemas()
	if err != nil {
		t.Fatalf("Failed to register built-in schemas: %v", err)
	}

	// Test valid data
	validData := map[string]interface{}{
		"Vulnerability": map[string]interface{}{
			"Name":          "CVE-2024-0001",
			"NamespaceName": "test",
		},
		"Name":      "CVE-2024-0001",
		"Namespace": "test",
	}

	err = validator.Validate(ctx, VulnerabilitySchema_1_0_3, validData)
	if err != nil {
		t.Errorf("Valid data failed validation: %v", err)
	}

	// Test invalid data
	invalidData := map[string]interface{}{
		"Vulnerability": map[string]interface{}{
			"Name": "CVE-2024-0002",
			// Missing NamespaceName
		},
		"Name": "CVE-2024-0002",
		// Missing Namespace
	}

	err = validator.Validate(ctx, VulnerabilitySchema_1_0_3, invalidData)
	if err == nil {
		t.Error("Invalid data should have failed validation")
	}
}

func TestGetSchemaVersion(t *testing.T) {
	tests := []struct {
		url     string
		version string
		wantErr bool
	}{
		{
			url:     VulnerabilitySchema_1_0_3,
			version: "1.0.3",
			wantErr: false,
		},
		{
			url:     VulnerabilitySchema_1_0_0,
			version: "1.0.0",
			wantErr: false,
		},
		{
			url:     "invalid-url",
			version: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			version, err := GetSchemaVersion(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSchemaVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if version != tt.version {
				t.Errorf("GetSchemaVersion() = %v, want %v", version, tt.version)
			}
		})
	}
}
