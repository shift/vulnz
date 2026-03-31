package rpm

import (
	"fmt"
	"unicode"
)

// Validate checks if a version string is a valid RPM format.
// Valid formats:
//   - "version"             (e.g., "1.2.3")
//   - "version-release"     (e.g., "1.2.3-4.el8")
//   - "epoch:version"       (e.g., "2:1.2.3")
//   - "epoch:version-release" (e.g., "2:1.2.3-4.el8")
//
// Returns an error if the version string is invalid.
func Validate(s string) error {
	_, err := Parse(s)
	return err
}

// IsValidEpoch checks if an epoch value is valid.
// Epochs must be non-negative integers.
func IsValidEpoch(epoch int) bool {
	return epoch >= 0
}

// IsValidVersion checks if a version string is valid.
// A valid version string:
//   - Must not be empty
//   - Should contain alphanumeric characters
//   - Can contain dots, hyphens, tildes, carets, and underscores
//
// Note: This performs basic validation. Full validation is done by Parse().
func IsValidVersion(version string) bool {
	if version == "" {
		return false
	}

	// Check if it contains at least one alphanumeric character
	hasAlphaNum := false
	for _, r := range version {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			hasAlphaNum = true
		}
	}

	return hasAlphaNum
}

// ValidateComponents validates epoch, version, and release separately.
// This is useful when constructing versions programmatically.
//
// Returns an error if any component is invalid.
func ValidateComponents(epoch int, version, release string) error {
	if !IsValidEpoch(epoch) {
		return fmt.Errorf("invalid epoch: %d (must be non-negative)", epoch)
	}

	if !IsValidVersion(version) {
		return fmt.Errorf("invalid version: %q (must contain alphanumeric characters)", version)
	}

	// Release is optional, but if provided, should be valid
	if release != "" && !IsValidVersion(release) {
		return fmt.Errorf("invalid release: %q (must contain alphanumeric characters)", release)
	}

	return nil
}

// MustParse parses a version string and panics if it's invalid.
// This is useful for testing and when you're certain the version is valid.
//
// Example:
//
//	v := rpm.MustParse("2:1.2.3-4.el8")
func MustParse(s string) *Version {
	v, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("invalid RPM version %q: %v", s, err))
	}
	return v
}

// New creates a new Version from components.
// It validates the components before creating the version.
//
// Example:
//
//	v, err := rpm.New(2, "1.2.3", "4.el8")
func New(epoch int, version, release string) (*Version, error) {
	if err := ValidateComponents(epoch, version, release); err != nil {
		return nil, err
	}

	return &Version{
		Epoch:   epoch,
		Version: version,
		Release: release,
	}, nil
}

// MustNew creates a new Version from components and panics if invalid.
// This is useful for testing and when you're certain the components are valid.
//
// Example:
//
//	v := rpm.MustNew(2, "1.2.3", "4.el8")
func MustNew(epoch int, version, release string) *Version {
	v, err := New(epoch, version, release)
	if err != nil {
		panic(fmt.Sprintf("invalid RPM version components: %v", err))
	}
	return v
}
