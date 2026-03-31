// Package rpm provides RPM version comparison utilities for vulnerability matching.
// It implements RPM's version ordering algorithm for comparing package versions
// across RHEL, Fedora, CentOS, SUSE, Oracle Linux, and other RPM-based distributions.
package rpm

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents an RPM package version with epoch, version, and release components.
// RPM versions follow the format: [epoch:]version[-release]
//
// Examples:
//   - "1.2.3-4.el8"        -> epoch=0, version="1.2.3", release="4.el8"
//   - "2:1.1.1k-7.el8_6"   -> epoch=2, version="1.1.1k", release="7.el8_6"
//   - "1.0"                -> epoch=0, version="1.0", release=""
type Version struct {
	Epoch   int    // Epoch number, defaults to 0 if not specified
	Version string // Main version string (required)
	Release string // Release string (optional)
}

// Parse parses an RPM version string into a Version struct.
// It handles the format: [epoch:]version[-release]
//
// Examples:
//   - Parse("1.2.3-4.el8")      -> &Version{0, "1.2.3", "4.el8"}
//   - Parse("2:1.0-1")          -> &Version{2, "1.0", "1"}
//   - Parse("1.0")              -> &Version{0, "1.0", ""}
//
// Returns an error if the version string is invalid or if the epoch
// cannot be parsed as an integer.
func Parse(s string) (*Version, error) {
	if s == "" {
		return nil, fmt.Errorf("empty version string")
	}

	v := &Version{
		Epoch: 0,
	}

	// Split by epoch separator ':'
	epochParts := strings.SplitN(s, ":", 2)
	var versionRelease string

	if len(epochParts) == 2 {
		// Epoch is present
		epoch, err := strconv.Atoi(epochParts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid epoch '%s': %w", epochParts[0], err)
		}
		if epoch < 0 {
			return nil, fmt.Errorf("epoch cannot be negative: %d", epoch)
		}
		v.Epoch = epoch
		versionRelease = epochParts[1]
	} else {
		versionRelease = s
	}

	// Split by release separator '-' (rightmost occurrence)
	// We need to be careful here - version can contain dashes too
	// So we split from the right and take the last part as release
	releaseParts := strings.Split(versionRelease, "-")

	if len(releaseParts) == 1 {
		// No release part
		v.Version = releaseParts[0]
		v.Release = ""
	} else {
		// Join all but last part as version, last part is release
		v.Release = releaseParts[len(releaseParts)-1]
		v.Version = strings.Join(releaseParts[:len(releaseParts)-1], "-")
	}

	if v.Version == "" {
		return nil, fmt.Errorf("version part cannot be empty")
	}

	return v, nil
}

// String returns the string representation of the Version.
// It formats the version in RPM format: [epoch:]version[-release]
//
// Examples:
//   - Version{0, "1.2.3", "4.el8"}.String()    -> "1.2.3-4.el8"
//   - Version{2, "1.0", "1"}.String()          -> "2:1.0-1"
//   - Version{0, "1.0", ""}.String()           -> "1.0"
func (v *Version) String() string {
	var sb strings.Builder

	// Add epoch if non-zero
	if v.Epoch != 0 {
		sb.WriteString(strconv.Itoa(v.Epoch))
		sb.WriteString(":")
	}

	// Add version (always present)
	sb.WriteString(v.Version)

	// Add release if present
	if v.Release != "" {
		sb.WriteString("-")
		sb.WriteString(v.Release)
	}

	return sb.String()
}

// Compare compares two RPM versions according to RPM's version ordering algorithm.
// It returns:
//   - -1 if v < other
//   - 0 if v == other
//   - 1 if v > other
//
// Comparison order:
//  1. Compare epochs (higher epoch wins)
//  2. Compare version strings using RPM algorithm
//  3. Compare release strings using RPM algorithm
//
// Example:
//
//	v1, _ := Parse("2:1.0-1")
//	v2, _ := Parse("1:9999-999")
//	v1.Compare(v2) // Returns 1 (epoch 2 > epoch 1)
func (v *Version) Compare(other *Version) int {
	if v == nil && other == nil {
		return 0
	}
	if v == nil {
		return -1
	}
	if other == nil {
		return 1
	}

	// 1. Compare epochs first
	if v.Epoch > other.Epoch {
		return 1
	}
	if v.Epoch < other.Epoch {
		return -1
	}

	// 2. Compare version strings
	cmpResult := compareVersionParts(v.Version, other.Version)
	if cmpResult != 0 {
		return cmpResult
	}

	// 3. Compare release strings
	return compareVersionParts(v.Release, other.Release)
}

// Less returns true if v < other.
// This is a convenience method for Compare(other) < 0.
func (v *Version) Less(other *Version) bool {
	return v.Compare(other) < 0
}

// Equal returns true if v == other.
// This is a convenience method for Compare(other) == 0.
func (v *Version) Equal(other *Version) bool {
	return v.Compare(other) == 0
}

// Greater returns true if v > other.
// This is a convenience method for Compare(other) > 0.
func (v *Version) Greater(other *Version) bool {
	return v.Compare(other) > 0
}
