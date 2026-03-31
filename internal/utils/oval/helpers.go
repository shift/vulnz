package oval

import (
	"regexp"
	"strings"

	govalParser "github.com/quay/goval-parser/oval"
)

var (
	// packageNameRegex extracts package names from comments and descriptions
	packageNameRegex = regexp.MustCompile(`(?:^|\s)([a-zA-Z0-9_+-]+)(?:\s|$|:|-is-|<|>|=)`)
)

// ExtractCVEs extracts all CVE IDs from an OVAL definition.
// It searches through references to find CVE entries.
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	cves := oval.ExtractCVEs(def)
//	fmt.Printf("CVEs: %v\n", cves) // Output: CVEs: [CVE-2023-1234]
func ExtractCVEs(def *govalParser.Definition) []string {
	if def == nil {
		return []string{}
	}

	cves := make([]string, 0)
	for _, ref := range def.References {
		if strings.ToLower(ref.Source) == "cve" && ref.RefID != "" {
			cves = append(cves, ref.RefID)
		}
	}

	return cves
}

// ExtractPackages extracts affected package names from an OVAL definition.
// It analyzes the criteria comments to identify package names.
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	packages := oval.ExtractPackages(def)
//	fmt.Printf("Packages: %v\n", packages) // Output: Packages: [openssl openssl-devel]
func ExtractPackages(def *govalParser.Definition) []string {
	if def == nil {
		return []string{}
	}

	packageSet := make(map[string]struct{})
	extractPackagesFromCriteria(&def.Criteria, packageSet)

	// Convert set to slice
	packages := make([]string, 0, len(packageSet))
	for pkg := range packageSet {
		packages = append(packages, pkg)
	}

	return packages
}

// extractPackagesFromCriteria recursively extracts package names from criteria comments.
func extractPackagesFromCriteria(criteria *govalParser.Criteria, packageSet map[string]struct{}) {
	if criteria == nil {
		return
	}

	// Extract from criterion comments
	for _, criterion := range criteria.Criterions {
		extractPackagesFromComment(criterion.Comment, packageSet)
	}

	// Recurse into nested criteria
	for i := range criteria.Criterias {
		extractPackagesFromCriteria(&criteria.Criterias[i], packageSet)
	}
}

// extractPackagesFromComment extracts package names from a criterion comment.
// Common patterns:
// - "openssl is earlier than 1.1.1k-7"
// - "package openssl-devel is installed"
// - "openssl-libs < 1.1.1k"
func extractPackagesFromComment(comment string, packageSet map[string]struct{}) {
	if comment == "" {
		return
	}

	// Common keywords to look for
	keywords := []string{
		"is earlier than",
		"is installed",
		"is signed with",
		"<",
		">",
		"=",
		"version",
	}

	// Check if comment contains package-related keywords
	hasKeyword := false
	for _, keyword := range keywords {
		if strings.Contains(comment, keyword) {
			hasKeyword = true
			break
		}
	}

	if !hasKeyword {
		return
	}

	// Extract potential package names
	// Split by common delimiters and extract first valid-looking package name
	words := strings.Fields(comment)
	for _, word := range words {
		// Clean up the word
		word = strings.TrimSpace(word)
		word = strings.Trim(word, "(),[]{}\"'")

		// Skip common non-package words
		if isCommonWord(word) {
			continue
		}

		// Check if it looks like a package name (contains alphanumeric, dash, underscore, plus)
		if isValidPackageName(word) {
			packageSet[word] = struct{}{}
		}
	}
}

// isCommonWord checks if a word is a common non-package word.
func isCommonWord(word string) bool {
	commonWords := map[string]bool{
		"is": true, "are": true, "the": true, "a": true, "an": true,
		"earlier": true, "than": true, "installed": true, "signed": true,
		"with": true, "key": true, "version": true, "gpg": true,
		"less": true, "greater": true, "equal": true, "to": true,
		"or": true, "and": true, "not": true,
	}
	return commonWords[strings.ToLower(word)]
}

// isValidPackageName checks if a string looks like a valid package name.
func isValidPackageName(name string) bool {
	if len(name) == 0 || len(name) > 200 {
		return false
	}

	// Package names typically contain letters, numbers, dashes, underscores, plus
	// and don't start with special characters
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_+.-]*$`).MatchString(name) {
		return false
	}

	// Skip version-like strings
	if regexp.MustCompile(`^\d+[\d.:-]+$`).MatchString(name) {
		return false
	}

	// Skip hash-like strings
	if len(name) > 20 && regexp.MustCompile(`^[a-f0-9]+$`).MatchString(name) {
		return false
	}

	return true
}

// GetSeverity extracts the severity level from an OVAL definition.
// Returns the severity string if found, or "Unknown" if not specified.
//
// Common severity values:
// - Critical
// - Important / High
// - Moderate / Medium
// - Low
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	severity := oval.GetSeverity(def)
//	fmt.Printf("Severity: %s\n", severity) // Output: Severity: Important
func GetSeverity(def *govalParser.Definition) string {
	if def == nil {
		return "Unknown"
	}

	// Try to get severity from advisory
	if def.Advisory.Severity != "" {
		return NormalizeSeverity(def.Advisory.Severity)
	}

	// Some OVAL files store severity in description or title
	if strings.Contains(strings.ToLower(def.Description), "critical") {
		return "Critical"
	}
	if strings.Contains(strings.ToLower(def.Title), "critical") {
		return "Critical"
	}

	return "Unknown"
}

// NormalizeSeverity normalizes severity values to standard levels.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "important", "high":
		return "Important"
	case "moderate", "medium":
		return "Moderate"
	case "low":
		return "Low"
	default:
		return severity
	}
}

// GetFamily extracts the operating system family from an OVAL definition.
// Returns the family string if found, or "unknown" if not specified.
//
// Common family values:
// - unix
// - linux
// - windows
// - macos
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	family := oval.GetFamily(def)
//	fmt.Printf("Family: %s\n", family) // Output: Family: unix
func GetFamily(def *govalParser.Definition) string {
	if def == nil {
		return "unknown"
	}

	// Try to get family from affected platforms
	if def.Affecteds != nil && len(def.Affecteds) > 0 {
		for _, affected := range def.Affecteds {
			if affected.Family != "" {
				return affected.Family
			}
		}
	}

	// Try to infer from ID or platform
	if strings.Contains(strings.ToLower(def.ID), "windows") {
		return "windows"
	}
	if strings.Contains(strings.ToLower(def.ID), "macos") || strings.Contains(strings.ToLower(def.ID), "osx") {
		return "macos"
	}

	// Default to unix for Linux distributions
	if strings.Contains(strings.ToLower(def.ID), "redhat") ||
		strings.Contains(strings.ToLower(def.ID), "ubuntu") ||
		strings.Contains(strings.ToLower(def.ID), "debian") ||
		strings.Contains(strings.ToLower(def.ID), "suse") {
		return "unix"
	}

	return "unknown"
}

// GetPlatforms extracts all platform names from an OVAL definition.
// Returns a list of platform names that the definition applies to.
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	platforms := oval.GetPlatforms(def)
//	fmt.Printf("Platforms: %v\n", platforms)
//	// Output: Platforms: [Red Hat Enterprise Linux 8]
func GetPlatforms(def *govalParser.Definition) []string {
	if def == nil {
		return []string{}
	}

	platforms := make([]string, 0)
	if def.Affecteds != nil {
		for _, affected := range def.Affecteds {
			for _, platform := range affected.Platforms {
				if platform != "" {
					platforms = append(platforms, platform)
				}
			}
		}
	}

	return platforms
}

// GetAdvisoryID extracts the primary advisory ID from an OVAL definition.
// This is typically the RHSA, USN, DSA, or similar advisory identifier.
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	advisory := oval.GetAdvisoryID(def)
//	fmt.Printf("Advisory: %s\n", advisory) // Output: Advisory: RHSA-2023:0001
func GetAdvisoryID(def *govalParser.Definition) string {
	if def == nil {
		return ""
	}

	// Look for advisory-specific references
	advisorySources := []string{"rhsa", "rhba", "rhea", "usn", "dsa", "dla"}

	for _, ref := range def.References {
		refSourceLower := strings.ToLower(ref.Source)
		for _, source := range advisorySources {
			if refSourceLower == source && ref.RefID != "" {
				return ref.RefID
			}
		}
	}

	return ""
}
