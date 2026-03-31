// Example demonstrating how to use the OVAL parser
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/shift/vulnz/internal/utils/oval"
)

func main() {
	// Create a new OVAL parser
	parser := oval.NewParser()
	ctx := context.Background()

	// Example 1: Parse an OVAL file
	fmt.Println("=== Example 1: Parsing OVAL File ===")
	err := parser.ParseFile(ctx, "rhel-8.oval.xml")
	if err != nil {
		log.Printf("Note: File may not exist in this location: %v\n", err)
		// For demonstration, let's continue with other examples
	} else {
		fmt.Printf("Successfully parsed OVAL file\n")
	}

	// Example 2: Parse OVAL from bytes
	fmt.Println("\n=== Example 2: Parsing OVAL from Bytes ===")
	_, err = os.ReadFile("rhel-8.oval.xml")
	if err == nil {
		parser2 := oval.NewParser()
		err = parser2.ParseFile(ctx, "rhel-8.oval.xml")
		if err != nil {
			log.Printf("Parse error: %v\n", err)
		} else {
			fmt.Printf("Parsed %d definitions\n", len(parser2.GetDefinitions()))
		}
	}

	// Example 3: Get all definitions
	fmt.Println("\n=== Example 3: Retrieving Definitions ===")
	defs := parser.GetDefinitions()
	fmt.Printf("Total definitions: %d\n", len(defs))

	// Example 4: Get a specific definition
	fmt.Println("\n=== Example 4: Get Definition by ID ===")
	def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
	if ok {
		fmt.Printf("Found definition: %s\n", def.Title)
	} else {
		fmt.Println("Definition not found")
	}

	// Example 5: Filter by severity
	fmt.Println("\n=== Example 5: Filter by Severity ===")
	critical := parser.FilterBySeverity("Critical")
	fmt.Printf("Critical definitions: %d\n", len(critical))

	important := parser.FilterBySeverity("Important")
	fmt.Printf("Important definitions: %d\n", len(important))

	// Example 6: Filter by OS family
	fmt.Println("\n=== Example 6: Filter by OS Family ===")
	unix := parser.FilterByFamily("unix")
	fmt.Printf("Unix family definitions: %d\n", len(unix))

	// Example 7: Extract CVEs from definitions
	fmt.Println("\n=== Example 7: Extract CVEs ===")
	for _, def := range defs {
		cves := oval.ExtractCVEs(def)
		if len(cves) > 0 {
			fmt.Printf("%s has CVEs: %v\n", def.ID, cves)
		}
	}

	// Example 8: Extract affected packages
	fmt.Println("\n=== Example 8: Extract Affected Packages ===")
	for _, def := range defs {
		packages := oval.ExtractPackages(def)
		if len(packages) > 0 {
			fmt.Printf("%s affects packages: %v\n", def.ID, packages)
		}
	}

	// Example 9: Get metadata from definitions
	fmt.Println("\n=== Example 9: Get Metadata ===")
	for _, def := range defs {
		severity := oval.GetSeverity(def)
		family := oval.GetFamily(def)
		platforms := oval.GetPlatforms(def)
		advisory := oval.GetAdvisoryID(def)

		fmt.Printf("\nDefinition: %s\n", def.ID)
		fmt.Printf("  Severity: %s\n", severity)
		fmt.Printf("  Family: %s\n", family)
		fmt.Printf("  Platforms: %v\n", platforms)
		if advisory != "" {
			fmt.Printf("  Advisory: %s\n", advisory)
		}
	}

	// Example 10: Simplify definitions
	fmt.Println("\n=== Example 10: Simplify Definitions ===")
	for _, def := range defs {
		simplified := oval.Simplify(def)
		if simplified != nil {
			fmt.Printf("\nSimplified %s:\n", simplified.ID)
			fmt.Printf("  Title: %s\n", simplified.Title)
			fmt.Printf("  Severity: %s\n", simplified.Severity)
			fmt.Printf("  CVEs: %v\n", simplified.GetCVEs())

			// Convert to map for JSON export
			m := simplified.ToMap()
			jsonData, _ := json.MarshalIndent(m, "  ", "  ")
			fmt.Printf("  JSON:\n  %s\n", string(jsonData))
		}
	}

	// Example 11: Check for specific CVE
	fmt.Println("\n=== Example 11: Check for Specific CVE ===")
	for _, def := range defs {
		simplified := oval.Simplify(def)
		if simplified.HasCVE("CVE-2023-1234") {
			fmt.Printf("Found definition with CVE-2023-1234: %s\n", simplified.Title)
		}
	}

	// Example 12: Multi-file parsing
	fmt.Println("\n=== Example 12: Multi-file Parsing ===")
	multiParser := oval.NewParser()

	// Parse multiple OVAL files
	files := []string{
		"rhel-8.oval.xml",
		"ubuntu-22.04.oval.xml",
		"debian-11.oval.xml",
	}

	for _, file := range files {
		err := multiParser.ParseFile(ctx, file)
		if err != nil {
			fmt.Printf("Failed to parse %s: %v\n", file, err)
		} else {
			fmt.Printf("Successfully parsed %s\n", file)
		}
	}

	allDefs := multiParser.GetDefinitions()
	fmt.Printf("Total definitions from all files: %d\n", len(allDefs))

	// Example 13: Context cancellation
	fmt.Println("\n=== Example 13: Context Cancellation ===")
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cancelParser := oval.NewParser()
	err = cancelParser.ParseFile(cancelCtx, "rhel-8.oval.xml")
	if err != nil {
		fmt.Printf("Expected error due to cancelled context: %v\n", err)
	}

	// Example 14: Real-world usage pattern
	fmt.Println("\n=== Example 14: Real-world Usage Pattern ===")
	realParser := oval.NewParser()

	// Parse RHEL OVAL
	if err := realParser.ParseFile(ctx, "rhel-8.oval.xml"); err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		// Get all critical vulnerabilities
		critical := realParser.FilterBySeverity("Critical")

		// For each critical vulnerability
		for _, def := range critical {
			// Extract CVEs
			cves := oval.ExtractCVEs(def)

			// Extract affected packages
			packages := oval.ExtractPackages(def)

			// Get advisory ID
			advisory := oval.GetAdvisoryID(def)

			// Print vulnerability report
			fmt.Printf("\n🚨 Critical Vulnerability\n")
			fmt.Printf("Advisory: %s\n", advisory)
			fmt.Printf("CVEs: %v\n", cves)
			fmt.Printf("Affected Packages: %v\n", packages)
			fmt.Printf("Description: %s\n", def.Description)
		}
	}

	fmt.Println("\n=== Examples Complete ===")
}
