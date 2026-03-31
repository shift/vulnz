package oval

import (
	"strings"

	govalParser "github.com/quay/goval-parser/oval"
)

// SimplifiedDefinition represents a simplified view of an OVAL definition
// with key fields extracted for easier consumption.
type SimplifiedDefinition struct {
	// ID is the unique identifier for the OVAL definition
	ID string

	// Title is the human-readable title of the vulnerability
	Title string

	// Description provides detailed information about the vulnerability
	Description string

	// Severity indicates the severity level (Critical, High, Medium, Low)
	Severity string

	// Family indicates the OS family (unix, windows, etc.)
	Family string

	// References contains external references like CVEs and advisories
	References []Reference

	// Criteria defines the logical conditions for vulnerability detection
	Criteria *Criteria
}

// Reference represents an external reference from an OVAL definition.
type Reference struct {
	// Source is the reference source (CVE, RHSA, USN, etc.)
	Source string

	// RefID is the reference identifier
	RefID string

	// RefURL is the URL to the reference
	RefURL string
}

// Criteria represents a logical group of conditions for vulnerability detection.
// Criteria can be nested to form complex logical expressions.
type Criteria struct {
	// Operator defines how child criteria/criterion are combined (AND, OR)
	Operator string

	// Criteria contains nested criteria groups
	Criteria []*Criteria

	// Criterion contains individual test conditions
	Criterion []Criterion
}

// Criterion represents a single test condition in OVAL criteria.
type Criterion struct {
	// TestRef references an OVAL test by ID
	TestRef string

	// Comment describes what the test checks
	Comment string
}

// Simplify converts a goval-parser Definition to a simplified format.
// This extracts commonly used fields and makes the definition easier to work with.
//
// Example:
//
//	def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
//	simplified := oval.Simplify(def)
//	fmt.Printf("Severity: %s\n", simplified.Severity)
func Simplify(def *govalParser.Definition) *SimplifiedDefinition {
	if def == nil {
		return nil
	}

	simplified := &SimplifiedDefinition{
		ID:          def.ID,
		Title:       def.Title,
		Description: def.Description,
		Severity:    GetSeverity(def),
		Family:      GetFamily(def),
		References:  extractReferences(def),
		Criteria:    extractCriteria(&def.Criteria),
	}

	return simplified
}

// extractReferences extracts references from a goval definition.
func extractReferences(def *govalParser.Definition) []Reference {
	references := make([]Reference, 0)

	for _, ref := range def.References {
		references = append(references, Reference{
			Source: ref.Source,
			RefID:  ref.RefID,
			RefURL: ref.RefURL,
		})
	}

	return references
}

// extractCriteria recursively extracts criteria from goval criteria.
func extractCriteria(criteria *govalParser.Criteria) *Criteria {
	if criteria == nil {
		return nil
	}

	// If criteria is empty (no operator, no criterias, no criterions), return nil
	if criteria.Operator == "" && len(criteria.Criterias) == 0 && len(criteria.Criterions) == 0 {
		return nil
	}

	result := &Criteria{
		Operator:  criteria.Operator,
		Criteria:  make([]*Criteria, 0),
		Criterion: make([]Criterion, 0),
	}

	// Extract nested criteria
	for i := range criteria.Criterias {
		if nested := extractCriteria(&criteria.Criterias[i]); nested != nil {
			result.Criteria = append(result.Criteria, nested)
		}
	}

	// Extract criterion
	for _, crit := range criteria.Criterions {
		result.Criterion = append(result.Criterion, Criterion{
			TestRef: crit.TestRef,
			Comment: crit.Comment,
		})
	}

	return result
}

// ToMap converts a SimplifiedDefinition to a map for easy serialization.
// This is useful for JSON/YAML output or debugging.
//
// Example:
//
//	simplified := oval.Simplify(def)
//	data := simplified.ToMap()
//	json.NewEncoder(os.Stdout).Encode(data)
func (sd *SimplifiedDefinition) ToMap() map[string]interface{} {
	references := make([]map[string]string, 0, len(sd.References))
	for _, ref := range sd.References {
		references = append(references, map[string]string{
			"source":  ref.Source,
			"ref_id":  ref.RefID,
			"ref_url": ref.RefURL,
		})
	}

	result := map[string]interface{}{
		"id":          sd.ID,
		"title":       sd.Title,
		"description": sd.Description,
		"severity":    sd.Severity,
		"family":      sd.Family,
		"references":  references,
	}

	if sd.Criteria != nil {
		result["criteria"] = criteriaToMap(sd.Criteria)
	}

	return result
}

// criteriaToMap converts Criteria to a map representation.
func criteriaToMap(criteria *Criteria) map[string]interface{} {
	if criteria == nil {
		return nil
	}

	result := map[string]interface{}{
		"operator": criteria.Operator,
	}

	if len(criteria.Criteria) > 0 {
		nested := make([]map[string]interface{}, 0, len(criteria.Criteria))
		for _, c := range criteria.Criteria {
			if m := criteriaToMap(c); m != nil {
				nested = append(nested, m)
			}
		}
		result["criteria"] = nested
	}

	if len(criteria.Criterion) > 0 {
		criterion := make([]map[string]string, 0, len(criteria.Criterion))
		for _, c := range criteria.Criterion {
			criterion = append(criterion, map[string]string{
				"test_ref": c.TestRef,
				"comment":  c.Comment,
			})
		}
		result["criterion"] = criterion
	}

	return result
}

// HasCVE checks if the simplified definition references a specific CVE.
// CVE matching is case-insensitive.
//
// Example:
//
//	if simplified.HasCVE("CVE-2023-1234") {
//	    fmt.Println("This definition addresses CVE-2023-1234")
//	}
func (sd *SimplifiedDefinition) HasCVE(cveID string) bool {
	cveLower := strings.ToLower(cveID)
	for _, ref := range sd.References {
		if strings.ToLower(ref.Source) == "cve" && strings.ToLower(ref.RefID) == cveLower {
			return true
		}
	}
	return false
}

// GetCVEs returns all CVE IDs referenced in the definition.
//
// Example:
//
//	cves := simplified.GetCVEs()
//	fmt.Printf("Addresses CVEs: %v\n", cves)
func (sd *SimplifiedDefinition) GetCVEs() []string {
	cves := make([]string, 0)
	for _, ref := range sd.References {
		if strings.ToLower(ref.Source) == "cve" {
			cves = append(cves, ref.RefID)
		}
	}
	return cves
}
