package csaf

import (
	"github.com/gocsaf/csaf/v3/csaf"
)

// Remediation represents a remediation action for a vulnerability.
type Remediation struct {
	Category   string // workaround, mitigation, vendor_fix
	Details    string
	ProductIDs []string
	URL        string
}

// Score represents a CVSS score for a vulnerability.
type Score struct {
	CVE        string
	Version    string // CVSS v2, v3.0, v3.1
	BaseScore  float64
	Vector     string
	Severity   string // Low, Medium, High, Critical
	ProductIDs []string
}

// ExtractCVEs extracts all unique CVE IDs from the advisory.
// Returns an empty slice if no vulnerabilities are present.
func ExtractCVEs(doc *csaf.Advisory) []string {
	if doc == nil || doc.Vulnerabilities == nil {
		return []string{}
	}

	// Use a map to deduplicate CVE IDs
	cveMap := make(map[string]struct{})
	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE != nil && *vuln.CVE != "" {
			cveMap[string(*vuln.CVE)] = struct{}{}
		}
	}

	// Convert map to slice
	cves := make([]string, 0, len(cveMap))
	for cve := range cveMap {
		cves = append(cves, cve)
	}

	return cves
}

// ExtractProducts extracts all unique product names from the product tree.
// Returns an empty slice if no product tree is present.
func ExtractProducts(doc *csaf.Advisory) []string {
	if doc == nil || doc.ProductTree == nil {
		return []string{}
	}

	// Use a map to deduplicate product names
	productMap := make(map[string]struct{})

	// Extract from branches
	if doc.ProductTree.Branches != nil {
		extractProductsFromBranches(doc.ProductTree.Branches, productMap)
	}

	// Extract from relationships
	if doc.ProductTree.RelationShips != nil {
		for _, rel := range *doc.ProductTree.RelationShips {
			if rel.FullProductName != nil && rel.FullProductName.Name != nil && *rel.FullProductName.Name != "" {
				productMap[*rel.FullProductName.Name] = struct{}{}
			}
		}
	}

	// Convert map to slice
	products := make([]string, 0, len(productMap))
	for product := range productMap {
		products = append(products, product)
	}

	return products
}

// extractProductsFromBranches recursively extracts product names from branches.
func extractProductsFromBranches(branches csaf.Branches, productMap map[string]struct{}) {
	for _, branch := range branches {
		if branch.Product != nil && branch.Product.Name != nil && *branch.Product.Name != "" {
			productMap[*branch.Product.Name] = struct{}{}
		}
		// Recurse into sub-branches
		if branch.Branches != nil {
			extractProductsFromBranches(branch.Branches, productMap)
		}
	}
}

// ExtractRemediations extracts all remediation details from the advisory.
// Returns an empty slice if no vulnerabilities with remediations are present.
func ExtractRemediations(doc *csaf.Advisory) []Remediation {
	if doc == nil || doc.Vulnerabilities == nil {
		return []Remediation{}
	}

	var remediations []Remediation

	for _, vuln := range doc.Vulnerabilities {
		if vuln.Remediations == nil {
			continue
		}

		for _, rem := range vuln.Remediations {
			remediation := Remediation{
				Category:   string(*rem.Category),
				Details:    *rem.Details,
				ProductIDs: []string{},
			}

			if rem.URL != nil {
				remediation.URL = *rem.URL
			}

			if rem.ProductIds != nil {
				for _, pid := range *rem.ProductIds {
					remediation.ProductIDs = append(remediation.ProductIDs, string(*pid))
				}
			}

			remediations = append(remediations, remediation)
		}
	}

	return remediations
}

// ExtractScores extracts all CVSS scores from the advisory.
// Returns an empty slice if no vulnerabilities with scores are present.
func ExtractScores(doc *csaf.Advisory) []Score {
	if doc == nil || doc.Vulnerabilities == nil {
		return []Score{}
	}

	var scores []Score

	for _, vuln := range doc.Vulnerabilities {
		if vuln.Scores == nil {
			continue
		}

		cveID := ""
		if vuln.CVE != nil {
			cveID = string(*vuln.CVE)
		}

		for _, scoreSet := range vuln.Scores {
			// Extract CVSS v3 scores
			if scoreSet.CVSS3 != nil {
				score := Score{
					CVE:        cveID,
					Version:    "3.1",
					BaseScore:  *scoreSet.CVSS3.BaseScore,
					Vector:     string(*scoreSet.CVSS3.VectorString),
					Severity:   string(*scoreSet.CVSS3.BaseSeverity),
					ProductIDs: []string{},
				}

				if scoreSet.Products != nil {
					for _, pid := range *scoreSet.Products {
						score.ProductIDs = append(score.ProductIDs, string(*pid))
					}
				}

				scores = append(scores, score)
			}

			// Extract CVSS v2 scores
			if scoreSet.CVSS2 != nil {
				score := Score{
					CVE:        cveID,
					Version:    "2.0",
					BaseScore:  *scoreSet.CVSS2.BaseScore,
					Vector:     string(*scoreSet.CVSS2.VectorString),
					Severity:   calculateCVSSv2Severity(*scoreSet.CVSS2.BaseScore),
					ProductIDs: []string{},
				}

				if scoreSet.Products != nil {
					for _, pid := range *scoreSet.Products {
						score.ProductIDs = append(score.ProductIDs, string(*pid))
					}
				}

				scores = append(scores, score)
			}
		}
	}

	return scores
}

// calculateCVSSv2Severity calculates severity rating from CVSS v2 base score.
func calculateCVSSv2Severity(baseScore float64) string {
	switch {
	case baseScore >= 7.0:
		return "HIGH"
	case baseScore >= 4.0:
		return "MEDIUM"
	case baseScore > 0.0:
		return "LOW"
	default:
		return "NONE"
	}
}
