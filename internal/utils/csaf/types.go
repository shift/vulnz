package csaf

import (
	"github.com/gocsaf/csaf/v3/csaf"
)

// SimplifiedAdvisory represents a simplified view of a CSAF advisory
// with commonly accessed fields extracted for convenience.
type SimplifiedAdvisory struct {
	ID             string   // Tracking ID
	Title          string   // Document title
	Summary        string   // Summary text from notes
	Publisher      string   // Publisher name
	InitialRelease string   // Initial release date
	CurrentRelease string   // Current release date
	CVEs           []string // All CVE IDs
	Products       []string // All product names
	Severity       string   // Aggregate severity
	Status         string   // draft, interim, final
}

// Simplify converts a CSAF Advisory to a simplified format.
// Returns nil if the input document is nil or missing required fields.
func Simplify(doc *csaf.Advisory) *SimplifiedAdvisory {
	if doc == nil || doc.Document == nil {
		return nil
	}

	simplified := &SimplifiedAdvisory{}

	// Extract document metadata
	if doc.Document.Tracking != nil {
		if doc.Document.Tracking.ID != nil {
			simplified.ID = string(*doc.Document.Tracking.ID)
		}
		if doc.Document.Tracking.Status != nil {
			simplified.Status = string(*doc.Document.Tracking.Status)
		}
		if doc.Document.Tracking.InitialReleaseDate != nil {
			simplified.InitialRelease = *doc.Document.Tracking.InitialReleaseDate
		}
		if doc.Document.Tracking.CurrentReleaseDate != nil {
			simplified.CurrentRelease = *doc.Document.Tracking.CurrentReleaseDate
		}
	}

	if doc.Document.Title != nil {
		simplified.Title = string(*doc.Document.Title)
	}

	if doc.Document.Publisher != nil && doc.Document.Publisher.Name != nil {
		simplified.Publisher = string(*doc.Document.Publisher.Name)
	}

	// Extract aggregate severity
	if doc.Document.AggregateSeverity != nil && doc.Document.AggregateSeverity.Text != nil {
		simplified.Severity = string(*doc.Document.AggregateSeverity.Text)
	}

	// Extract summary from notes
	if doc.Document.Notes != nil {
		for _, note := range doc.Document.Notes {
			if note.NoteCategory != nil && *note.NoteCategory == "summary" && note.Text != nil {
				simplified.Summary = *note.Text
				break
			}
		}
	}

	// Extract CVEs
	simplified.CVEs = ExtractCVEs(doc)

	// Extract products
	simplified.Products = ExtractProducts(doc)

	return simplified
}
