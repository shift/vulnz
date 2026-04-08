package ropa

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "ROPA_GDPR_Art30"

// Provider implements Records of Processing Activities controls per GDPR Article 30.
// ROPA is mandatory for organisations processing personal data and must be maintained
// as a living document kept available to supervisory authorities on request.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "ropa"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ROPA (GDPR Art. 30) controls")
	return p.writeControls(ctx, embeddedROPAControls())
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote ROPA controls to storage", "count", count)
	return count, nil
}

func embeddedROPAControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: section}}
	}
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-01",
			Title:                  "Controller ROPA Maintenance",
			Family:                 "Records Management",
			Description:            "As a data controller, maintain a written record of all processing activities under your responsibility. The ROPA must be maintained in electronic form and made available to the supervisory authority on request.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)"),
			ImplementationGuidance: "Establish a ROPA register. Assign a ROPA owner. Review and update ROPA at least annually and when new processing activities are introduced. Use a structured ROPA template covering all Art. 30(1) elements.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-02",
			Title:                  "Controller Identity and Contact Details",
			Family:                 "Records Management",
			Description:            "The ROPA must include the name and contact details of the controller, any joint controllers, the controller's representative, and the Data Protection Officer where applicable.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)(a)"),
			ImplementationGuidance: "Record full legal entity name, registered address, and DPO contact details. Update ROPA within 30 days of any organisational changes affecting controller identity.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-03",
			Title:                  "Processing Purposes Documentation",
			Family:                 "Records Management",
			Description:            "The ROPA must document the purposes of each processing activity. Purposes must be specific, explicit, and legitimate as required by the purpose limitation principle.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)(b)"),
			ImplementationGuidance: "For each processing activity, articulate the specific business purpose. Avoid generic descriptions. Link each purpose to its lawful basis. Review purposes when business processes change.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-04",
			Title:                  "Data Subject Categories and Personal Data Types",
			Family:                 "Records Management",
			Description:            "The ROPA must describe the categories of data subjects and the categories of personal data processed in each activity, including any special category data or criminal conviction data.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)(c)"),
			ImplementationGuidance: "Categorise data subjects (employees, customers, prospects, etc.). List data elements for each activity. Flag special category data (health, biometric, etc.) and confirm additional safeguards are in place.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-05",
			Title:                  "Third-Party Recipients Documentation",
			Family:                 "Records Management",
			Description:            "The ROPA must identify the categories of recipients to whom personal data is or will be disclosed, including recipients in third countries or international organisations.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)(d)"),
			ImplementationGuidance: "List all data processor and controller recipients. Identify transfers to third countries and the transfer mechanism used (adequacy decision, SCCs, BCRs). Review third-party recipients annually.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-06",
			Title:                  "Retention Periods",
			Family:                 "Records Management",
			Description:            "The ROPA must specify envisaged time limits for erasure of each category of personal data, or the criteria used to determine those limits. Retention periods must be aligned with the storage limitation principle.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("Art. 30(1)(f)"),
			ImplementationGuidance: "Define specific retention periods for each data category. Justify retention based on legal obligation, contractual need, or legitimate interest. Implement automated data deletion aligned with ROPA retention periods.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "ROPA-07",
			Title:                  "Technical and Organisational Security Measures",
			Family:                 "Records Management",
			Description:            "Where possible, the ROPA must include a general description of the technical and organisational security measures implemented to protect personal data processed in each activity.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-311"},
			References:             ref("Art. 30(1)(g)"),
			ImplementationGuidance: "Document security measures at an appropriate level of detail (e.g. encryption, pseudonymisation, access controls, backup). Reference relevant security policies. Update when security controls change.",
		},
	}
}
