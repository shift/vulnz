package veris_vcdb

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "VERIS_VCDB"

// Provider implements VERIS/VCDB (Vocabulary for Event Recording and Incident Sharing /
// VERIS Community Database) incident classification and governance controls.
// VERIS provides a common language for describing security incidents and is the
// foundation of the Verizon DBIR methodology.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "veris_vcdb"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading VERIS/VCDB incident classification controls")
	return p.writeControls(ctx, embeddedVERISControls())
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
	p.logger.Info("wrote VERIS/VCDB controls to storage", "count", count)
	return count, nil
}

func embeddedVERISControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "VERIS Framework v1.3.7", Section: section, URL: "https://veriscommunity.net"}}
	}
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-01",
			Title:                  "Incident Recording Using VERIS Schema",
			Family:                 "Incident Management",
			Description:            "All security incidents must be recorded using the VERIS schema to enable consistent classification, root cause analysis, and benchmarking against industry data. VERIS records must capture the four As: Actor, Action, Asset, and Attribute.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-778"},
			References:             ref("VERIS Schema"),
			ImplementationGuidance: "Train incident responders on VERIS schema. Implement VERIS-compatible incident recording in the ticketing system. Conduct quarterly data quality reviews of VERIS records.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-02",
			Title:                  "Threat Actor Classification",
			Family:                 "Threat Intelligence",
			Description:            "Security incidents must classify the threat actor using the VERIS taxonomy: External, Internal, Partner, or Unknown. Actor motives and known affiliations must be recorded where attributable.",
			Level:                  "medium",
			RelatedCWEs:            []string{},
			References:             ref("VERIS Actor Taxonomy"),
			ImplementationGuidance: "Use VERIS actor varieties (hacker, organised crime, state-affiliated, etc.) when recording incidents. Integrate threat intelligence to enrich actor attribution where available.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-03",
			Title:                  "Action Categorisation for Root Cause Analysis",
			Family:                 "Incident Management",
			Description:            "The action(s) that led to or enabled the incident must be classified using VERIS action categories: Hacking, Malware, Social, Misuse, Physical, Error, or Environmental. This enables systematic root cause analysis and control improvement.",
			Level:                  "high",
			RelatedCWEs:            []string{},
			References:             ref("VERIS Action Taxonomy"),
			ImplementationGuidance: "Map incident root causes to VERIS action categories during post-incident review. Use action data to identify gaps in preventive controls. Include action analysis in quarterly security metrics.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-04",
			Title:                  "Asset Inventory Alignment with VERIS",
			Family:                 "Asset Management",
			Description:            "The organisation's asset inventory must be aligned with VERIS asset categories (Server, User Device, Network, Person, Media, Kiosk/Terminal, Unknown) to enable accurate incident impact assessment.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-1078"},
			References:             ref("VERIS Asset Taxonomy"),
			ImplementationGuidance: "Map CMDB asset types to VERIS asset categories. Include VERIS asset classification in incident records. Use asset data to calculate blast radius and business impact during incidents.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-05",
			Title:                  "Incident Data Confidentiality Sharing",
			Family:                 "Information Sharing",
			Description:            "Anonymised incident data should be contributed to the VERIS Community Database (VCDB) where permitted by legal and business constraints, to support industry-wide threat intelligence and benchmarking.",
			Level:                  "low",
			RelatedCWEs:            []string{},
			References:             ref("VCDB Contribution Guidelines"),
			ImplementationGuidance: "Establish a policy for VCDB contribution. Define anonymisation requirements before submission. Obtain legal review for each submission. Contribute at least annually to maintain benchmarking access.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "VERIS-06",
			Title:                  "DBIR Benchmark Review",
			Family:                 "Risk Management",
			Description:            "The annual Verizon Data Breach Investigations Report (DBIR) must be reviewed by the security team to identify emerging threat patterns relevant to the organisation's industry and update controls accordingly.",
			Level:                  "low",
			RelatedCWEs:            []string{},
			References:             ref("DBIR Methodology"),
			ImplementationGuidance: "Assign DBIR review to a security analyst each year upon release. Compare organisational incident patterns to industry benchmarks. Use findings to prioritise control improvements in the security roadmap.",
		},
	}
}
