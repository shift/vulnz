package scap_xccdf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "SCAP_XCCDF"

// Provider implements SCAP/XCCDF (Security Content Automation Protocol /
// Extensible Configuration Checklist Description Format) governance controls.
// These controls govern the creation, validation, and operational use of
// SCAP content for automated security configuration assessment.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "scap_xccdf"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading SCAP/XCCDF governance controls")
	return p.writeControls(ctx, embeddedSCAPControls())
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
	p.logger.Info("wrote SCAP/XCCDF controls to storage", "count", count)
	return count, nil
}

func embeddedSCAPControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "NIST SP 800-126 (SCAP)", Section: section}}
	}
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-01",
			Title:                  "SCAP Content Validation",
			Family:                 "Content Management",
			Description:            "All SCAP content (XCCDF benchmarks, OVAL definitions, CPE dictionaries) used for automated assessment must be validated against official NIST schemas before deployment. Only NIST-validated SCAP content sources are permitted.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             ref("Sec. 3"),
			ImplementationGuidance: "Validate SCAP content with NIST SCAP Validation Tool or OpenSCAP scanner. Source benchmarks from NVD or vendor-supplied STIG content only. Verify digital signatures on downloaded content.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-02",
			Title:                  "Automated Configuration Assessment Schedule",
			Family:                 "Assessment Operations",
			Description:            "SCAP-based configuration assessments must run on all in-scope systems at least weekly. Results must be collected, aggregated, and reported to the security team. Deviations from baseline must generate findings.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1188"},
			References:             ref("Sec. 4"),
			ImplementationGuidance: "Schedule OpenSCAP or equivalent to scan all systems weekly. Integrate scan results with SIEM or vulnerability management platform. Define remediation SLAs based on finding severity.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-03",
			Title:                  "XCCDF Benchmark Profile Selection",
			Family:                 "Content Management",
			Description:            "The XCCDF benchmark profile applied to each system must be appropriate for its role and risk classification. The use of the default or most permissive profile is prohibited for production systems.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-1188"},
			References:             ref("Sec. 5.2"),
			ImplementationGuidance: "Map system roles to XCCDF profiles (e.g. STIG High for government systems, CIS Level 2 for enterprise). Document profile selection rationale. Review profile assignments when system role changes.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-04",
			Title:                  "Assessment Result Retention and Traceability",
			Family:                 "Assessment Operations",
			Description:            "SCAP assessment results (ARF reports, XCCDF result files) must be retained for at least 12 months to support audit, trend analysis, and remediation tracking. Results must be linked to the specific content version used.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-778"},
			References:             ref("Sec. 6"),
			ImplementationGuidance: "Store ARF results in centralized repository. Tag results with scanner version, benchmark version, and assessment date. Implement retention policy to archive results after 12 months.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-05",
			Title:                  "Remediation Workflow Integration",
			Family:                 "Remediation",
			Description:            "SCAP findings must be fed into the organisation's vulnerability management or ticketing system. Each failing rule must generate a trackable remediation item assigned to the responsible team with a defined due date.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1104"},
			References:             ref("Sec. 7"),
			ImplementationGuidance: "Integrate OpenSCAP results with vulnerability management platform. Auto-create tickets for new findings. Define severity-based remediation SLAs. Track remediation progress via dashboard.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "SCAP-06",
			Title:                  "SCAP Scanner Integrity",
			Family:                 "Tool Security",
			Description:            "SCAP scanning tools must be kept current with vendor updates and their integrity verified before use. Scanners must run with minimum necessary privileges and their output must be protected from tampering.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-494", "CWE-269"},
			References:             ref("Sec. 3.1"),
			ImplementationGuidance: "Verify checksum of scanner binaries before deployment. Update scanners to latest stable release. Run scanners under dedicated service accounts. Store results in write-protected repository.",
		},
	}
}
