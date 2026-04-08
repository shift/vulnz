package misp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "MISP"

// Provider implements MISP (Malware Information Sharing Platform) governance controls.
// These controls cover threat intelligence sharing, indicator lifecycle management,
// and operational security for running or participating in MISP instances.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "misp"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading MISP governance controls")
	return p.writeControls(ctx, embeddedMISPControls())
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
	p.logger.Info("wrote MISP controls to storage", "count", count)
	return count, nil
}

func embeddedMISPControls() []grc.Control {
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-01",
			Title:                  "Threat Intelligence Feed Validation",
			Family:                 "Data Quality",
			Description:            "All threat intelligence feeds ingested into MISP must be validated for accuracy, timeliness, and source credibility before distribution. False positive indicators must be reviewed and retracted within defined SLAs.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			ImplementationGuidance: "Implement feed scoring and credibility tracking. Define and enforce false positive retraction SLAs. Use MISP warninglists to automatically flag known false positives.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-02",
			Title:                  "Traffic Light Protocol Compliance",
			Family:                 "Information Sharing",
			Description:            "All indicators and events shared via MISP must be tagged with a Traffic Light Protocol (TLP) classification. Distribution of indicators beyond their TLP boundary is prohibited and must be enforced technically.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284"},
			ImplementationGuidance: "Configure MISP distribution settings to enforce TLP boundaries. Audit shared events regularly for TLP compliance. Train all MISP users on TLP semantics before granting sharing privileges.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-03",
			Title:                  "MISP Instance Access Control",
			Family:                 "Access Control",
			Description:            "Access to the MISP platform must be controlled via role-based permissions. Read-only, analyst, and publisher roles must be defined. All user accounts must use strong authentication and be reviewed quarterly.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-287"},
			ImplementationGuidance: "Configure MISP RBAC with principle of least privilege. Integrate MISP with enterprise SSO. Disable unused accounts promptly. Audit MISP user permissions quarterly.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-04",
			Title:                  "Indicator Lifecycle Management",
			Family:                 "Data Governance",
			Description:            "Threat indicators in MISP must have defined expiry dates appropriate to their type. Expired indicators must be automatically decayed or removed to prevent stale intelligence from generating false positives in detection systems.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			ImplementationGuidance: "Enable MISP decay model for automatic indicator scoring decay. Set default expiry periods per indicator type (IP: 30 days, domain: 60 days, hash: 365 days). Review and update decay parameters quarterly.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-05",
			Title:                  "API Security and Key Management",
			Family:                 "Integration Security",
			Description:            "MISP API keys must be treated as credentials and managed accordingly. Keys must be rotated at least annually, scoped to minimum required permissions, and revoked immediately when the associated service or user is decommissioned.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-522", "CWE-798"},
			ImplementationGuidance: "Store MISP API keys in secrets manager. Define API key rotation policy. Audit API key usage logs for anomalous patterns. Revoke and rotate keys immediately on suspected compromise.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "MISP-06",
			Title:                  "MISP Platform Hardening and Updates",
			Family:                 "Platform Security",
			Description:            "The MISP platform must be kept current with security updates. The underlying server must be hardened per OS security benchmarks. MISP must not be exposed directly to the internet without authentication and TLS.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1104", "CWE-311"},
			ImplementationGuidance: "Subscribe to MISP security advisories. Apply MISP updates within 30 days of release. Reverse-proxy MISP behind authenticated gateway. Enable TLS with valid certificate. Restrict admin interface to management network.",
		},
	}
}
