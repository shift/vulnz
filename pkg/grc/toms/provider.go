package toms

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "TOMs_GDPR_Art32"

// Provider implements Technical and Organisational Measures controls per GDPR Article 32.
// TOMs are the security measures a controller or processor must implement to ensure
// a level of security appropriate to the risk. They form the backbone of GDPR
// security compliance documentation.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "toms"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading TOMs (GDPR Art. 32) controls")
	return p.writeControls(ctx, embeddedTOMsControls())
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
	p.logger.Info("wrote TOMs controls to storage", "count", count)
	return count, nil
}

func embeddedTOMsControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: section}}
	}
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-01",
			Title:                  "Pseudonymisation of Personal Data",
			Family:                 "Technical Measures",
			Description:            "Implement pseudonymisation as a technical measure to reduce risk when processing personal data. Pseudonymised data must be stored separately from the additional information needed to re-identify data subjects.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-312"},
			References:             ref("Art. 32(1)(a)"),
			ImplementationGuidance: "Apply pseudonymisation (e.g. tokenisation, key-based substitution) to direct identifiers in analytics and test environments. Maintain key-mapping tables in separate secure storage with strict access controls.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-02",
			Title:                  "Encryption of Personal Data",
			Family:                 "Technical Measures",
			Description:            "Personal data must be encrypted at rest and in transit using appropriate cryptographic algorithms. Encryption key management must be documented and keys must be rotated on a defined schedule.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             ref("Art. 32(1)(a)"),
			ImplementationGuidance: "Use AES-256 for data at rest. Use TLS 1.2+ for data in transit. Manage encryption keys via a dedicated KMS. Document key lifecycle including rotation schedule and revocation procedures.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-03",
			Title:                  "Ongoing Confidentiality and Integrity",
			Family:                 "Organisational Measures",
			Description:            "Ensure ongoing confidentiality, integrity, availability, and resilience of processing systems and services through documented security policies, access controls, and change management processes.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-693"},
			References:             ref("Art. 32(1)(b)"),
			ImplementationGuidance: "Maintain an information security management system (ISMS). Define and enforce security policies for all personnel. Implement access control, change management, and incident management procedures.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-04",
			Title:                  "Restoration of Personal Data After Incident",
			Family:                 "Technical Measures",
			Description:            "Implement backup and recovery capabilities to restore access to personal data in a timely manner following a physical or technical incident. Recovery time and recovery point objectives must be defined and tested.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-693"},
			References:             ref("Art. 32(1)(c)"),
			ImplementationGuidance: "Define and document RTO and RPO for systems processing personal data. Implement automated backups with tested restoration procedures. Conduct annual recovery drills. Store backups off-site or in a separate cloud region.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-05",
			Title:                  "Regular Security Testing and Evaluation",
			Family:                 "Organisational Measures",
			Description:            "A process for regularly testing, assessing, and evaluating the effectiveness of technical and organisational measures must be established and maintained. Testing must include penetration testing, vulnerability scanning, and security audits.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1104"},
			References:             ref("Art. 32(1)(d)"),
			ImplementationGuidance: "Conduct annual penetration testing of systems processing personal data. Run vulnerability scans monthly. Perform security audits of TOMs at least annually. Document findings and remediation actions.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-06",
			Title:                  "Workforce Security Training",
			Family:                 "Organisational Measures",
			Description:            "All personnel with access to personal data must receive regular security awareness training covering data protection obligations, social engineering threats, incident reporting procedures, and acceptable use policies.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-693"},
			References:             ref("Art. 32(4)"),
			ImplementationGuidance: "Conduct mandatory security awareness training at onboarding and annually thereafter. Provide role-specific training for high-risk roles. Track completion and escalate non-completions. Test awareness via phishing simulations.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-07",
			Title:                  "Data Processor Security Requirements",
			Family:                 "Organisational Measures",
			Description:            "Where personal data is processed by a processor, the controller must ensure the processor implements equivalent technical and organisational measures. Processor TOMs must be documented and subject to regular review.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1357"},
			References:             ref("Art. 28"),
			ImplementationGuidance: "Include TOM requirements in data processing agreements (DPAs). Conduct or obtain evidence of processor security assessments at onboarding and annually. Request SOC 2 Type II or ISO 27001 certification as evidence.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TOM-08",
			Title:                  "Access Control and Need-to-Know",
			Family:                 "Technical Measures",
			Description:            "Access to personal data must be restricted to authorised personnel on a strict need-to-know basis. All access must be authenticated, logged, and reviewed regularly. Privileged access must be subject to additional controls.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-269"},
			References:             ref("Art. 32(1)(b)"),
			ImplementationGuidance: "Implement RBAC for all systems containing personal data. Log all access to personal data. Review access rights quarterly. Require MFA for all access to sensitive personal data. Apply PAM for administrative access.",
		},
	}
}
