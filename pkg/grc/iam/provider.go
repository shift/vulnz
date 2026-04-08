package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "IAM"

// Provider implements Identity and Access Management security controls.
// These controls cover the full identity lifecycle: provisioning, access review,
// privileged access management, authentication, and de-provisioning.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "iam"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading IAM controls")
	return p.writeControls(ctx, embeddedIAMControls())
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
	p.logger.Info("wrote IAM controls to storage", "count", count)
	return count, nil
}

func embeddedIAMControls() []grc.Control {
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-01",
			Title:                  "Identity Lifecycle Management",
			Family:                 "Identity Governance",
			Description:            "Establish and maintain a formal identity lifecycle management process covering joiner, mover, and leaver events. Access rights must be provisioned, modified, and de-provisioned in a timely and automated manner tied to HR system events.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284"},
			ImplementationGuidance: "Integrate IAM with HR system. Automate account creation and de-provisioning. Define SLAs for access changes (e.g. new joiner provisioned within 1 business day, leaver de-provisioned within 4 hours).",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-02",
			Title:                  "Least Privilege Access",
			Family:                 "Access Control",
			Description:            "All identities must be granted the minimum access rights necessary to perform their assigned functions. Access requests must include business justification and follow an approval workflow.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			ImplementationGuidance: "Implement role-based access control (RBAC). Review and right-size roles at least annually. Use just-in-time (JIT) access for privileged operations. Remove standing privileged access where possible.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-03",
			Title:                  "Multi-Factor Authentication",
			Family:                 "Authentication",
			Description:            "Multi-factor authentication (MFA) must be enforced for all user accounts accessing sensitive systems, administrative interfaces, and any remote access. Phishing-resistant MFA (e.g. FIDO2, hardware tokens) is required for privileged accounts.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-308", "CWE-287"},
			ImplementationGuidance: "Enable MFA in identity provider. Enforce conditional access policies requiring MFA for all logins. Migrate privileged users to FIDO2 hardware keys. Block legacy authentication protocols.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-04",
			Title:                  "Privileged Access Management",
			Family:                 "Privileged Access",
			Description:            "Privileged access must be managed through a dedicated Privileged Access Management (PAM) solution. Privileged session recording, credential vaulting, and just-in-time elevation are required for all administrative access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-522"},
			ImplementationGuidance: "Deploy PAM tooling (e.g. CyberArk, HashiCorp Vault, AWS SSM Session Manager). Vault all privileged credentials. Record all privileged sessions. Rotate credentials after each use.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-05",
			Title:                  "Access Review and Recertification",
			Family:                 "Access Governance",
			Description:            "User access rights must be reviewed and recertified at least quarterly for privileged access and at least annually for standard access. Access that cannot be justified must be revoked immediately.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284"},
			ImplementationGuidance: "Schedule automated access review campaigns. Route reviews to line managers and data owners. Track completion rates and escalate overdue reviews. Document and retain review evidence.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-06",
			Title:                  "Service Account Governance",
			Family:                 "Non-Human Identity",
			Description:            "All service accounts and non-human identities must be inventoried, owned by a specific team, and subject to credential rotation policies. Long-lived static credentials must be replaced by short-lived tokens and workload identity where supported.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-522", "CWE-798"},
			ImplementationGuidance: "Maintain service account inventory. Assign owners to all service accounts. Implement credential rotation (maximum 90 days for static credentials). Migrate to OIDC federation or managed identity.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-07",
			Title:                  "Single Sign-On and Federated Identity",
			Family:                 "Authentication",
			Description:            "All enterprise applications must integrate with the centralized identity provider using SSO. Direct application-level credentials for human users are prohibited except for documented exceptions.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-287"},
			ImplementationGuidance: "Mandate SSO for all new application onboarding. Migrate existing applications to identity provider federation (SAML 2.0 or OIDC). Disable local user databases in applications where SSO is available.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "IAM-08",
			Title:                  "Identity Threat Detection",
			Family:                 "Identity Security",
			Description:            "Monitor identity and access events for anomalous behaviour including impossible travel, credential stuffing, privilege escalation, and lateral movement patterns. Automated response must be configured for high-confidence identity threats.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-284", "CWE-307"},
			ImplementationGuidance: "Integrate identity provider logs with SIEM/UEBA. Enable risk-based conditional access policies. Configure automated account suspension for high-risk sign-in events. Review identity threat alerts daily.",
		},
	}
}
