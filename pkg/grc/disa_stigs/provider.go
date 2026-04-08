package disa_stigs

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "DISA_STIGs"

// Provider implements DISA Security Technical Implementation Guide controls.
// STIGs are mandatory configuration standards for US Department of Defense
// information systems and are widely adopted as hardening benchmarks outside DoD.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "disa_stigs"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading DISA STIG controls")
	return p.writeControls(ctx, embeddedSTIGControls())
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
	p.logger.Info("wrote DISA STIG controls to storage", "count", count)
	return count, nil
}

func embeddedSTIGControls() []grc.Control {
	ref := func(vulnID string) []grc.Reference {
		return []grc.Reference{{Source: "DISA STIGs", Section: vulnID}}
	}
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "V-220706",
			Title:                  "Operating System Must Use DoD-Approved Encryption",
			Family:                 "System Cryptography",
			Description:            "The operating system must implement DoD-approved encryption to protect the confidentiality of remote access sessions. This requirement applies to systems where data is transmitted over networks.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             ref("V-220706"),
			ImplementationGuidance: "Configure system to use FIPS 140-2 validated cryptographic modules. Disable weak cipher suites (RC4, DES, 3DES). Enable TLS 1.2+ for all remote access.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220707",
			Title:                  "Unique Identifier Assigned to Each User Account",
			Family:                 "Account Management",
			Description:            "The operating system must uniquely identify and authenticate organizational users and processes acting on behalf of organizational users. Shared accounts are prohibited for human users.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-287", "CWE-284"},
			References:             ref("V-220707"),
			ImplementationGuidance: "Disable all default and shared accounts. Enforce unique user IDs. Implement centralised identity management (e.g. Active Directory, LDAP).",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220708",
			Title:                  "Session Timeout for Inactive Connections",
			Family:                 "Session Management",
			Description:            "The operating system must automatically terminate user sessions after a defined period of inactivity to prevent unauthorized access via abandoned sessions.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-613"},
			References:             ref("V-220708"),
			ImplementationGuidance: "Configure idle session timeout to 15 minutes or less. Apply to all interactive sessions including SSH, GUI, and web interfaces.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220709",
			Title:                  "Audit Logging of Security-Relevant Events",
			Family:                 "Audit and Accountability",
			Description:            "The operating system must generate audit records for security-relevant events including logon, logoff, privilege escalation, account management, and object access failures.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-778"},
			References:             ref("V-220709"),
			ImplementationGuidance: "Enable auditd or equivalent. Configure rules for logon events, sudo usage, file permission changes, and network configuration changes. Forward logs to centralized SIEM.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220710",
			Title:                  "Password Complexity and Minimum Length",
			Family:                 "Identification and Authentication",
			Description:            "The operating system must enforce a minimum password complexity and length. Passwords must contain uppercase, lowercase, numeric, and special characters and must be at least 15 characters long.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-521"},
			References:             ref("V-220710"),
			ImplementationGuidance: "Configure PAM or equivalent to enforce complexity rules. Set minimum password length to 15+. Implement password history to prevent reuse of last 5 passwords.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220711",
			Title:                  "Host-Based Intrusion Detection System",
			Family:                 "System and Information Integrity",
			Description:            "The operating system must employ a host-based intrusion detection system to detect malicious activity and unauthorized changes to the system.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-693"},
			References:             ref("V-220711"),
			ImplementationGuidance: "Deploy HIDS such as AIDE, Tripwire, or OS-integrated FIM. Configure to alert on changes to critical system files. Run integrity checks daily.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220712",
			Title:                  "Removal of Unnecessary Software and Services",
			Family:                 "Configuration Management",
			Description:            "The operating system must not have unnecessary services, packages, or accounts enabled. Attack surface must be minimized by removing or disabling all components not required for the system mission.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-1188"},
			References:             ref("V-220712"),
			ImplementationGuidance: "Remove unused packages after OS installation. Disable unnecessary system services (e.g. telnet, rsh, FTP). Apply CIS Benchmark level 1 or 2 hardening.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "V-220713",
			Title:                  "Kernel and Package Updates Applied Timely",
			Family:                 "System and Information Integrity",
			Description:            "The operating system must be kept current with security patches. Critical and high-severity patches must be applied within 30 days of release. Emergency patches addressing actively exploited vulnerabilities must be applied within 72 hours.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1104"},
			References:             ref("V-220713"),
			ImplementationGuidance: "Subscribe to vendor security advisories. Implement automated patch management. Define and enforce patch SLAs by severity. Test patches in staging before production deployment.",
		},
	}
}
