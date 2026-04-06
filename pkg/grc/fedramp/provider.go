package fedramp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const (
	FedRAMPCatalogURL = "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json"
	FrameworkID       = "FedRAMP_Rev5"
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

func (p *Provider) Name() string {
	return "fedramp"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching FedRAMP catalog", "url", FedRAMPCatalogURL)

	destPath := filepath.Join(os.TempDir(), "fedramp_catalog.json")
	if err := p.download(ctx, FedRAMPCatalogURL, destPath); err != nil {
		p.logger.Warn("FedRAMP catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("FedRAMP catalog parse failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}

	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog struct {
		Catalog struct {
			Groups []struct {
				ID       string `json:"id"`
				Title    string `json:"title"`
				Controls []struct {
					ID    string `json:"id"`
					Title string `json:"title"`
					Props []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"props"`
					Parts []struct {
						Name  string `json:"name"`
						Prose string `json:"prose"`
					} `json:"parts"`
				} `json:"controls"`
			} `json:"groups"`
		} `json:"catalog"`
	}
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode FedRAMP catalog: %w", err)
	}

	var controls []grc.Control
	for _, group := range catalog.Catalog.Groups {
		for _, ctrl := range group.Controls {
			description := ""
			for _, part := range ctrl.Parts {
				if part.Name == "statement" {
					description = part.Prose
				}
			}
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   ctrl.ID,
				Title:       ctrl.Title,
				Family:      group.Title,
				Description: description,
				Level:       "moderate",
			})
		}
	}

	return controls, nil
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
	p.logger.Info("wrote FedRAMP controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedFedRAMPControls()
	return p.writeControls(ctx, controls)
}

func embeddedFedRAMPControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "AC-1", Title: "Access Control Policy and Procedures", Family: "Access Control", Description: "Develop, document, and disseminate access control policy and procedures.", Level: "moderate", ImplementationGuidance: "Document AC policy and procedures. Review annually or after significant changes."},
		{Framework: FrameworkID, ControlID: "AC-2", Title: "Account Management", Family: "Access Control", Description: "Manage information system accounts including establishment, activation, modification, review, and removal.", Level: "moderate", ImplementationGuidance: "Automate account lifecycle management. Review accounts quarterly."},
		{Framework: FrameworkID, ControlID: "AC-3", Title: "Access Enforcement", Family: "Access Control", Description: "Enforce approved authorizations for logical access to information and system resources.", Level: "moderate", ImplementationGuidance: "Implement RBAC or ABAC. Enforce access controls at all system layers."},
		{Framework: FrameworkID, ControlID: "AC-4", Title: "Information Flow Enforcement", Family: "Access Control", Description: "Control information flows within the system and between interconnected systems.", Level: "moderate", ImplementationGuidance: "Implement network segmentation. Control data flows between security domains."},
		{Framework: FrameworkID, ControlID: "AC-5", Title: "Separation of Duties", Family: "Access Control", Description: "Separate duties of individuals to prevent malevolent activity without collusion.", Level: "moderate", ImplementationGuidance: "Define role separation requirements. Implement dual control for critical operations."},
		{Framework: FrameworkID, ControlID: "AC-6", Title: "Least Privilege", Family: "Access Control", Description: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.", Level: "moderate", ImplementationGuidance: "Implement least privilege access. Review permissions regularly."},
		{Framework: FrameworkID, ControlID: "AC-7", Title: "Unsuccessful Logon Attempts", Family: "Access Control", Description: "Enforce a limit on consecutive invalid logon attempts and lock account after threshold.", Level: "moderate", ImplementationGuidance: "Lock accounts after 3-5 failed attempts. Implement progressive delays."},
		{Framework: FrameworkID, ControlID: "AC-8", Title: "System Use Notification", Family: "Access Control", Description: "Display system use notification message before granting access.", Level: "moderate", ImplementationGuidance: "Display banner before login. Include monitoring and consent language."},
		{Framework: FrameworkID, ControlID: "AC-17", Title: "Remote Access", Family: "Access Control", Description: "Establish and document usage restrictions, configuration requirements, and implementation guidance for remote access.", Level: "moderate", ImplementationGuidance: "Require VPN for remote access. Implement MFA for all remote connections."},
		{Framework: FrameworkID, ControlID: "AC-18", Title: "Wireless Access", Family: "Access Control", Description: "Establish usage restrictions and implementation guidance for wireless technologies.", Level: "moderate", ImplementationGuidance: "Segment wireless networks. Use WPA3 encryption. Monitor for rogue access points."},
		{Framework: FrameworkID, ControlID: "AC-19", Title: "Access Control for Mobile Devices", Family: "Access Control", Description: "Establish usage restrictions and implementation guidance for mobile devices.", Level: "moderate", ImplementationGuidance: "Implement MDM. Enforce device encryption and remote wipe capabilities."},
		{Framework: FrameworkID, ControlID: "AC-20", Title: "Use of External Systems", Family: "Access Control", Description: "Establish terms and conditions for authorized individuals to access systems from external systems.", Level: "moderate", ImplementationGuidance: "Define acceptable use for external systems. Implement virtual desktop infrastructure."},

		{Framework: FrameworkID, ControlID: "AU-2", Title: "Audit Events", Family: "Audit and Accountability", Description: "Determine auditable events and coordinate with organizational monitoring.", Level: "moderate", ImplementationGuidance: "Define auditable events per system. Review audit requirements annually."},
		{Framework: FrameworkID, ControlID: "AU-3", Title: "Content of Audit Records", Family: "Audit and Accountability", Description: "Generate audit records containing information to establish what events occurred, sources, and outcomes.", Level: "moderate", ImplementationGuidance: "Include timestamp, source, outcome, and identity in audit records."},
		{Framework: FrameworkID, ControlID: "AU-6", Title: "Audit Review, Analysis, and Reporting", Family: "Audit and Accountability", Description: "Review and analyze audit records for indications of inappropriate or unusual activity.", Level: "moderate", ImplementationGuidance: "Automate log analysis with SIEM. Review audit reports weekly."},
		{Framework: FrameworkID, ControlID: "AU-9", Title: "Protection of Audit Information", Family: "Audit and Accountability", Description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.", Level: "moderate", ImplementationGuidance: "Store logs in write-once storage. Restrict access to audit tools."},
		{Framework: FrameworkID, ControlID: "AU-11", Title: "Audit Record Retention", Family: "Audit and Accountability", Description: "Retain audit records for defined time period to provide support for after-the-fact investigations.", Level: "moderate", ImplementationGuidance: "Retain audit logs for minimum 1 year. Archive per FedRAMP requirements."},
		{Framework: FrameworkID, ControlID: "AU-12", Title: "Audit Generation", Family: "Audit and Accountability", Description: "Provide audit record generation capability for defined auditable events.", Level: "moderate", ImplementationGuidance: "Enable audit logging on all system components. Centralize log collection."},

		{Framework: FrameworkID, ControlID: "CM-2", Title: "Baseline Configuration", Family: "Configuration Management", Description: "Develop, document, and maintain baseline configurations of systems.", Level: "moderate", ImplementationGuidance: "Document baseline configurations. Track deviations from baseline."},
		{Framework: FrameworkID, ControlID: "CM-3", Title: "Configuration Change Control", Family: "Configuration Management", Description: "Determine types of changes that are configuration-controlled and require formal review and approval.", Level: "moderate", ImplementationGuidance: "Implement change advisory board. Document and approve all configuration changes."},
		{Framework: FrameworkID, ControlID: "CM-6", Title: "Configuration Settings", Family: "Configuration Management", Description: "Establish and document configuration settings for systems reflecting most restrictive mode consistent with operational requirements.", Level: "moderate", ImplementationGuidance: "Apply CIS benchmarks. Monitor configuration drift."},
		{Framework: FrameworkID, ControlID: "CM-7", Title: "Least Functionality", Family: "Configuration Management", Description: "Configure systems to provide only essential capabilities and prohibit or restrict use of non-essential functions.", Level: "moderate", ImplementationGuidance: "Disable unnecessary services and ports. Implement application whitelisting."},
		{Framework: FrameworkID, ControlID: "CM-8", Title: "System Component Inventory", Family: "Configuration Management", Description: "Develop and document an inventory of system components that accurately reflects current system.", Level: "moderate", ImplementationGuidance: "Maintain automated CMDB. Update inventory after each change."},
		{Framework: FrameworkID, ControlID: "CM-9", Title: "Configuration Management Plan", Family: "Configuration Management", Description: "Develop, document, and implement a configuration management plan.", Level: "moderate", ImplementationGuidance: "Document CM plan. Review and update annually."},
		{Framework: FrameworkID, ControlID: "CM-10", Title: "Software Usage Restrictions", Family: "Configuration Management", Description: "Use software and associated documentation in accordance with contract agreements and copyright laws.", Level: "moderate", ImplementationGuidance: "Maintain software license inventory. Track open source license compliance."},
		{Framework: FrameworkID, ControlID: "CM-11", Title: "User-Installed Software", Family: "Configuration Management", Description: "Establish policies governing user-installed software and enforce using automated mechanisms.", Level: "moderate", ImplementationGuidance: "Restrict software installation to authorized personnel. Implement application control."},

		{Framework: FrameworkID, ControlID: "IA-2", Title: "Identification and Authentication (Organizational Users)", Family: "Identification and Authentication", Description: "Uniquely identify and authenticate organizational users and associate that unique identification with processes.", Level: "moderate", ImplementationGuidance: "Require MFA for all users. Use PIV/CAC cards for federal employees."},
		{Framework: FrameworkID, ControlID: "IA-5", Title: "Authenticator Management", Family: "Identification and Authentication", Description: "Manage information system authenticators by verifying identity before issuing authenticators.", Level: "moderate", ImplementationGuidance: "Enforce password complexity. Implement certificate-based authentication."},
		{Framework: FrameworkID, ControlID: "IA-8", Title: "Identification and Authentication (Non-Organizational Users)", Family: "Identification and Authentication", Description: "Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.", Level: "moderate", ImplementationGuidance: "Use federation for external users. Implement OAuth 2.0 / SAML for partner access."},

		{Framework: FrameworkID, ControlID: "IR-4", Title: "Incident Handling", Family: "Incident Response", Description: "Implement an incident handling capability for security incidents that includes preparation, detection, analysis, containment, eradication, and recovery.", Level: "moderate", ImplementationGuidance: "Develop incident response plan. Conduct tabletop exercises quarterly."},
		{Framework: FrameworkID, ControlID: "IR-5", Title: "Incident Monitoring", Family: "Incident Response", Description: "Track and document security incidents.", Level: "moderate", ImplementationGuidance: "Implement incident tracking system. Document all incident handling activities."},
		{Framework: FrameworkID, ControlID: "IR-6", Title: "Incident Reporting", Family: "Incident Response", Description: "Require personnel to report suspected security incidents to organizational incident response capability.", Level: "moderate", ImplementationGuidance: "Define incident reporting procedures. Report to US-CERT per FedRAMP requirements."},
		{Framework: FrameworkID, ControlID: "IR-7", Title: "Incident Response Assistance", Family: "Incident Response", Description: "Provide an incident response support resource that offers advice and assistance to users.", Level: "moderate", ImplementationGuidance: "Establish help desk for incident reporting. Maintain incident response team contacts."},
		{Framework: FrameworkID, ControlID: "IR-8", Title: "Incident Response Plan", Family: "Incident Response", Description: "Develop and implement an incident response plan.", Level: "moderate", ImplementationGuidance: "Document IR plan. Review and update annually."},

		{Framework: FrameworkID, ControlID: "RA-3", Title: "Risk Assessment", Family: "Risk Assessment", Description: "Conduct risk assessments including identification of threats, vulnerabilities, and likelihood of occurrence.", Level: "moderate", ImplementationGuidance: "Conduct annual risk assessments. Use NIST SP 800-30 methodology."},
		{Framework: FrameworkID, ControlID: "RA-5", Title: "Vulnerability Monitoring and Scanning", Family: "Risk Assessment", Description: "Monitor and scan for vulnerabilities in the system and hosted applications.", Level: "moderate", ImplementationGuidance: "Scan monthly. Remediate high vulnerabilities within 30 days per FedRAMP."},

		{Framework: FrameworkID, ControlID: "SA-4", Title: "Acquisition Process", Family: "System and Services Acquisition", Description: "Include security requirements and acquisition considerations in procurement documents.", Level: "moderate", ImplementationGuidance: "Include security requirements in RFPs. Evaluate vendor security posture."},
		{Framework: FrameworkID, ControlID: "SA-9", Title: "External System Services", Family: "System and Services Acquisition", Description: "Require providers of external system services to comply with organizational security requirements.", Level: "moderate", ImplementationGuidance: "Include security requirements in SLAs. Assess third-party security controls."},
		{Framework: FrameworkID, ControlID: "SA-22", Title: "Unsupported System Components", Family: "System and Services Acquisition", Description: "Replace unsupported system components with supported alternatives or document justification for continued use.", Level: "moderate", ImplementationGuidance: "Track end-of-life dates. Plan migrations before EOL."},

		{Framework: FrameworkID, ControlID: "SC-7", Title: "Boundary Protection", Family: "System and Communications Protection", Description: "Monitor and control communications at external and key internal boundaries of the system.", Level: "moderate", ImplementationGuidance: "Deploy NGFW at boundaries. Implement network segmentation."},
		{Framework: FrameworkID, ControlID: "SC-8", Title: "Transmission Confidentiality and Integrity", Family: "System and Communications Protection", Description: "Protect the confidentiality and integrity of transmitted information.", Level: "moderate", ImplementationGuidance: "Use TLS 1.2+ for all transmissions. Implement mutual TLS for sensitive connections."},
		{Framework: FrameworkID, ControlID: "SC-12", Title: "Cryptographic Key Establishment and Management", Family: "System and Communications Protection", Description: "Establish and manage cryptographic keys when cryptography is employed within the system.", Level: "moderate", ImplementationGuidance: "Use FIPS 140-2 validated cryptographic modules. Implement key rotation."},
		{Framework: FrameworkID, ControlID: "SC-13", Title: "Cryptographic Protection", Family: "System and Communications Protection", Description: "Implement FIPS-validated cryptography for protection of information.", Level: "moderate", ImplementationGuidance: "Use FIPS 140-2/140-3 validated modules. Validate cryptographic implementations."},
		{Framework: FrameworkID, ControlID: "SC-28", Title: "Protection of Information at Rest", Family: "System and Communications Protection", Description: "Protect the confidentiality and integrity of information at rest.", Level: "moderate", ImplementationGuidance: "Encrypt data at rest. Implement key management for stored data."},
		{Framework: FrameworkID, ControlID: "SC-39", Title: "Process Isolation", Family: "System and Communications Protection", Description: "Maintain a separate execution domain for each executing process in the system.", Level: "moderate", ImplementationGuidance: "Ensure OS-level process isolation. Use containers with proper isolation."},

		{Framework: FrameworkID, ControlID: "SI-2", Title: "Flaw Remediation", Family: "System and Information Integrity", Description: "Identify, report, and correct system flaws.", Level: "moderate", ImplementationGuidance: "Apply security patches within FedRAMP timelines. Test patches before deployment."},
		{Framework: FrameworkID, ControlID: "SI-3", Title: "Malicious Code Protection", Family: "System and Information Integrity", Description: "Implement and maintain malicious code protection mechanisms at system entry and exit points.", Level: "moderate", ImplementationGuidance: "Deploy endpoint protection. Keep signatures updated. Scan all incoming files."},
		{Framework: FrameworkID, ControlID: "SI-4", Title: "System Monitoring", Family: "System and Information Integrity", Description: "Monitor the system to detect attacks and indicators of potential attacks.", Level: "moderate", ImplementationGuidance: "Deploy IDS/IPS. Monitor for anomalous behavior patterns."},
		{Framework: FrameworkID, ControlID: "SI-5", Title: "Security Alerts, Advisories, and Directives", Family: "System and Information Integrity", Description: "Receive and respond to security alerts, advisories, and directives from external organizations.", Level: "moderate", ImplementationGuidance: "Subscribe to US-CERT alerts. Respond to CISA directives within required timeframes."},
		{Framework: FrameworkID, ControlID: "SI-12", Title: "Information Management and Retention", Family: "System and Information Integrity", Description: "Manage and retain information within the system and information output from the system.", Level: "moderate", ImplementationGuidance: "Define data retention policies. Implement automated data lifecycle management."},

		// Cloud-specific additions
		{Framework: FrameworkID, ControlID: "AC-21", Title: "Cloud Access Controls", Family: "Access Control", Description: "Implement access controls specific to cloud service environments and multi-tenant architectures.", Level: "moderate", ImplementationGuidance: "Use cloud-native IAM. Implement cross-account access controls."},
		{Framework: FrameworkID, ControlID: "CM-12", Title: "Cloud Configuration Management", Family: "Configuration Management", Description: "Manage cloud resource configurations using infrastructure-as-code and automated compliance checking.", Level: "moderate", ImplementationGuidance: "Use Terraform/CloudFormation. Implement policy-as-code with OPA/Sentinel."},
		{Framework: FrameworkID, ControlID: "SC-40", Title: "Cloud Network Isolation", Family: "System and Communications Protection", Description: "Implement network isolation controls specific to cloud environments including VPCs and security groups.", Level: "moderate", ImplementationGuidance: "Use private subnets for sensitive workloads. Implement VPC peering controls."},
		{Framework: FrameworkID, ControlID: "SI-16", Title: "Cloud Security Monitoring", Family: "System and Information Integrity", Description: "Monitor cloud service configurations and security posture continuously.", Level: "moderate", ImplementationGuidance: "Use CSPM tools. Monitor for misconfigurations and compliance drift."},
	}
}
