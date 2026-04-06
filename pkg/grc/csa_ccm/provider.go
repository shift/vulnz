package csa_ccm

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
	CSACCMCatalogURL = "https://cloudsecurityalliance.org/artifacts/ccm/v4/controls_catalog.json"
	FrameworkID      = "CSA_CCM_v4"
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "csa_ccm" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CSA CCM catalog", "url", CSACCMCatalogURL)
	destPath := filepath.Join(os.TempDir(), "csa_ccm_catalog.json")
	if err := p.download(ctx, CSACCMCatalogURL, destPath); err != nil {
		p.logger.Warn("CSA CCM catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)
	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("CSA CCM catalog parse failed, using embedded controls", "error", err)
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
	var controls []grc.Control
	if err := json.NewDecoder(f).Decode(&controls); err != nil {
		return nil, fmt.Errorf("decode CSA CCM catalog: %w", err)
	}
	for i := range controls {
		controls[i].Framework = FrameworkID
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
	p.logger.Info("wrote CSA CCM controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	return p.writeControls(ctx, embeddedCSACCMControls())
}

func embeddedCSACCMControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "AIS-01", Title: "Artificial Intelligence Systems Governance", Family: "AI Security", Description: "Establish governance framework for AI/ML systems used in cloud environments.", Level: "high", ImplementationGuidance: "Define AI risk assessment process. Implement model validation and monitoring."},
		{Framework: FrameworkID, ControlID: "AIS-02", Title: "AI Data Protection", Family: "AI Security", Description: "Protect training data and model outputs from unauthorized access and manipulation.", Level: "high", ImplementationGuidance: "Encrypt training datasets. Implement model access controls."},
		{Framework: FrameworkID, ControlID: "AIS-03", Title: "AI Transparency", Family: "AI Security", Description: "Maintain transparency in AI decision-making processes affecting cloud operations.", Level: "medium", ImplementationGuidance: "Document AI model purposes and limitations. Implement explainability measures."},
		{Framework: FrameworkID, ControlID: "AAI-01", Title: "Audit Planning", Family: "Audit Assurance & Compliance", Description: "Develop comprehensive audit plan covering all cloud service components.", Level: "high", ImplementationGuidance: "Define audit scope and frequency. Coordinate with cloud provider audit programs."},
		{Framework: FrameworkID, ControlID: "AAI-02", Title: "Audit Scope", Family: "Audit Assurance & Compliance", Description: "Define audit scope to include all relevant cloud services and configurations.", Level: "high", ImplementationGuidance: "Include IaaS, PaaS, SaaS in audit scope. Cover shared responsibility boundaries."},
		{Framework: FrameworkID, ControlID: "AAI-03", Title: "Information System Controls", Family: "Audit Assurance & Compliance", Description: "Evaluate effectiveness of information system controls in cloud environment.", Level: "high", ImplementationGuidance: "Assess technical and administrative controls. Review cloud provider SOC reports."},
		{Framework: FrameworkID, ControlID: "AAI-04", Title: "Compliance Monitoring", Family: "Audit Assurance & Compliance", Description: "Monitor compliance with applicable regulations and standards.", Level: "high", ImplementationGuidance: "Implement automated compliance checking. Track regulatory changes."},
		{Framework: FrameworkID, ControlID: "BCR-01", Title: "Business Continuity Management", Family: "Business Continuity Management", Description: "Establish business continuity program for cloud-hosted services.", Level: "high", ImplementationGuidance: "Define BIA for cloud services. Develop BCP with cloud-specific recovery procedures."},
		{Framework: FrameworkID, ControlID: "BCR-02", Title: "Disaster Recovery", Family: "Business Continuity Management", Description: "Implement disaster recovery capabilities for cloud infrastructure.", Level: "high", ImplementationGuidance: "Deploy multi-region redundancy. Test DR procedures quarterly."},
		{Framework: FrameworkID, ControlID: "BCR-03", Title: "Backup Management", Family: "Business Continuity Management", Description: "Manage backup processes for cloud-stored data and configurations.", Level: "high", ImplementationGuidance: "Implement automated backups. Verify backup integrity regularly."},
		{Framework: FrameworkID, ControlID: "CCC-01", Title: "Change Control", Family: "Change Control and Configuration Management", Description: "Manage changes to cloud infrastructure through formal change control process.", Level: "high", ImplementationGuidance: "Implement change advisory board. Use infrastructure-as-code for change tracking."},
		{Framework: FrameworkID, ControlID: "CCC-02", Title: "Configuration Management", Family: "Change Control and Configuration Management", Description: "Maintain configuration baselines for all cloud resources.", Level: "high", ImplementationGuidance: "Document baseline configurations. Monitor for configuration drift."},
		{Framework: FrameworkID, ControlID: "CCC-03", Title: "Automated Configuration", Family: "Change Control and Configuration Management", Description: "Use automated tools for configuration management and deployment.", Level: "medium", ImplementationGuidance: "Implement CI/CD pipelines with security gates. Use policy-as-code."},
		{Framework: FrameworkID, ControlID: "DSI-01", Title: "Data Security and Privacy", Family: "Data Security and Privacy Lifecycle Management", Description: "Implement data lifecycle management controls for cloud-stored data.", Level: "high", ImplementationGuidance: "Classify cloud data. Apply controls based on classification."},
		{Framework: FrameworkID, ControlID: "DSI-02", Title: "Data Encryption", Family: "Data Security and Privacy Lifecycle Management", Description: "Encrypt sensitive data at rest and in transit in cloud environments.", Level: "high", ImplementationGuidance: "Use customer-managed encryption keys. Implement envelope encryption."},
		{Framework: FrameworkID, ControlID: "DSI-03", Title: "Data Retention", Family: "Data Security and Privacy Lifecycle Management", Description: "Define and enforce data retention and deletion policies.", Level: "high", ImplementationGuidance: "Implement automated data lifecycle management. Verify data deletion."},
		{Framework: FrameworkID, ControlID: "DSI-04", Title: "Data Loss Prevention", Family: "Data Security and Privacy Lifecycle Management", Description: "Implement DLP controls to prevent unauthorized data exfiltration from cloud.", Level: "high", ImplementationGuidance: "Deploy cloud-native DLP. Monitor data transfer patterns."},
		{Framework: FrameworkID, ControlID: "DSI-05", Title: "Data Sovereignty", Family: "Data Security and Privacy Lifecycle Management", Description: "Ensure data residency compliance for cloud-stored data.", Level: "high", ImplementationGuidance: "Deploy data in compliant regions. Verify data localization requirements."},
		{Framework: FrameworkID, ControlID: "DST-01", Title: "Secure Development Lifecycle", Family: "Development and Software Security", Description: "Implement secure development practices for cloud-native applications.", Level: "high", ImplementationGuidance: "Follow secure SDLC. Conduct code reviews and security testing."},
		{Framework: FrameworkID, ControlID: "DST-02", Title: "Code Security", Family: "Development and Software Security", Description: "Scan application code for security vulnerabilities before deployment.", Level: "high", ImplementationGuidance: "Integrate SAST/DAST into CI/CD. Remediate findings before release."},
		{Framework: FrameworkID, ControlID: "DST-03", Title: "Third-Party Components", Family: "Development and Software Security", Description: "Manage security risks from third-party and open source components.", Level: "high", ImplementationGuidance: "Maintain SBOM. Scan dependencies for known vulnerabilities."},
		{Framework: FrameworkID, ControlID: "DST-04", Title: "API Security", Family: "Development and Software Security", Description: "Secure APIs used by cloud applications and services.", Level: "high", ImplementationGuidance: "Implement API authentication and rate limiting. Validate all API inputs."},
		{Framework: FrameworkID, ControlID: "DST-05", Title: "Container Security", Family: "Development and Software Security", Description: "Secure container images and runtime environments.", Level: "high", ImplementationGuidance: "Scan container images for vulnerabilities. Implement runtime protection."},
		{Framework: FrameworkID, ControlID: "DST-06", Title: "Infrastructure as Code Security", Family: "Development and Software Security", Description: "Validate infrastructure-as-code templates for security misconfigurations.", Level: "high", ImplementationGuidance: "Scan IaC templates with security tools. Enforce security policies in CI/CD."},
		{Framework: FrameworkID, ControlID: "GRC-01", Title: "Governance Framework", Family: "Governance and Risk Management", Description: "Establish cloud security governance framework aligned with organizational objectives.", Level: "high", ImplementationGuidance: "Define cloud security roles and responsibilities. Establish governance committee."},
		{Framework: FrameworkID, ControlID: "GRC-02", Title: "Risk Assessment", Family: "Governance and Risk Management", Description: "Conduct risk assessments for cloud services and deployments.", Level: "high", ImplementationGuidance: "Assess cloud-specific risks. Review risks after significant changes."},
		{Framework: FrameworkID, ControlID: "GRC-03", Title: "Third-Party Risk Management", Family: "Governance and Risk Management", Description: "Manage risks associated with cloud service providers and third parties.", Level: "high", ImplementationGuidance: "Assess CSP security posture. Review SOC 2 and ISO 27001 certifications."},
		{Framework: FrameworkID, ControlID: "GRC-04", Title: "Policy Management", Family: "Governance and Risk Management", Description: "Develop and maintain cloud security policies and standards.", Level: "high", ImplementationGuidance: "Document cloud security policies. Review annually."},
		{Framework: FrameworkID, ControlID: "GRC-05", Title: "Shared Responsibility", Family: "Governance and Risk Management", Description: "Define and document shared responsibility model with cloud providers.", Level: "high", ImplementationGuidance: "Document responsibility boundaries for each cloud service. Review with legal."},
		{Framework: FrameworkID, ControlID: "HRS-01", Title: "Human Resources Security", Family: "Human Resources", Description: "Implement security controls for personnel with access to cloud environments.", Level: "high", ImplementationGuidance: "Conduct background checks. Define cloud access authorization process."},
		{Framework: FrameworkID, ControlID: "HRS-02", Title: "Security Training", Family: "Human Resources", Description: "Provide cloud security training for all relevant personnel.", Level: "medium", ImplementationGuidance: "Conduct annual cloud security training. Provide role-specific training."},
		{Framework: FrameworkID, ControlID: "HRS-03", Title: "Termination Process", Family: "Human Resources", Description: "Revoke cloud access upon employee termination or role change.", Level: "high", ImplementationGuidance: "Automate access revocation. Conduct exit procedures for cloud access."},
		{Framework: FrameworkID, ControlID: "IAM-01", Title: "Identity and Access Management", Family: "Identity and Access Management", Description: "Implement centralized identity management for cloud environments.", Level: "high", ImplementationGuidance: "Use cloud-native IAM. Implement SSO and federation."},
		{Framework: FrameworkID, ControlID: "IAM-02", Title: "Multi-Factor Authentication", Family: "Identity and Access Management", Description: "Require MFA for all cloud service access.", Level: "high", ImplementationGuidance: "Enforce MFA for all users. Use hardware tokens for privileged access."},
		{Framework: FrameworkID, ControlID: "IAM-03", Title: "Privileged Access Management", Family: "Identity and Access Management", Description: "Control and monitor privileged access to cloud infrastructure.", Level: "high", ImplementationGuidance: "Implement PAM for cloud. Use just-in-time privileged access."},
		{Framework: FrameworkID, ControlID: "IAM-04", Title: "Service Account Management", Family: "Identity and Access Management", Description: "Manage service accounts and workload identities in cloud environments.", Level: "high", ImplementationGuidance: "Use workload identity federation. Rotate service credentials regularly."},
		{Framework: FrameworkID, ControlID: "IAM-05", Title: "Access Review", Family: "Identity and Access Management", Description: "Periodically review cloud access rights and permissions.", Level: "high", ImplementationGuidance: "Conduct quarterly access reviews. Use automated access certification."},
		{Framework: FrameworkID, ControlID: "IPF-01", Title: "Interoperability and Portability", Family: "Interoperability and Portability", Description: "Ensure cloud service interoperability and data portability.", Level: "medium", ImplementationGuidance: "Use standard APIs and data formats. Test data export procedures."},
		{Framework: FrameworkID, ControlID: "IPF-02", Title: "Vendor Lock-in Prevention", Family: "Interoperability and Portability", Description: "Implement strategies to prevent cloud vendor lock-in.", Level: "medium", ImplementationGuidance: "Use multi-cloud architecture where feasible. Maintain exit strategy."},
		{Framework: FrameworkID, ControlID: "IVS-01", Title: "Infrastructure and Virtualization Security", Family: "Infrastructure and Virtualization Security", Description: "Secure virtualization infrastructure hosting cloud workloads.", Level: "high", ImplementationGuidance: "Harden hypervisor configurations. Isolate management networks."},
		{Framework: FrameworkID, ControlID: "IVS-02", Title: "Network Security", Family: "Infrastructure and Virtualization Security", Description: "Implement network security controls for cloud environments.", Level: "high", ImplementationGuidance: "Use security groups and NACLs. Implement network segmentation."},
		{Framework: FrameworkID, ControlID: "IVS-03", Title: "Endpoint Security", Family: "Infrastructure and Virtualization Security", Description: "Secure endpoints accessing cloud services.", Level: "high", ImplementationGuidance: "Deploy EDR on all endpoints. Enforce device compliance policies."},
		{Framework: FrameworkID, ControlID: "IVS-04", Title: "Serverless Security", Family: "Infrastructure and Virtualization Security", Description: "Secure serverless computing environments and functions.", Level: "high", ImplementationGuidance: "Apply least privilege to function permissions. Scan function code for vulnerabilities."},
		{Framework: FrameworkID, ControlID: "IVS-05", Title: "Edge Computing Security", Family: "Infrastructure and Virtualization Security", Description: "Secure edge computing deployments connected to cloud infrastructure.", Level: "high", ImplementationGuidance: "Harden edge devices. Implement secure communication to cloud."},
		{Framework: FrameworkID, ControlID: "LOG-01", Title: "Logging and Monitoring", Family: "Logging and Monitoring", Description: "Implement comprehensive logging and monitoring for cloud environments.", Level: "high", ImplementationGuidance: "Enable cloud-native logging. Centralize logs in SIEM."},
		{Framework: FrameworkID, ControlID: "LOG-02", Title: "Log Protection", Family: "Logging and Monitoring", Description: "Protect log data from unauthorized access and tampering.", Level: "high", ImplementationGuidance: "Use write-once storage for logs. Implement log integrity verification."},
		{Framework: FrameworkID, ControlID: "LOG-03", Title: "Alert Management", Family: "Logging and Monitoring", Description: "Define and manage security alerts for cloud environments.", Level: "high", ImplementationGuidance: "Define alert thresholds. Implement automated alert response procedures."},
		{Framework: FrameworkID, ControlID: "SEF-01", Title: "Security Incident Management", Family: "Security Incident Management", Description: "Establish incident response capabilities for cloud security events.", Level: "high", ImplementationGuidance: "Develop cloud-specific IR playbooks. Conduct incident response exercises."},
		{Framework: FrameworkID, ControlID: "SEF-02", Title: "Incident Detection", Family: "Security Incident Management", Description: "Detect and respond to security incidents in cloud environments.", Level: "high", ImplementationGuidance: "Deploy cloud-native threat detection. Use behavioral analytics."},
		{Framework: FrameworkID, ControlID: "SEF-03", Title: "Incident Reporting", Family: "Security Incident Management", Description: "Report cloud security incidents to appropriate parties within required timeframes.", Level: "high", ImplementationGuidance: "Define reporting procedures. Maintain contact lists for stakeholders."},
	}
}
