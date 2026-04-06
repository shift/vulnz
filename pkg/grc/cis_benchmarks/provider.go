package cis_benchmarks

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
	CISBenchmarksURL = "https://www.cisecurity.org/cis-benchmarks/controls_catalog.json"
	FrameworkID      = "CIS_Benchmarks_2024"
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "cis_benchmarks" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CIS Benchmarks catalog", "url", CISBenchmarksURL)
	destPath := filepath.Join(os.TempDir(), "cis_benchmarks_catalog.json")
	if err := p.download(ctx, CISBenchmarksURL, destPath); err != nil {
		p.logger.Warn("CIS Benchmarks catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)
	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("CIS Benchmarks catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode CIS Benchmarks catalog: %w", err)
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
	p.logger.Info("wrote CIS Benchmarks controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	return p.writeControls(ctx, embeddedCISControls())
}

func embeddedCISControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "CIS-1.1", Title: "Establish and Maintain Detailed Enterprise Asset Inventory", Family: "Basic Hygiene", Description: "Actively manage all assets connected to the organization's network to identify unauthorized or unmanaged assets.", Level: "high", ImplementationGuidance: "Deploy asset discovery tools. Maintain CMDB with automated updates."},
		{Framework: FrameworkID, ControlID: "CIS-1.2", Title: "Address Unauthorized Assets", Family: "Basic Hygiene", Description: "Ensure that unauthorized assets are removed from the network or denied access.", Level: "high", ImplementationGuidance: "Implement NAC. Quarantine unauthorized devices."},
		{Framework: FrameworkID, ControlID: "CIS-2.1", Title: "Establish and Maintain a Software Inventory", Family: "Basic Hygiene", Description: "Maintain an inventory of all installed software across enterprise assets.", Level: "high", ImplementationGuidance: "Deploy software inventory tools. Track software versions and licenses."},
		{Framework: FrameworkID, ControlID: "CIS-2.2", Title: "Ensure Authorized Software is Currently Supported", Family: "Basic Hygiene", Description: "Ensure that only currently supported software is allowed in the enterprise.", Level: "high", ImplementationGuidance: "Track end-of-life dates. Plan migrations for unsupported software."},
		{Framework: FrameworkID, ControlID: "CIS-2.3", Title: "Address Unauthorized Software", Family: "Basic Hygiene", Description: "Ensure that unauthorized software is removed or denied installation.", Level: "high", ImplementationGuidance: "Implement application whitelisting. Monitor for unauthorized software installation."},
		{Framework: FrameworkID, ControlID: "CIS-3.1", Title: "Establish and Maintain a Data Management Process", Family: "Data Protection", Description: "Develop and maintain a data management process for classification and handling.", Level: "high", ImplementationGuidance: "Define data classification scheme. Implement data handling procedures."},
		{Framework: FrameworkID, ControlID: "CIS-3.2", Title: "Establish and Maintain a Data Inventory", Family: "Data Protection", Description: "Maintain an inventory of data stored across enterprise assets.", Level: "high", ImplementationGuidance: "Map data storage locations. Classify data by sensitivity."},
		{Framework: FrameworkID, ControlID: "CIS-3.3", Title: "Configure Data Access Control Lists", Family: "Data Protection", Description: "Implement access control lists for data based on classification.", Level: "high", ImplementationGuidance: "Apply least privilege to data access. Review permissions regularly."},
		{Framework: FrameworkID, ControlID: "CIS-4.1", Title: "Establish and Maintain a Secure Configuration Process", Family: "Secure Configuration", Description: "Establish and maintain a secure configuration process for enterprise assets and software.", Level: "high", ImplementationGuidance: "Adopt CIS Benchmarks as configuration baseline. Automate configuration management."},
		{Framework: FrameworkID, ControlID: "CIS-4.2", Title: "Establish and Maintain a Secure Configuration Process for Network Infrastructure", Family: "Secure Configuration", Description: "Establish and maintain secure configurations for network devices.", Level: "high", ImplementationGuidance: "Apply CIS Benchmarks for network devices. Disable unused services and ports."},
		{Framework: FrameworkID, ControlID: "CIS-4.3", Title: "Configure Automatic Session Locking", Family: "Secure Configuration", Description: "Configure enterprise assets to automatically lock sessions after inactivity.", Level: "medium", ImplementationGuidance: "Set session timeout to 15 minutes or less. Require re-authentication."},
		{Framework: FrameworkID, ControlID: "CIS-4.4", Title: "Implement and Manage a Firewall on Servers", Family: "Secure Configuration", Description: "Implement and manage a firewall on servers to restrict inbound and outbound traffic.", Level: "high", ImplementationGuidance: "Deploy host-based firewalls. Define rules based on least privilege."},
		{Framework: FrameworkID, ControlID: "CIS-4.5", Title: "Implement and Manage a Firewall on End-User Devices", Family: "Secure Configuration", Description: "Implement and manage a firewall on end-user devices.", Level: "medium", ImplementationGuidance: "Enable OS firewalls. Configure rules for common applications."},
		{Framework: FrameworkID, ControlID: "CIS-4.6", Title: "Securely Manage Enterprise Assets and Software", Family: "Secure Configuration", Description: "Securely manage enterprise assets and software through centralized management.", Level: "high", ImplementationGuidance: "Use centralized configuration management. Enforce security baselines."},
		{Framework: FrameworkID, ControlID: "CIS-5.1", Title: "Establish and Maintain Account Inventory", Family: "Access Control", Description: "Maintain an inventory of all accounts across enterprise assets.", Level: "high", ImplementationGuidance: "Automate account discovery. Track account lifecycle."},
		{Framework: FrameworkID, ControlID: "CIS-5.2", Title: "Use Unique Passwords", Family: "Access Control", Description: "Ensure all accounts use unique passwords to prevent credential reuse attacks.", Level: "high", ImplementationGuidance: "Enforce password uniqueness. Deploy password manager."},
		{Framework: FrameworkID, ControlID: "CIS-5.3", Title: "Disable Dormant Accounts", Family: "Access Control", Description: "Disable dormant accounts after a defined period of inactivity.", Level: "high", ImplementationGuidance: "Disable accounts after 45 days of inactivity. Review dormant accounts quarterly."},
		{Framework: FrameworkID, ControlID: "CIS-5.4", Title: "Restrict Administrator Privileges", Family: "Access Control", Description: "Restrict administrator privileges to only authorized accounts.", Level: "high", ImplementationGuidance: "Implement least privilege. Use PAM for administrative access."},
		{Framework: FrameworkID, ControlID: "CIS-6.1", Title: "Establish and Maintain an Access Control Management Process", Family: "Access Control", Description: "Establish and maintain an access control management process for enterprise assets.", Level: "high", ImplementationGuidance: "Define access request and approval workflow. Implement RBAC."},
		{Framework: FrameworkID, ControlID: "CIS-6.2", Title: "Establish and Maintain an Inventory of Authentication and Authorization Systems", Family: "Access Control", Description: "Maintain an inventory of all authentication and authorization systems.", Level: "high", ImplementationGuidance: "Document all identity systems. Track authentication protocols."},
		{Framework: FrameworkID, ControlID: "CIS-6.3", Title: "Require MFA for Externally-Exposed Applications", Family: "Access Control", Description: "Require MFA for all externally-exposed applications and services.", Level: "high", ImplementationGuidance: "Enforce MFA for all external access. Use phishing-resistant MFA."},
		{Framework: FrameworkID, ControlID: "CIS-7.1", Title: "Establish and Maintain a Vulnerability Management Process", Family: "Vulnerability Management", Description: "Establish and maintain a documented vulnerability management process.", Level: "high", ImplementationGuidance: "Define vulnerability management lifecycle. Assign responsibilities."},
		{Framework: FrameworkID, ControlID: "CIS-7.2", Title: "Establish and Maintain a Remediation Process", Family: "Vulnerability Management", Description: "Establish and maintain a documented risk-based remediation process.", Level: "high", ImplementationGuidance: "Define remediation SLAs by severity. Track remediation progress."},
		{Framework: FrameworkID, ControlID: "CIS-7.3", Title: "Perform Automated Operating System Patch Management", Family: "Vulnerability Management", Description: "Perform operating system patch management on enterprise assets.", Level: "high", ImplementationGuidance: "Automate patch deployment. Test patches before production deployment."},
		{Framework: FrameworkID, ControlID: "CIS-7.4", Title: "Perform Automated Application Patch Management", Family: "Vulnerability Management", Description: "Perform application patch management on enterprise assets.", Level: "high", ImplementationGuidance: "Automate application updates. Prioritize security updates."},
		{Framework: FrameworkID, ControlID: "CIS-7.5", Title: "Perform Automated Vulnerability Scans", Family: "Vulnerability Management", Description: "Perform automated vulnerability scans of internal and external assets.", Level: "high", ImplementationGuidance: "Scan weekly. Remediate critical vulnerabilities within 48 hours."},
		{Framework: FrameworkID, ControlID: "CIS-8.1", Title: "Establish and Maintain an Audit Log Management Process", Family: "Audit Logging", Description: "Establish and maintain an audit log management process.", Level: "high", ImplementationGuidance: "Define log retention policies. Centralize log collection."},
		{Framework: FrameworkID, ControlID: "CIS-8.2", Title: "Collect Audit Logs", Family: "Audit Logging", Description: "Collect audit logs from all enterprise assets.", Level: "high", ImplementationGuidance: "Enable logging on all systems. Forward logs to centralized SIEM."},
		{Framework: FrameworkID, ControlID: "CIS-8.3", Title: "Ensure Adequate Audit Log Storage", Family: "Audit Logging", Description: "Ensure adequate storage capacity for audit logs.", Level: "high", ImplementationGuidance: "Plan log storage capacity. Implement log rotation and archival."},
		{Framework: FrameworkID, ControlID: "CIS-8.4", Title: "Standardize Time Synchronization", Family: "Audit Logging", Description: "Standardize time synchronization across all enterprise assets.", Level: "medium", ImplementationGuidance: "Deploy NTP servers. Ensure all systems use synchronized time."},
		{Framework: FrameworkID, ControlID: "CIS-8.5", Title: "Collect Detailed Audit Logs", Family: "Audit Logging", Description: "Collect detailed audit logs including user activity and system events.", Level: "high", ImplementationGuidance: "Enable detailed logging. Include user identity in all log entries."},
		{Framework: FrameworkID, ControlID: "CIS-8.6", Title: "Collect URL Request Logging", Family: "Audit Logging", Description: "Collect URL request logging from web proxies and firewalls.", Level: "medium", ImplementationGuidance: "Enable web proxy logging. Monitor for suspicious URL patterns."},
		{Framework: FrameworkID, ControlID: "CIS-8.7", Title: "Collect DNS Query Logging", Family: "Audit Logging", Description: "Collect DNS query logging to detect malicious domain activity.", Level: "medium", ImplementationGuidance: "Enable DNS query logging. Monitor for DGA and suspicious domains."},
		{Framework: FrameworkID, ControlID: "CIS-8.8", Title: "Collect DNS Arbitration Logging", Family: "Audit Logging", Description: "Collect DNS arbitration logging to detect DNS-based attacks.", Level: "medium", ImplementationGuidance: "Monitor DNS resolution. Alert on DNS tunneling indicators."},
		{Framework: FrameworkID, ControlID: "CIS-8.9", Title: "Deploy Centralized Log Management", Family: "Audit Logging", Description: "Deploy centralized log management for all enterprise assets.", Level: "high", ImplementationGuidance: "Implement SIEM solution. Define log parsing and correlation rules."},
		{Framework: FrameworkID, ControlID: "CIS-8.10", Title: "Retain Audit Logs", Family: "Audit Logging", Description: "Retain audit logs for a minimum of 90 days.", Level: "high", ImplementationGuidance: "Configure log retention for 90+ days. Archive logs for compliance."},
		{Framework: FrameworkID, ControlID: "CIS-8.11", Title: "Conduct Audit Log Reviews", Family: "Audit Logging", Description: "Conduct regular reviews of audit logs to detect anomalous activity.", Level: "high", ImplementationGuidance: "Automate log analysis. Review security alerts daily."},
		{Framework: FrameworkID, ControlID: "CIS-9.1", Title: "Establish and Maintain an Email Protection Process", Family: "Email and Web Browser Protections", Description: "Establish and maintain an email protection process for the enterprise.", Level: "high", ImplementationGuidance: "Deploy email security gateway. Implement anti-phishing controls."},
		{Framework: FrameworkID, ControlID: "CIS-9.2", Title: "Use DNS Filtering Services", Family: "Email and Web Browser Protections", Description: "Use DNS filtering services to block access to known malicious domains.", Level: "high", ImplementationGuidance: "Deploy DNS filtering. Block known malicious and suspicious domains."},
		{Framework: FrameworkID, ControlID: "CIS-9.3", Title: "Maintain and Enforce Network-Based URL Filters", Family: "Email and Web Browser Protections", Description: "Enforce network-based URL filters on all enterprise assets.", Level: "high", ImplementationGuidance: "Deploy web filtering. Block access to malicious and inappropriate categories."},
		{Framework: FrameworkID, ControlID: "CIS-9.4", Title: "Restrict Unnecessary or Unauthorized Browser Extensions", Family: "Email and Web Browser Protections", Description: "Restrict browser extensions to only authorized and necessary extensions.", Level: "medium", ImplementationGuidance: "Maintain approved extension list. Block unauthorized extensions."},
	}
}
