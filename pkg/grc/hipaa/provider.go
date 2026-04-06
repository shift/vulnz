package hipaa

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
	HIPAACatalogURL = "https://www.hhs.gov/sites/default/files/hipaa-security-rule-catalog.json"
	FrameworkID     = "HIPAA_Security_Rule"
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
	return "hipaa"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching HIPAA Security Rule catalog", "url", HIPAACatalogURL)

	destPath := filepath.Join(os.TempDir(), "hipaa_catalog.json")
	if err := p.download(ctx, HIPAACatalogURL, destPath); err != nil {
		p.logger.Warn("HIPAA catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("HIPAA catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode HIPAA catalog: %w", err)
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
	p.logger.Info("wrote HIPAA controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedHIPAAControls()
	return p.writeControls(ctx, controls)
}

func embeddedHIPAAControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "164.308(a)(1)", Title: "Security Management Process", Family: "Administrative Safeguards", Description: "Implement policies and procedures to prevent, detect, contain, and compensate for security violations.", Level: "high", ImplementationGuidance: "Conduct risk analysis. Implement risk management program. Apply sanctions policy."},
		{Framework: FrameworkID, ControlID: "164.308(a)(1)(ii)(A)", Title: "Risk Analysis", Family: "Administrative Safeguards", Description: "Conduct accurate and thorough risk assessment of potential risks and vulnerabilities to ePHI.", Level: "high", ImplementationGuidance: "Document risk assessment methodology. Review risks annually or after significant changes."},
		{Framework: FrameworkID, ControlID: "164.308(a)(1)(ii)(B)", Title: "Risk Management", Family: "Administrative Safeguards", Description: "Implement security measures sufficient to reduce risks and vulnerabilities to ePHI.", Level: "high", ImplementationGuidance: "Document risk treatment decisions. Implement controls based on risk assessment findings."},
		{Framework: FrameworkID, ControlID: "164.308(a)(1)(ii)(C)", Title: "Sanction Policy", Family: "Administrative Safeguards", Description: "Apply appropriate sanctions against workforce members who fail to comply with security policies.", Level: "high", ImplementationGuidance: "Document sanction policy in workforce guidelines. Apply sanctions consistently."},
		{Framework: FrameworkID, ControlID: "164.308(a)(1)(ii)(D)", Title: "Information System Activity Review", Family: "Administrative Safeguards", Description: "Implement procedures to regularly review records of information system activity.", Level: "high", ImplementationGuidance: "Review audit logs regularly. Monitor for anomalous access patterns to ePHI."},
		{Framework: FrameworkID, ControlID: "164.308(a)(2)", Title: "Assigned Security Responsibility", Family: "Administrative Safeguards", Description: "Identify a security official responsible for development and implementation of security policies.", Level: "high", ImplementationGuidance: "Appoint security officer in writing. Define responsibilities and authority."},
		{Framework: FrameworkID, ControlID: "164.308(a)(3)", Title: "Workforce Security", Family: "Administrative Safeguards", Description: "Implement policies and procedures to ensure workforce members have appropriate access to ePHI.", Level: "high", ImplementationGuidance: "Implement authorization and supervision procedures. Clear workforce access upon termination."},
		{Framework: FrameworkID, ControlID: "164.308(a)(3)(i)", Title: "Authorization and/or Supervision", Family: "Administrative Safeguards", Description: "Implement procedures for authorization and/or supervision of workforce access to ePHI.", Level: "high", ImplementationGuidance: "Define access authorization workflow. Supervise workforce access to ePHI systems."},
		{Framework: FrameworkID, ControlID: "164.308(a)(3)(ii)(A)", Title: "Workforce Clearance Procedure", Family: "Administrative Safeguards", Description: "Implement procedures to determine that access to ePHI is appropriate.", Level: "high", ImplementationGuidance: "Conduct background checks for workforce with ePHI access. Document clearance procedures."},
		{Framework: FrameworkID, ControlID: "164.308(a)(3)(ii)(B)", Title: "Termination Procedures", Family: "Administrative Safeguards", Description: "Implement procedures for terminating access to ePHI when employment ends.", Level: "high", ImplementationGuidance: "Automate access revocation upon termination. Conduct exit interviews."},
		{Framework: FrameworkID, ControlID: "164.308(a)(4)", Title: "Information Access Management", Family: "Administrative Safeguards", Description: "Implement policies and procedures for authorizing access to ePHI based on role or function.", Level: "high", ImplementationGuidance: "Implement role-based access control. Apply minimum necessary standard."},
		{Framework: FrameworkID, ControlID: "164.308(a)(4)(i)", Title: "Isolating Healthcare Clearinghouse Functions", Family: "Administrative Safeguards", Description: "If a healthcare clearinghouse is part of a larger organization, implement policies to protect ePHI.", Level: "high", ImplementationGuidance: "Logically separate clearinghouse functions. Restrict access to clearinghouse data."},
		{Framework: FrameworkID, ControlID: "164.308(a)(4)(ii)(A)", Title: "Access Authorization", Family: "Administrative Safeguards", Description: "Implement policies and procedures for granting access to ePHI.", Level: "high", ImplementationGuidance: "Document access authorization criteria. Review access rights periodically."},
		{Framework: FrameworkID, ControlID: "164.308(a)(4)(ii)(B)", Title: "Access Establishment and Modification", Family: "Administrative Safeguards", Description: "Implement policies and procedures for establishing, documenting, reviewing, and modifying access.", Level: "high", ImplementationGuidance: "Define access request and approval workflow. Review access rights at least annually."},
		{Framework: FrameworkID, ControlID: "164.308(a)(5)", Title: "Security Awareness and Training", Family: "Administrative Safeguards", Description: "Implement security awareness and training program for all workforce members.", Level: "high", ImplementationGuidance: "Conduct annual security awareness training. Provide role-specific training."},
		{Framework: FrameworkID, ControlID: "164.308(a)(5)(ii)(A)", Title: "Security Reminders", Family: "Administrative Safeguards", Description: "Implement periodic security reminders for workforce members.", Level: "medium", ImplementationGuidance: "Send monthly security tips. Conduct phishing simulation exercises."},
		{Framework: FrameworkID, ControlID: "164.308(a)(5)(ii)(B)", Title: "Protection from Malicious Software", Family: "Administrative Safeguards", Description: "Train workforce on procedures for guarding against, detecting, and reporting malicious software.", Level: "high", ImplementationGuidance: "Train on malware recognition. Define reporting procedures for suspected malware."},
		{Framework: FrameworkID, ControlID: "164.308(a)(5)(ii)(C)", Title: "Log-in Monitoring", Family: "Administrative Safeguards", Description: "Implement procedures for monitoring log-in attempts and reporting discrepancies.", Level: "medium", ImplementationGuidance: "Monitor for failed login attempts. Alert on suspicious login patterns."},
		{Framework: FrameworkID, ControlID: "164.308(a)(5)(ii)(D)", Title: "Password Management", Family: "Administrative Safeguards", Description: "Implement procedures for creating, changing, and safeguarding passwords.", Level: "high", ImplementationGuidance: "Enforce password complexity requirements. Implement password rotation policies."},
		{Framework: FrameworkID, ControlID: "164.308(a)(6)", Title: "Security Incident Procedures", Family: "Administrative Safeguards", Description: "Implement policies and procedures to address security incidents.", Level: "high", ImplementationGuidance: "Define incident response procedures. Document and track all security incidents."},
		{Framework: FrameworkID, ControlID: "164.308(a)(6)(ii)", Title: "Response and Reporting", Family: "Administrative Safeguards", Description: "Identify and respond to suspected or known security incidents; mitigate harmful effects.", Level: "high", ImplementationGuidance: "Define incident classification. Establish reporting timelines per breach notification rule."},
		{Framework: FrameworkID, ControlID: "164.308(a)(7)", Title: "Contingency Plan", Family: "Administrative Safeguards", Description: "Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI.", Level: "high", ImplementationGuidance: "Develop contingency plan. Test and revise plan regularly."},
		{Framework: FrameworkID, ControlID: "164.308(a)(7)(ii)(A)", Title: "Data Backup Plan", Family: "Administrative Safeguards", Description: "Establish and implement procedures to create and maintain retrievable exact copies of ePHI.", Level: "high", ImplementationGuidance: "Define backup schedule. Test backup restoration procedures."},
		{Framework: FrameworkID, ControlID: "164.308(a)(7)(ii)(B)", Title: "Disaster Recovery Plan", Family: "Administrative Safeguards", Description: "Establish procedures to restore any loss of data.", Level: "high", ImplementationGuidance: "Document disaster recovery procedures. Conduct annual DR testing."},
		{Framework: FrameworkID, ControlID: "164.308(a)(7)(ii)(C)", Title: "Emergency Mode Operation Plan", Family: "Administrative Safeguards", Description: "Establish procedures to enable continuation of critical business processes during emergency operations.", Level: "high", ImplementationGuidance: "Define critical systems for emergency mode. Document emergency operating procedures."},
		{Framework: FrameworkID, ControlID: "164.308(a)(8)", Title: "Evaluation", Family: "Administrative Safeguards", Description: "Perform periodic technical and non-technical evaluation of security policies and procedures.", Level: "high", ImplementationGuidance: "Conduct annual security evaluations. Document findings and remediation plans."},

		{Framework: FrameworkID, ControlID: "164.310(a)(1)", Title: "Facility Access Controls", Family: "Physical Safeguards", Description: "Implement policies and procedures to limit physical access to electronic information systems.", Level: "high", ImplementationGuidance: "Control physical access to facilities. Implement visitor management procedures."},
		{Framework: FrameworkID, ControlID: "164.310(a)(2)(i)", Title: "Contingency Operations", Family: "Physical Safeguards", Description: "Establish procedures that allow facility access in support of restoration of lost data under disaster recovery plans.", Level: "high", ImplementationGuidance: "Define emergency facility access procedures. Maintain contact lists for key personnel."},
		{Framework: FrameworkID, ControlID: "164.310(a)(2)(ii)", Title: "Facility Security Plan", Family: "Physical Safeguards", Description: "Implement policies and procedures to safeguard facilities and equipment from unauthorized access.", Level: "high", ImplementationGuidance: "Document facility security plan. Implement layered physical security controls."},
		{Framework: FrameworkID, ControlID: "164.310(a)(2)(iii)", Title: "Access Control and Validation Procedures", Family: "Physical Safeguards", Description: "Implement procedures to control and validate a person's access to facilities.", Level: "high", ImplementationGuidance: "Deploy badge access systems. Maintain visitor logs."},
		{Framework: FrameworkID, ControlID: "164.310(a)(2)(iv)", Title: "Maintenance Records", Family: "Physical Safeguards", Description: "Implement policies and procedures to document repairs and modifications to physical components.", Level: "medium", ImplementationGuidance: "Maintain maintenance logs for security-relevant equipment. Track repair history."},
		{Framework: FrameworkID, ControlID: "164.310(b)", Title: "Workstation Use", Family: "Physical Safeguards", Description: "Implement policies and procedures specifying proper functions and access to workstations containing ePHI.", Level: "high", ImplementationGuidance: "Define workstation use policy. Position screens to prevent unauthorized viewing."},
		{Framework: FrameworkID, ControlID: "164.310(c)", Title: "Workstation Security", Family: "Physical Safeguards", Description: "Implement physical safeguards for all workstations that access ePHI.", Level: "high", ImplementationGuidance: "Implement automatic screen locks. Use privacy screens for workstations in public areas."},
		{Framework: FrameworkID, ControlID: "164.310(d)(1)", Title: "Device and Media Controls", Family: "Physical Safeguards", Description: "Implement policies and procedures governing receipt and removal of hardware and electronic media containing ePHI.", Level: "high", ImplementationGuidance: "Track removable media. Implement device encryption policies."},
		{Framework: FrameworkID, ControlID: "164.310(d)(2)(i)", Title: "Disposal", Family: "Physical Safeguards", Description: "Implement policies and procedures for the final disposition of ePHI and hardware containing ePHI.", Level: "high", ImplementationGuidance: "Use approved media sanitization methods. Document media destruction."},
		{Framework: FrameworkID, ControlID: "164.310(d)(2)(ii)", Title: "Media Re-use", Family: "Physical Safeguards", Description: "Implement procedures for removal of ePHI from electronic media before re-use.", Level: "high", ImplementationGuidance: "Sanitize media before re-use. Document sanitization procedures."},
		{Framework: FrameworkID, ControlID: "164.310(d)(2)(iii)", Title: "Accountability", Family: "Physical Safeguards", Description: "Maintain a record of the movements of hardware and electronic media containing ePHI.", Level: "medium", ImplementationGuidance: "Track hardware and media inventory. Document media transfers."},
		{Framework: FrameworkID, ControlID: "164.310(d)(2)(iv)", Title: "Data Backup and Storage", Family: "Physical Safeguards", Description: "Create a retrievable, exact copy of ePHI before moving equipment.", Level: "high", ImplementationGuidance: "Backup data before equipment moves. Verify backup integrity before transport."},

		{Framework: FrameworkID, ControlID: "164.312(a)(1)", Title: "Access Control", Family: "Technical Safeguards", Description: "Implement technical policies and procedures for electronic information systems that maintain ePHI.", Level: "high", ImplementationGuidance: "Implement unique user identification. Enable emergency access procedures."},
		{Framework: FrameworkID, ControlID: "164.312(a)(2)(i)", Title: "Unique User Identification", Family: "Technical Safeguards", Description: "Assign a unique name and/or number for identifying and tracking user identity.", Level: "high", ImplementationGuidance: "Enforce unique user IDs across all systems. Prohibit shared accounts."},
		{Framework: FrameworkID, ControlID: "164.312(a)(2)(ii)", Title: "Emergency Access Procedure", Family: "Technical Safeguards", Description: "Establish procedures for obtaining necessary ePHI during an emergency.", Level: "high", ImplementationGuidance: "Define break-glass access procedures. Log and review emergency access events."},
		{Framework: FrameworkID, ControlID: "164.312(a)(2)(iii)", Title: "Automatic Logoff", Family: "Technical Safeguards", Description: "Implement electronic procedures that terminate an electronic session after a predetermined time.", Level: "high", ImplementationGuidance: "Configure session timeout (15 minutes max). Implement automatic logoff for idle sessions."},
		{Framework: FrameworkID, ControlID: "164.312(a)(2)(iv)", Title: "Encryption and Decryption", Family: "Technical Safeguards", Description: "Implement mechanism to encrypt and decrypt ePHI.", Level: "high", ImplementationGuidance: "Encrypt ePHI at rest using AES-256. Manage encryption keys securely."},
		{Framework: FrameworkID, ControlID: "164.312(b)", Title: "Audit Controls", Family: "Technical Safeguards", Description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems containing ePHI.", Level: "high", ImplementationGuidance: "Enable audit logging on all systems with ePHI. Centralize log collection."},
		{Framework: FrameworkID, ControlID: "164.312(c)(1)", Title: "Integrity", Family: "Technical Safeguards", Description: "Implement policies and procedures to protect ePHI from improper alteration or destruction.", Level: "high", ImplementationGuidance: "Implement integrity controls (checksums, digital signatures). Monitor for unauthorized changes."},
		{Framework: FrameworkID, ControlID: "164.312(c)(2)", Title: "Mechanism to Authenticate ePHI", Family: "Technical Safeguards", Description: "Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed.", Level: "high", ImplementationGuidance: "Use cryptographic hashing for ePHI integrity verification. Implement file integrity monitoring."},
		{Framework: FrameworkID, ControlID: "164.312(d)", Title: "Person or Entity Authentication", Family: "Technical Safeguards", Description: "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.", Level: "high", ImplementationGuidance: "Implement strong authentication mechanisms. Deploy MFA for remote access."},
		{Framework: FrameworkID, ControlID: "164.312(e)(1)", Title: "Transmission Security", Family: "Technical Safeguards", Description: "Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic networks.", Level: "high", ImplementationGuidance: "Use TLS 1.2+ for all ePHI in transit. Disable weak cipher suites."},
		{Framework: FrameworkID, ControlID: "164.312(e)(2)(i)", Title: "Integrity Controls", Family: "Technical Safeguards", Description: "Implement security measures to ensure that electronically transmitted ePHI is not improperly modified without detection.", Level: "high", ImplementationGuidance: "Use message authentication codes. Implement digital signatures for critical transmissions."},
		{Framework: FrameworkID, ControlID: "164.312(e)(2)(ii)", Title: "Encryption", Family: "Technical Safeguards", Description: "Implement mechanism to encrypt ePHI whenever deemed appropriate.", Level: "high", ImplementationGuidance: "Encrypt ePHI in transit using TLS. Use VPN for remote access to ePHI systems."},
	}
}
