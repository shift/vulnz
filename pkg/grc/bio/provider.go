package bio

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
	BIOCatalogURL = "https://www.bio-overheid.nl/binaries/bio/documenten/catalogus/BIO_Catalogus_2022.json"
	FrameworkID   = "BIO_2022_NL"
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
	return "bio"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching BIO catalog", "url", BIOCatalogURL)

	destPath := filepath.Join(os.TempDir(), "bio_catalog.json")
	if err := p.download(ctx, BIOCatalogURL, destPath); err != nil {
		p.logger.Warn("BIO catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("BIO catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode BIO catalog: %w", err)
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
	p.logger.Info("wrote BIO controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedBIOControls()
	return p.writeControls(ctx, controls)
}

func embeddedBIOControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "BIO-01", Title: "Informatiebeveiligingsbeleid", Family: "Beleid", Description: "Establish and maintain an information security policy approved by management.", Level: "basic", ImplementationGuidance: "Define security policy aligned with organizational objectives. Review annually."},
		{Framework: FrameworkID, ControlID: "BIO-02", Title: "Organisatie van informatiebeveiliging", Family: "Organisatie", Description: "Establish a management framework to initiate and control information security within the organization.", Level: "basic", ImplementationGuidance: "Assign information security responsibilities. Define reporting lines."},
		{Framework: FrameworkID, ControlID: "BIO-03", Title: "Verantwoordelijkheden voor middelen", Family: "Organisatie", Description: "Maintain accountability for all information assets with assigned owners.", Level: "basic", ImplementationGuidance: "Maintain asset inventory. Assign asset owners for each information asset."},
		{Framework: FrameworkID, ControlID: "BIO-04", Title: "Scheiding van taken", Family: "Organisatie", Description: "Separate conflicting duties to reduce risk of unauthorized or unintentional modification.", Level: "medium", ImplementationGuidance: "Define role separation requirements. Implement dual control for critical operations."},
		{Framework: FrameworkID, ControlID: "BIO-05", Title: "Contact met autoriteiten", Family: "Organisatie", Description: "Maintain appropriate contacts with relevant authorities and regulatory bodies.", Level: "basic", ImplementationGuidance: "Maintain contact list for law enforcement, NCSC-NL, and supervisory authorities."},
		{Framework: FrameworkID, ControlID: "BIO-06", Title: "Contact met belangengroepen", Family: "Organisatie", Description: "Maintain contacts with special interest groups and professional associations.", Level: "basic", ImplementationGuidance: "Participate in information security forums. Monitor industry best practices."},
		{Framework: FrameworkID, ControlID: "BIO-07", Title: "Onafhankelijke beoordeling", Family: "Organisatie", Description: "Conduct independent reviews of information security controls.", Level: "medium", ImplementationGuidance: "Schedule annual security audits. Engage independent assessors."},
		{Framework: FrameworkID, ControlID: "BIO-08", Title: "Risicobeoordeling", Family: "Risico", Description: "Establish and maintain a risk assessment methodology for information security.", Level: "basic", ImplementationGuidance: "Define risk assessment criteria. Conduct assessments at planned intervals."},
		{Framework: FrameworkID, ControlID: "BIO-09", Title: "Risicobehandeling", Family: "Risico", Description: "Implement risk treatment plans based on risk assessment results.", Level: "basic", ImplementationGuidance: "Document risk treatment decisions. Track implementation of controls."},
		{Framework: FrameworkID, ControlID: "BIO-10", Title: "Acceptatie van risico's", Family: "Risico", Description: "Formally accept residual risks within defined risk appetite.", Level: "medium", ImplementationGuidance: "Document risk acceptance decisions. Require management approval for residual risks."},

		{Framework: FrameworkID, ControlID: "BIO-11", Title: "Toegangsbeleid", Family: "Toegangsbeheer", Description: "Define and implement access control policy based on business requirements.", Level: "basic", ImplementationGuidance: "Document access control rules. Implement least privilege principle."},
		{Framework: FrameworkID, ControlID: "BIO-12", Title: "Gebruikersregistratie", Family: "Toegangsbeheer", Description: "Formal user registration and de-registration procedure for all systems.", Level: "basic", ImplementationGuidance: "Implement automated user provisioning. Define account lifecycle management."},
		{Framework: FrameworkID, ControlID: "BIO-13", Title: "Rechtenbeheer", Family: "Toegangsbeheer", Description: "Manage user access rights based on least privilege and need-to-know.", Level: "basic", ImplementationGuidance: "Implement role-based access control. Review permissions periodically."},
		{Framework: FrameworkID, ControlID: "BIO-14", Title: "Wachtwoordbeheer", Family: "Toegangsbeheer", Description: "Enforce strong password policies and secure credential management.", Level: "basic", ImplementationGuidance: "Require minimum 12 characters. Enforce password complexity and rotation."},
		{Framework: FrameworkID, ControlID: "BIO-15", Title: "Meertrapsauthenticatie", Family: "Toegangsbeheer", Description: "Require multi-factor authentication for access to government systems.", Level: "medium", ImplementationGuidance: "Deploy MFA for all remote and privileged access. Use PKI-based authentication."},
		{Framework: FrameworkID, ControlID: "BIO-16", Title: "Beheer van voorrechten", Family: "Toegangsbeheer", Description: "Control and monitor allocation of privileged access rights.", Level: "medium", ImplementationGuidance: "Implement privileged access management. Log all privileged sessions."},
		{Framework: FrameworkID, ControlID: "BIO-17", Title: "Netwerktoegangsbeheer", Family: "Toegangsbeheer", Description: "Control access to network services and resources.", Level: "medium", ImplementationGuidance: "Implement network segmentation. Use 802.1X for network access control."},
		{Framework: FrameworkID, ControlID: "BIO-18", Title: "Toegangsbeheer besturingssysteem", Family: "Toegangsbeheer", Description: "Implement secure access control for operating systems.", Level: "medium", ImplementationGuidance: "Harden OS configurations. Disable unnecessary services and accounts."},
		{Framework: FrameworkID, ControlID: "BIO-19", Title: "Toegangsbeheer applicaties", Family: "Toegangsbeheer", Description: "Implement application-level access controls.", Level: "medium", ImplementationGuidance: "Define application roles and permissions. Implement SSO where possible."},
		{Framework: FrameworkID, ControlID: "BIO-20", Title: "Gebruikersactiviteiten monitor", Family: "Toegangsbeheer", Description: "Monitor and log user activities for security purposes.", Level: "medium", ImplementationGuidance: "Enable audit logging. Review logs for anomalous behavior."},

		{Framework: FrameworkID, ControlID: "BIO-21", Title: "Cryptographybeleid", Family: "Cryptografie", Description: "Develop and implement cryptography policy for information protection.", Level: "medium", ImplementationGuidance: "Define approved algorithms and key lengths. Align with NCSC-NL guidelines."},
		{Framework: FrameworkID, ControlID: "BIO-22", Title: "Sleutelbeheer", Family: "Cryptografie", Description: "Manage cryptographic keys throughout their lifecycle.", Level: "medium", ImplementationGuidance: "Implement key generation, distribution, storage, and destruction procedures."},
		{Framework: FrameworkID, ControlID: "BIO-23", Title: "Fysieke beveiliging", Family: "Fysiek", Description: "Secure physical access to information processing facilities.", Level: "basic", ImplementationGuidance: "Implement access control systems. Maintain visitor logs."},
		{Framework: FrameworkID, ControlID: "BIO-24", Title: "Beveiliging van kantoren en ruimtes", Family: "Fysiek", Description: "Protect offices, rooms, and facilities from unauthorized access.", Level: "basic", ImplementationGuidance: "Define security perimeters. Implement layered physical security."},
		{Framework: FrameworkID, ControlID: "BIO-25", Title: "Beveiliging van apparatuur", Family: "Fysiek", Description: "Protect equipment from physical and environmental threats.", Level: "basic", ImplementationGuidance: "Deploy environmental controls. Protect against power failures and flooding."},
		{Framework: FrameworkID, ControlID: "BIO-26", Title: "Veilig omgaan met middelen", Family: "Fysiek", Description: "Handle information assets securely throughout their lifecycle.", Level: "basic", ImplementationGuidance: "Define handling procedures for classified information. Implement clean desk policy."},
		{Framework: FrameworkID, ControlID: "BIO-27", Title: "Beveiligingszones", Family: "Fysiek", Description: "Organize facilities into security zones with different protection levels.", Level: "medium", ImplementationGuidance: "Define security zones based on information classification. Control access between zones."},

		{Framework: FrameworkID, ControlID: "BIO-28", Title: "Operationele procedures", Family: "Operaties", Description: "Document and maintain operational procedures for information systems.", Level: "basic", ImplementationGuidance: "Create runbooks for all critical systems. Review procedures annually."},
		{Framework: FrameworkID, ControlID: "BIO-29", Title: "Capaciteitsbeheer", Family: "Operaties", Description: "Monitor and plan capacity to ensure required service levels.", Level: "medium", ImplementationGuidance: "Monitor resource utilization trends. Plan capacity upgrades proactively."},
		{Framework: FrameworkID, ControlID: "BIO-30", Title: "Scheidingsomgeving", Family: "Operaties", Description: "Separate development, testing, and production environments.", Level: "medium", ImplementationGuidance: "Use separate infrastructure for each environment. Control data flow between environments."},
		{Framework: FrameworkID, ControlID: "BIO-31", Title: "Wijzigingsbeheer", Family: "Operaties", Description: "Manage changes to information systems through formal change control.", Level: "medium", ImplementationGuidance: "Implement change advisory board. Test changes before production deployment."},
		{Framework: FrameworkID, ControlID: "BIO-32", Title: "Capaciteits- en prestatiebewaking", Family: "Operaties", Description: "Monitor system capacity and performance metrics.", Level: "medium", ImplementationGuidance: "Define performance baselines. Set up alerting for threshold breaches."},
		{Framework: FrameworkID, ControlID: "BIO-33", Title: "Logboekregistratie", Family: "Operaties", Description: "Maintain audit logs of security-relevant events.", Level: "medium", ImplementationGuidance: "Centralize log collection. Define log retention periods per legal requirements."},
		{Framework: FrameworkID, ControlID: "BIO-34", Title: "Beheer van technische kwetsbaarheden", Family: "Operaties", Description: "Identify and remediate technical vulnerabilities in a timely manner.", Level: "medium", ImplementationGuidance: "Conduct regular vulnerability scans. Prioritize remediation based on risk."},
		{Framework: FrameworkID, ControlID: "BIO-35", Title: "Beperking van klokkenluiders", Family: "Operaties", Description: "Restrict use of system utilities that could override security controls.", Level: "high", ImplementationGuidance: "Control access to system utilities. Monitor utility usage."},

		{Framework: FrameworkID, ControlID: "BIO-36", Title: "Informatieoverdracht", Family: "Communicatie", Description: "Secure transfer of information between organizations and systems.", Level: "medium", ImplementationGuidance: "Define data transfer agreements. Use encryption for sensitive data in transit."},
		{Framework: FrameworkID, ControlID: "BIO-37", Title: "Verzend- en ontvangstprocedures", Family: "Communicatie", Description: "Maintain procedures for secure physical transfer of information media.", Level: "basic", ImplementationGuidance: "Use tracked courier services for sensitive media. Require signature on receipt."},
		{Framework: FrameworkID, ControlID: "BIO-38", Title: "Elektronische berichtgeving", Family: "Communicatie", Description: "Protect information in electronic messaging systems.", Level: "medium", ImplementationGuidance: "Implement email encryption for sensitive communications. Deploy anti-phishing controls."},
		{Framework: FrameworkID, ControlID: "BIO-39", Title: "Vertrouwelijkheidsverklaring", Family: "Communicatie", Description: "Require confidentiality agreements for personnel with access to sensitive information.", Level: "basic", ImplementationGuidance: "Include confidentiality clauses in employment contracts. Review periodically."},

		{Framework: FrameworkID, ControlID: "BIO-40", Title: "Continuïteitsplanning", Family: "Continuïteit", Description: "Develop and maintain business continuity plans for critical processes.", Level: "medium", ImplementationGuidance: "Identify critical business processes. Develop BCP with recovery procedures."},
		{Framework: FrameworkID, ControlID: "BIO-41", Title: "Back-up", Family: "Continuïteit", Description: "Perform regular backups of critical information and systems.", Level: "basic", ImplementationGuidance: "Define backup schedule based on RPO. Test restoration procedures periodically."},
		{Framework: FrameworkID, ControlID: "BIO-42", Title: "Redundantie", Family: "Continuïteit", Description: "Implement redundancy for critical system components.", Level: "medium", ImplementationGuidance: "Deploy redundant network paths, servers, and storage. Test failover mechanisms."},
		{Framework: FrameworkID, ControlID: "BIO-43", Title: "Herstelprocedures", Family: "Continuïteit", Description: "Document and test disaster recovery procedures.", Level: "medium", ImplementationGuidance: "Define RTO targets. Conduct disaster recovery exercises annually."},

		{Framework: FrameworkID, ControlID: "BIO-44", Title: "Informatiebeveiligingsincidenten", Family: "Incidenten", Description: "Establish incident management procedures for information security events.", Level: "medium", ImplementationGuidance: "Define incident classification scheme. Create incident response playbooks."},
		{Framework: FrameworkID, ControlID: "BIO-45", Title: "Melding van zwakke plekken", Family: "Incidenten", Description: "Enable reporting of security weaknesses and vulnerabilities.", Level: "basic", ImplementationGuidance: "Establish vulnerability reporting channel. Acknowledge reports within defined SLA."},
		{Framework: FrameworkID, ControlID: "BIO-46", Title: "Melding van incidenten", Family: "Incidenten", Description: "Report security incidents through appropriate management channels.", Level: "medium", ImplementationGuidance: "Define incident notification procedures. Report to NCSC-NL as required."},
		{Framework: FrameworkID, ControlID: "BIO-47", Title: "Lessons learned", Family: "Incidenten", Description: "Capture and apply lessons learned from security incidents.", Level: "medium", ImplementationGuidance: "Conduct post-incident reviews. Update controls based on findings."},
		{Framework: FrameworkID, ControlID: "BIO-48", Title: "Verzamelen van bewijsmateriaal", Family: "Incidenten", Description: "Maintain capability for digital forensic evidence collection.", Level: "high", ImplementationGuidance: "Define evidence preservation procedures. Train staff in forensic techniques."},

		{Framework: FrameworkID, ControlID: "BIO-49", Title: "Naleving van wettelijke verplichtingen", Family: "Naleving", Description: "Ensure compliance with applicable legal and regulatory requirements.", Level: "basic", ImplementationGuidance: "Maintain register of applicable laws. Conduct periodic compliance assessments."},
		{Framework: FrameworkID, ControlID: "BIO-50", Title: "Intellectuele eigendomsrechten", Family: "Naleving", Description: "Protect intellectual property rights for software and information.", Level: "basic", ImplementationGuidance: "Maintain software license inventory. Enforce acceptable use of copyrighted material."},
		{Framework: FrameworkID, ControlID: "BIO-51", Title: "Bescherming van persoonsgegevens", Family: "Naleving", Description: "Process personal data in compliance with GDPR and Dutch implementation law.", Level: "high", ImplementationGuidance: "Appoint Data Protection Officer. Conduct DPIAs for high-risk processing."},
		{Framework: FrameworkID, ControlID: "BIO-52", Title: "Onafhankelijke beoordeling naleving", Family: "Naleving", Description: "Conduct independent reviews of compliance with security policies.", Level: "medium", ImplementationGuidance: "Schedule annual compliance audits. Address findings within defined timeframes."},
		{Framework: FrameworkID, ControlID: "BIO-53", Title: "Review van toegangsrechten", Family: "Naleving", Description: "Periodically review user access rights for appropriateness.", Level: "medium", ImplementationGuidance: "Conduct quarterly access reviews. Remove unnecessary privileges promptly."},
		{Framework: FrameworkID, ControlID: "BIO-54", Title: "Cloud-diensten", Family: "Cloud", Description: "Manage security risks associated with cloud service providers.", Level: "medium", ImplementationGuidance: "Assess cloud provider security posture. Define data residency requirements."},
		{Framework: FrameworkID, ControlID: "BIO-55", Title: "Supply chain beveiliging", Family: "Cloud", Description: "Manage security risks in the ICT supply chain.", Level: "high", ImplementationGuidance: "Include security requirements in procurement contracts. Assess supplier security."},
		{Framework: FrameworkID, ControlID: "BIO-56", Title: "Mobiliteit", Family: "Cloud", Description: "Secure mobile devices and remote working arrangements.", Level: "medium", ImplementationGuidance: "Implement mobile device management. Enforce encryption on mobile devices."},
		{Framework: FrameworkID, ControlID: "BIO-57", Title: "Internet of Things", Family: "Cloud", Description: "Manage security risks of IoT devices in government environments.", Level: "medium", ImplementationGuidance: "Maintain IoT device inventory. Segment IoT devices on separate network."},
		{Framework: FrameworkID, ControlID: "BIO-58", Title: "Keteninformatiebeveiliging", Family: "Cloud", Description: "Coordinate information security across organizational boundaries.", Level: "high", ImplementationGuidance: "Define security responsibilities in inter-organizational agreements."},
	}
}
