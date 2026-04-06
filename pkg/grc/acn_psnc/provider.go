package acn_psnc

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
	ACNPSNCCatalogURL = "https://www.cybersecurity.it/psnc/controls_catalog.json"
	FrameworkID       = "ACN_PSNC_2023_IT"
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
	return "acn_psnc"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ACN PSNC catalog", "url", ACNPSNCCatalogURL)

	destPath := filepath.Join(os.TempDir(), "acn_psnc_catalog.json")
	if err := p.download(ctx, ACNPSNCCatalogURL, destPath); err != nil {
		p.logger.Warn("ACN PSNC catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("ACN PSNC catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode ACN PSNC catalog: %w", err)
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
	p.logger.Info("wrote ACN PSNC controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedACNPSNCControls()
	return p.writeControls(ctx, controls)
}

func embeddedACNPSNCControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "PSNC-01", Title: "Perimetro di Sicurezza Nazionale", Family: "Governance", Description: "Define and maintain the national cybersecurity perimeter for critical digital assets and infrastructure.", Level: "high", ImplementationGuidance: "Map all critical network assets. Define perimeter boundaries per ACN guidelines."},
		{Framework: FrameworkID, ControlID: "PSNC-02", Title: "Classificazione degli Asset Critici", Family: "Governance", Description: "Classify assets based on criticality to national security and essential services.", Level: "high", ImplementationGuidance: "Maintain asset criticality register. Review classification annually."},
		{Framework: FrameworkID, ControlID: "PSNC-03", Title: "Notifica degli Incidenti", Family: "Governance", Description: "Report cybersecurity incidents to ACN within mandated timeframes.", Level: "high", ImplementationGuidance: "Define incident notification procedures. Maintain 24/7 contact with ACN CSIRT."},
		{Framework: FrameworkID, ControlID: "PSNC-04", Title: "Valutazione del Rischio", Family: "Governance", Description: "Conduct periodic risk assessments for perimeter assets.", Level: "high", ImplementationGuidance: "Perform annual risk assessments. Use ACN-approved methodologies."},
		{Framework: FrameworkID, ControlID: "PSNC-05", Title: "Piano di Sicurezza", Family: "Governance", Description: "Develop and maintain security plans for all perimeter entities.", Level: "high", ImplementationGuidance: "Document security measures per asset. Update plans after significant changes."},
		{Framework: FrameworkID, ControlID: "PSNC-06", Title: "Audit di Conformità", Family: "Governance", Description: "Conduct regular compliance audits against PSNC requirements.", Level: "high", ImplementationGuidance: "Schedule annual audits. Engage ACN-accredited assessors."},

		{Framework: FrameworkID, ControlID: "PSNC-07", Title: "Segmentazione della Rete", Family: "Network Security", Description: "Implement network segmentation to isolate critical systems.", Level: "high", ImplementationGuidance: "Deploy firewalls between security zones. Implement micro-segmentation for critical assets."},
		{Framework: FrameworkID, ControlID: "PSNC-08", Title: "Monitoraggio del Traffico", Family: "Network Security", Description: "Monitor network traffic for anomalous patterns and threats.", Level: "high", ImplementationGuidance: "Deploy NDR solutions. Analyze traffic flows for indicators of compromise."},
		{Framework: FrameworkID, ControlID: "PSNC-09", Title: "Protezione dei Confini di Rete", Family: "Network Security", Description: "Secure network perimeter with next-generation firewalls and IDS/IPS.", Level: "high", ImplementationGuidance: "Deploy NGFW at all perimeter points. Keep signatures updated."},
		{Framework: FrameworkID, ControlID: "PSNC-10", Title: "Crittografia delle Comunicazioni", Family: "Network Security", Description: "Encrypt all communications crossing the national cybersecurity perimeter.", Level: "high", ImplementationGuidance: "Use TLS 1.3 for all external communications. Implement mutual TLS for critical connections."},
		{Framework: FrameworkID, ControlID: "PSNC-11", Title: "DNS Security", Family: "Network Security", Description: "Implement DNS security measures to prevent DNS-based attacks.", Level: "medium", ImplementationGuidance: "Deploy DNS filtering. Monitor for DNS tunneling and DGA domains."},
		{Framework: FrameworkID, ControlID: "PSNC-12", Title: "Gestione delle Vulnerabilità di Rete", Family: "Network Security", Description: "Identify and remediate network infrastructure vulnerabilities.", Level: "high", ImplementationGuidance: "Conduct monthly network scans. Patch critical vulnerabilities within 72 hours."},

		{Framework: FrameworkID, ControlID: "PSNC-13", Title: "Hardening dei Sistemi", Family: "System Security", Description: "Harden operating systems and applications per ACN security baselines.", Level: "high", ImplementationGuidance: "Apply ACN hardening guidelines. Maintain configuration baselines."},
		{Framework: FrameworkID, ControlID: "PSNC-14", Title: "Gestione delle Patch", Family: "System Security", Description: "Apply security patches within ACN-mandated timeframes.", Level: "high", ImplementationGuidance: "Maintain patch management process. Test patches before deployment."},
		{Framework: FrameworkID, ControlID: "PSNC-15", Title: "Protezione Endpoint", Family: "System Security", Description: "Deploy endpoint detection and response on all perimeter systems.", Level: "high", ImplementationGuidance: "Install EDR agents on all endpoints. Integrate with central SIEM."},
		{Framework: FrameworkID, ControlID: "PSNC-16", Title: "Controllo delle Applicazioni", Family: "System Security", Description: "Implement application whitelisting and control mechanisms.", Level: "medium", ImplementationGuidance: "Define approved application lists. Block unauthorized software execution."},
		{Framework: FrameworkID, ControlID: "PSNC-17", Title: "Sicurezza dei Database", Family: "System Security", Description: "Secure database systems containing critical national data.", Level: "high", ImplementationGuidance: "Implement database activity monitoring. Encrypt sensitive data at rest."},
		{Framework: FrameworkID, ControlID: "PSNC-18", Title: "Virtualizzazione Sicura", Family: "System Security", Description: "Secure virtualization infrastructure hosting critical workloads.", Level: "high", ImplementationGuidance: "Harden hypervisor configurations. Isolate management networks."},

		{Framework: FrameworkID, ControlID: "PSNC-19", Title: "Gestione delle Identità", Family: "Access Control", Description: "Implement centralized identity management for perimeter systems.", Level: "high", ImplementationGuidance: "Deploy centralized IAM solution. Enforce strong authentication."},
		{Framework: FrameworkID, ControlID: "PSNC-20", Title: "Autenticazione Multifattore", Family: "Access Control", Description: "Require MFA for all access to perimeter systems.", Level: "high", ImplementationGuidance: "Deploy MFA for all users. Use hardware tokens for privileged access."},
		{Framework: FrameworkID, ControlID: "PSNC-21", Title: "Controllo degli Accessi Privilegiati", Family: "Access Control", Description: "Manage and monitor privileged access to critical systems.", Level: "high", ImplementationGuidance: "Implement PAM solution. Record all privileged sessions."},
		{Framework: FrameworkID, ControlID: "PSNC-22", Title: "Gestione dei Segreti", Family: "Access Control", Description: "Securely manage credentials, keys, and other secrets.", Level: "high", ImplementationGuidance: "Deploy secrets management solution. Rotate credentials regularly."},

		{Framework: FrameworkID, ControlID: "PSNC-23", Title: "Centro Operativo di Sicurezza", Family: "Monitoring", Description: "Establish 24/7 security operations center capabilities.", Level: "high", ImplementationGuidance: "Deploy SIEM/SOAR platform. Staff SOC 24/7 with trained analysts."},
		{Framework: FrameworkID, ControlID: "PSNC-24", Title: "Rilevamento delle Minacce", Family: "Monitoring", Description: "Implement advanced threat detection capabilities.", Level: "high", ImplementationGuidance: "Deploy threat intelligence feeds. Use behavioral analytics for anomaly detection."},
		{Framework: FrameworkID, ControlID: "PSNC-25", Title: "Gestione degli Incidenti", Family: "Monitoring", Description: "Establish incident response capabilities aligned with ACN procedures.", Level: "high", ImplementationGuidance: "Define incident response playbooks. Conduct tabletop exercises quarterly."},
		{Framework: FrameworkID, ControlID: "PSNC-26", Title: "Threat Intelligence", Family: "Monitoring", Description: "Consume and integrate threat intelligence relevant to national security.", Level: "high", ImplementationGuidance: "Subscribe to ACN threat feeds. Share IOCs with national CSIRT."},
		{Framework: FrameworkID, ControlID: "PSNC-27", Title: "Analisi Forense", Family: "Monitoring", Description: "Maintain digital forensic investigation capabilities.", Level: "high", ImplementationGuidance: "Train forensic analysts. Maintain chain of custody procedures."},

		{Framework: FrameworkID, ControlID: "PSNC-28", Title: "Continuità Operativa", Family: "Resilience", Description: "Ensure continuity of critical national services.", Level: "high", ImplementationGuidance: "Define RTO/RPO for critical services. Test recovery procedures annually."},
		{Framework: FrameworkID, ControlID: "PSNC-29", Title: "Backup Sicuri", Family: "Resilience", Description: "Maintain secure backups of critical data and systems.", Level: "high", ImplementationGuidance: "Implement immutable backups. Store backups in geographically separate locations."},
		{Framework: FrameworkID, ControlID: "PSNC-30", Title: "Ridondanza dei Sistemi", Family: "Resilience", Description: "Implement redundancy for critical infrastructure components.", Level: "high", ImplementationGuidance: "Deploy active-active configurations. Test failover mechanisms regularly."},

		{Framework: FrameworkID, ControlID: "PSNC-31", Title: "Sicurezza della Catena di Fornitura", Family: "Supply Chain", Description: "Manage cybersecurity risks in the supply chain for critical components.", Level: "high", ImplementationGuidance: "Assess supplier security posture. Include security requirements in contracts."},
		{Framework: FrameworkID, ControlID: "PSNC-32", Title: "Verifica dei Fornitori ICT", Family: "Supply Chain", Description: "Verify security of ICT suppliers per PSNC requirements.", Level: "high", ImplementationGuidance: "Conduct supplier security assessments. Monitor supplier compliance."},
		{Framework: FrameworkID, ControlID: "PSNC-33", Title: "Sicurezza del Software", Family: "Supply Chain", Description: "Ensure security of software components used in critical systems.", Level: "high", ImplementationGuidance: "Maintain SBOM for all critical software. Scan dependencies for vulnerabilities."},
		{Framework: FrameworkID, ControlID: "PSNC-34", Title: "Formazione del Personale", Family: "Awareness", Description: "Provide cybersecurity training for personnel with access to perimeter systems.", Level: "medium", ImplementationGuidance: "Conduct annual security training. Provide role-specific training for technical staff."},
		{Framework: FrameworkID, ControlID: "PSNC-35", Title: "Consapevolezza della Sicurezza", Family: "Awareness", Description: "Maintain security awareness programs for all organizational personnel.", Level: "medium", ImplementationGuidance: "Run phishing simulation campaigns. Publish security awareness materials."},
		{Framework: FrameworkID, ControlID: "PSNC-36", Title: "Protezione dei Dati Personali", Family: "Compliance", Description: "Process personal data in compliance with GDPR and Italian privacy law.", Level: "high", ImplementationGuidance: "Appoint DPO. Conduct DPIAs for high-risk processing activities."},
		{Framework: FrameworkID, ControlID: "PSNC-37", Title: "Documentazione di Conformità", Family: "Compliance", Description: "Maintain documentation demonstrating compliance with PSNC requirements.", Level: "high", ImplementationGuidance: "Maintain compliance evidence repository. Update documentation after changes."},
		{Framework: FrameworkID, ControlID: "PSNC-38", Title: "Cooperazione Internazionale", Family: "Compliance", Description: "Participate in international cybersecurity cooperation frameworks.", Level: "medium", ImplementationGuidance: "Engage with EU cybersecurity agencies. Participate in cross-border exercises."},
		{Framework: FrameworkID, ControlID: "PSNC-39", Title: "Valutazione dei Prodotti ICT", Family: "Compliance", Description: "Evaluate ICT products for security before deployment in critical infrastructure.", Level: "high", ImplementationGuidance: "Conduct security assessments of new products. Prefer certified solutions."},
		{Framework: FrameworkID, ControlID: "PSNC-40", Title: "Reporting Periodico", Family: "Compliance", Description: "Submit periodic security reports to ACN as required by law.", Level: "high", ImplementationGuidance: "Define reporting schedule. Automate report generation where possible."},
	}
}
