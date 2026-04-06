package secnumcloud

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
	SecNumCloudCatalogURL = "https://cyber.gouv.fr/secnumcloud/controls_catalog.json"
	FrameworkID           = "SecNumCloud_2024_FR"
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
	return "secnumcloud"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching SecNumCloud catalog", "url", SecNumCloudCatalogURL)

	destPath := filepath.Join(os.TempDir(), "secnumcloud_catalog.json")
	if err := p.download(ctx, SecNumCloudCatalogURL, destPath); err != nil {
		p.logger.Warn("SecNumCloud catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("SecNumCloud catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode SecNumCloud catalog: %w", err)
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
	p.logger.Info("wrote SecNumCloud controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedSecNumCloudControls()
	return p.writeControls(ctx, controls)
}

func embeddedSecNumCloudControls() []grc.Control {
	return []grc.Control{
		{Framework: FrameworkID, ControlID: "SNC-01", Title: "Souveraineté des données", Family: "Souveraineté", Description: "Ensure data sovereignty by processing and storing data exclusively within French/EU territory.", Level: "high", ImplementationGuidance: "Deploy infrastructure in EU data centers. Verify data residency through provider attestations."},
		{Framework: FrameworkID, ControlID: "SNC-02", Title: "Contrôle opérationnel", Family: "Souveraineté", Description: "Maintain operational control over cloud infrastructure without foreign interference.", Level: "high", ImplementationGuidance: "Ensure management personnel are EU nationals. Prevent extraterritorial jurisdiction exposure."},
		{Framework: FrameworkID, ControlID: "SNC-03", Title: "Protection contre les lois extraterritoriales", Family: "Souveraineté", Description: "Protect against foreign laws that could compel data disclosure (e.g., US CLOUD Act).", Level: "high", ImplementationGuidance: "Use EU-based legal entities. Implement technical measures to prevent unauthorized access."},
		{Framework: FrameworkID, ControlID: "SNC-04", Title: "Gouvernance de l'opérateur", Family: "Souveraineté", Description: "Ensure cloud operator governance is free from foreign influence.", Level: "high", ImplementationGuidance: "Verify ownership structure. Require French/EU majority control of operating entity."},

		{Framework: FrameworkID, ControlID: "SNC-05", Title: "Chiffrement de bout en bout", Family: "Chiffrement", Description: "Implement end-to-end encryption for all data at rest and in transit.", Level: "high", ImplementationGuidance: "Use ANSSI-approved cryptographic algorithms. Manage encryption keys within EU."},
		{Framework: FrameworkID, ControlID: "SNC-06", Title: "Gestion des clés de chiffrement", Family: "Chiffrement", Description: "Manage cryptographic keys under sole organizational control.", Level: "high", ImplementationGuidance: "Deploy HSM in EU territory. Implement key lifecycle management per ANSSI guidelines."},
		{Framework: FrameworkID, ControlID: "SNC-07", Title: "Chiffrement des métadonnées", Family: "Chiffrement", Description: "Encrypt metadata and traffic analysis data to prevent intelligence gathering.", Level: "high", ImplementationGuidance: "Minimize metadata exposure. Encrypt DNS queries and network flow data."},
		{Framework: FrameworkID, ControlID: "SNC-08", Title: "Algorithmes certifiés", Family: "Chiffrement", Description: "Use only ANSSI-certified cryptographic algorithms and implementations.", Level: "high", ImplementationGuidance: "Reference ANSSI cryptographic recommendations. Avoid deprecated algorithms."},

		{Framework: FrameworkID, ControlID: "SNC-09", Title: "Authentification forte", Family: "Accès", Description: "Require strong authentication for all access to cloud services.", Level: "high", ImplementationGuidance: "Deploy multi-factor authentication. Use qualified certificates for privileged access."},
		{Framework: FrameworkID, ControlID: "SNC-10", Title: "Contrôle d'accès granulaire", Family: "Accès", Description: "Implement fine-grained access controls with least privilege enforcement.", Level: "high", ImplementationGuidance: "Define role-based access policies. Implement attribute-based access control for sensitive data."},
		{Framework: FrameworkID, ControlID: "SNC-11", Title: "Séparation des rôles d'administration", Family: "Accès", Description: "Separate administrative roles to prevent single points of compromise.", Level: "high", ImplementationGuidance: "Define distinct admin roles (network, storage, compute). Require dual authorization for critical operations."},
		{Framework: FrameworkID, ControlID: "SNC-12", Title: "Journalisation des accès", Family: "Accès", Description: "Log all access attempts with tamper-evident audit trails.", Level: "high", ImplementationGuidance: "Centralize audit logs. Implement cryptographic integrity protection for log data."},

		{Framework: FrameworkID, ControlID: "SNC-13", Title: "Isolation des locataires", Family: "Isolation", Description: "Ensure strong isolation between cloud tenants at all infrastructure layers.", Level: "high", ImplementationGuidance: "Use dedicated hardware for sensitive workloads. Verify hypervisor isolation."},
		{Framework: FrameworkID, ControlID: "SNC-14", Title: "Séparation des environnements", Family: "Isolation", Description: "Separate production, development, and testing environments.", Level: "high", ImplementationGuidance: "Deploy separate cloud subscriptions/projects. Prevent cross-environment data access."},
		{Framework: FrameworkID, ControlID: "SNC-15", Title: "Protection contre les canaux auxiliaires", Family: "Isolation", Description: "Mitigate side-channel attacks in multi-tenant environments.", Level: "high", ImplementationGuidance: "Use dedicated hardware for classified workloads. Implement cache partitioning."},

		{Framework: FrameworkID, ControlID: "SNC-16", Title: "Supervision continue", Family: "Supervision", Description: "Implement continuous security monitoring of cloud infrastructure.", Level: "high", ImplementationGuidance: "Deploy SIEM with cloud-native integrations. Monitor for anomalous behavior patterns."},
		{Framework: FrameworkID, ControlID: "SNC-17", Title: "Détection d'intrusion", Family: "Supervision", Description: "Deploy intrusion detection systems for cloud workloads.", Level: "high", ImplementationGuidance: "Use host-based and network-based detection. Correlate alerts across layers."},
		{Framework: FrameworkID, ControlID: "SNC-18", Title: "Analyse des vulnérabilités", Family: "Supervision", Description: "Conduct regular vulnerability assessments of cloud infrastructure.", Level: "high", ImplementationGuidance: "Scan workloads weekly. Remediate critical vulnerabilities within 72 hours."},

		{Framework: FrameworkID, ControlID: "SNC-19", Title: "Plan de reprise d'activité", Family: "Résilience", Description: "Maintain disaster recovery capabilities within EU territory.", Level: "high", ImplementationGuidance: "Deploy active-passive configuration across EU regions. Test failover quarterly."},
		{Framework: FrameworkID, ControlID: "SNC-20", Title: "Sauvegarde souveraine", Family: "Résilience", Description: "Maintain sovereign backup capabilities with data residency guarantees.", Level: "high", ImplementationGuidance: "Store backups in EU-only locations. Encrypt backups with organization-managed keys."},
		{Framework: FrameworkID, ControlID: "SNC-21", Title: "Continuité de service", Family: "Résilience", Description: "Ensure service continuity for critical cloud-hosted services.", Level: "high", ImplementationGuidance: "Define RTO/RPO targets per service. Implement auto-scaling and load balancing."},

		{Framework: FrameworkID, ControlID: "SNC-22", Title: "Évaluation de sécurité", Family: "Certification", Description: "Undergo ANSSI security evaluation and certification process.", Level: "high", ImplementationGuidance: "Engage ANSSI-accredited evaluators. Maintain certification through continuous compliance."},
		{Framework: FrameworkID, ControlID: "SNC-23", Title: "Audit de conformité", Family: "Certification", Description: "Conduct regular compliance audits against SecNumCloud requirements.", Level: "high", ImplementationGuidance: "Schedule annual audits. Maintain evidence of compliance for all controls."},
		{Framework: FrameworkID, ControlID: "SNC-24", Title: "Gestion des non-conformités", Family: "Certification", Description: "Track and remediate non-conformities identified during audits.", Level: "high", ImplementationGuidance: "Maintain corrective action register. Define remediation timelines based on severity."},

		{Framework: FrameworkID, ControlID: "SNC-25", Title: "Sécurité de la chaîne d'approvisionnement", Family: "Supply Chain", Description: "Manage security risks in the cloud supply chain.", Level: "high", ImplementationGuidance: "Assess component suppliers. Maintain SBOM for cloud infrastructure."},
		{Framework: FrameworkID, ControlID: "SNC-26", Title: "Contrôle des mises à jour", Family: "Supply Chain", Description: "Control and verify all software updates applied to cloud infrastructure.", Level: "high", ImplementationGuidance: "Verify update signatures. Test updates in isolated environment before deployment."},
		{Framework: FrameworkID, ControlID: "SNC-27", Title: "Transparence opérationnelle", Family: "Supply Chain", Description: "Maintain full visibility into cloud provider operations and changes.", Level: "high", ImplementationGuidance: "Require change notifications. Maintain access to operational dashboards."},

		{Framework: FrameworkID, ControlID: "SNC-28", Title: "Formation du personnel", Family: "Personnel", Description: "Provide security training for personnel managing SecNumCloud infrastructure.", Level: "medium", ImplementationGuidance: "Conduct annual security training. Provide role-specific training for administrators."},
		{Framework: FrameworkID, ControlID: "SNC-29", Title: "Vérification du personnel", Family: "Personnel", Description: "Conduct background checks for personnel with access to sensitive cloud infrastructure.", Level: "high", ImplementationGuidance: "Perform security clearance checks. Restrict access based on need-to-know."},
		{Framework: FrameworkID, ControlID: "SNC-30", Title: "Gestion des habilitations", Family: "Personnel", Description: "Manage security clearances and access authorizations for cloud personnel.", Level: "high", ImplementationGuidance: "Maintain authorization register. Review clearances annually."},

		{Framework: FrameworkID, ControlID: "SNC-31", Title: "Protection des données sensibles", Family: "Données", Description: "Implement enhanced protection for sensitive and classified data.", Level: "high", ImplementationGuidance: "Classify data by sensitivity level. Apply additional controls for classified data."},
		{Framework: FrameworkID, ControlID: "SNC-32", Title: "Traçabilité des traitements", Family: "Données", Description: "Maintain complete traceability of data processing operations.", Level: "high", ImplementationGuidance: "Log all data access and processing. Maintain processing records per GDPR requirements."},
		{Framework: FrameworkID, ControlID: "SNC-33", Title: "Portabilité des données", Family: "Données", Description: "Ensure data portability to prevent vendor lock-in.", Level: "medium", ImplementationGuidance: "Use standard data formats. Test data export procedures regularly."},

		{Framework: FrameworkID, ControlID: "SNC-34", Title: "Sécurité physique des datacenters", Family: "Physique", Description: "Ensure physical security of datacenters hosting SecNumCloud services.", Level: "high", ImplementationGuidance: "Verify datacenter certifications. Review physical security controls."},
		{Framework: FrameworkID, ControlID: "SNC-35", Title: "Protection environnementale", Family: "Physique", Description: "Protect infrastructure from environmental threats.", Level: "medium", ImplementationGuidance: "Deploy environmental monitoring. Implement fire suppression and flood protection."},

		{Framework: FrameworkID, ControlID: "SNC-36", Title: "Gestion des incidents", Family: "Incidents", Description: "Establish incident response procedures aligned with ANSSI requirements.", Level: "high", ImplementationGuidance: "Define incident classification. Report incidents to ANSSI within mandated timeframes."},
		{Framework: FrameworkID, ControlID: "SNC-37", Title: "Réponse aux incidents", Family: "Incidents", Description: "Maintain incident response capabilities for cloud security events.", Level: "high", ImplementationGuidance: "Develop cloud-specific playbooks. Conduct incident response exercises."},
		{Framework: FrameworkID, ControlID: "SNC-38", Title: "Analyse post-incident", Family: "Incidents", Description: "Conduct thorough post-incident analysis and implement corrective measures.", Level: "high", ImplementationGuidance: "Document lessons learned. Update controls based on incident findings."},

		{Framework: FrameworkID, ControlID: "SNC-39", Title: "Conformité RGPD", Family: "Conformité", Description: "Ensure cloud processing complies with GDPR requirements.", Level: "high", ImplementationGuidance: "Execute data processing agreements. Conduct DPIAs for high-risk processing."},
		{Framework: FrameworkID, ControlID: "SNC-40", Title: "Respect de la réglementation française", Family: "Conformité", Description: "Comply with French cybersecurity and data protection regulations.", Level: "high", ImplementationGuidance: "Monitor regulatory changes. Maintain compliance with LPM and RGI requirements."},

		{Framework: FrameworkID, ControlID: "SNC-41", Title: "Sécurité des API", Family: "Technique", Description: "Secure all APIs used for cloud service management and data access.", Level: "high", ImplementationGuidance: "Implement API authentication and rate limiting. Monitor API usage patterns."},
		{Framework: FrameworkID, ControlID: "SNC-42", Title: "Configuration sécurisée", Family: "Technique", Description: "Maintain secure configurations for all cloud resources.", Level: "high", ImplementationGuidance: "Use infrastructure-as-code with security controls. Validate configurations against baselines."},
		{Framework: FrameworkID, ControlID: "SNC-43", Title: "Gestion des identités de service", Family: "Technique", Description: "Manage service identities and machine-to-machine authentication.", Level: "high", ImplementationGuidance: "Use workload identity federation. Rotate service credentials regularly."},
		{Framework: FrameworkID, ControlID: "SNC-44", Title: "Sécurité du réseau virtuel", Family: "Technique", Description: "Secure virtual network infrastructure and connectivity.", Level: "high", ImplementationGuidance: "Implement virtual network segmentation. Use private endpoints for service access."},
		{Framework: FrameworkID, ControlID: "SNC-45", Title: "Monitoring de performance", Family: "Technique", Description: "Monitor cloud service performance and availability.", Level: "medium", ImplementationGuidance: "Define performance SLAs. Implement automated alerting for threshold breaches."},
	}
}
