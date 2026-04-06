package ens

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
	ENSCatalogURL = "https://www.ccn-cert.cni.es/images/stories/ens/ENS_Catalogo_Controles.json"
	FrameworkID   = "ENS_2022_Spain"
)

// Provider fetches and parses ENS (Esquema Nacional de Seguridad) controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ENS provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "ens"
}

// Run fetches the ENS catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ENS catalog", "url", ENSCatalogURL)

	destPath := filepath.Join(os.TempDir(), "ens_catalog.json")
	if err := p.download(ctx, ENSCatalogURL, destPath); err != nil {
		p.logger.Warn("ENS catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("ENS catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode ENS catalog: %w", err)
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
	p.logger.Info("wrote ENS controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	controls := embeddedENSControls()
	return p.writeControls(ctx, controls)
}

func embeddedENSControls() []grc.Control {
	return []grc.Control{
		// Organization and Management (OP)
		{Framework: FrameworkID, ControlID: "OP.01", Title: "Organización de la seguridad", Family: "Organization", Description: "Establish and maintain an organizational structure for information security with defined roles and responsibilities.", Level: "basic", ImplementationGuidance: "Define security roles in organizational chart. Assign security officer responsibilities."},
		{Framework: FrameworkID, ControlID: "OP.02", Title: "Personal", Family: "Organization", Description: "Ensure personnel with access to sensitive information are properly vetted and trained.", Level: "basic", ImplementationGuidance: "Implement background checks for privileged roles. Conduct annual security awareness training."},
		{Framework: FrameworkID, ControlID: "OP.03", Title: "Uso legítimo y correcto de los recursos", Family: "Organization", Description: "Define acceptable use policies for information systems and resources.", Level: "basic", ImplementationGuidance: "Publish acceptable use policy. Require acknowledgment from all users."},
		{Framework: FrameworkID, ControlID: "OP.04", Title: "Requisitos de seguridad de la información", Family: "Organization", Description: "Define security requirements for information systems based on risk analysis.", Level: "basic", ImplementationGuidance: "Perform risk assessment. Document security requirements in system design specifications."},
		{Framework: FrameworkID, ControlID: "OP.05", Title: "Procedimientos operativos", Family: "Organization", Description: "Document and maintain operational procedures for information systems.", Level: "basic", ImplementationGuidance: "Create standard operating procedures for all critical systems. Review annually."},
		{Framework: FrameworkID, ControlID: "OP.06", Title: "Estructura orgánica de seguridad", Family: "Organization", Description: "Establish security organizational structure with clear reporting lines.", Level: "medium", ImplementationGuidance: "Define security committee. Establish escalation procedures for security incidents."},
		{Framework: FrameworkID, ControlID: "OP.07", Title: "Seguridad basada en el riesgo", Family: "Organization", Description: "Implement risk-based approach to security management.", Level: "medium", ImplementationGuidance: "Conduct annual risk assessments. Maintain risk register with treatment plans."},
		{Framework: FrameworkID, ControlID: "OP.08", Title: "Autorización del sistema de información", Family: "Organization", Description: "Formal authorization process for information systems before production deployment.", Level: "medium", ImplementationGuidance: "Define authorization criteria. Require security sign-off before go-live."},
		{Framework: FrameworkID, ControlID: "OP.09", Title: "Relaciones con terceros", Family: "Organization", Description: "Manage security risks associated with third-party service providers.", Level: "medium", ImplementationGuidance: "Include security requirements in contracts. Conduct periodic third-party audits."},
		{Framework: FrameworkID, ControlID: "OP.10", Title: "Plan de continuidad del servicio", Family: "Organization", Description: "Develop and maintain service continuity plans for critical systems.", Level: "high", ImplementationGuidance: "Define RTO/RPO for critical services. Test continuity plans annually."},
		{Framework: FrameworkID, ControlID: "OP.11", Title: "Gestión de la cadena de suministro", Family: "Organization", Description: "Manage security risks in the supply chain for ICT products and services.", Level: "high", ImplementationGuidance: "Assess supplier security posture. Include security clauses in procurement contracts."},
		{Framework: FrameworkID, ControlID: "OP.12", Title: "Gestión de la configuración", Family: "Organization", Description: "Maintain configuration management for all information system components.", Level: "medium", ImplementationGuidance: "Maintain configuration baseline. Track configuration changes with approval process."},

		// Asset Management (IN)
		{Framework: FrameworkID, ControlID: "IN.01", Title: "Inventario de activos de información", Family: "Asset Management", Description: "Maintain an inventory of all information assets with assigned ownership.", Level: "basic", ImplementationGuidance: "Create asset register. Assign asset owners for each information asset."},
		{Framework: FrameworkID, ControlID: "IN.02", Title: "Inventario de sistemas de información", Family: "Asset Management", Description: "Maintain inventory of all information systems and their components.", Level: "basic", ImplementationGuidance: "Document all systems, applications, and infrastructure components. Keep inventory current."},
		{Framework: FrameworkID, ControlID: "IN.03", Title: "Clasificación de la información", Family: "Asset Management", Description: "Classify information based on sensitivity and criticality.", Level: "basic", ImplementationGuidance: "Define classification levels (public, internal, confidential, restricted). Label information accordingly."},
		{Framework: FrameworkID, ControlID: "IN.04", Title: "Segregación de entornos", Family: "Asset Management", Description: "Separate development, testing, and production environments.", Level: "medium", ImplementationGuidance: "Use separate infrastructure for each environment. Control access between environments."},
		{Framework: FrameworkID, ControlID: "IN.05", Title: "Gestión de soportes", Family: "Asset Management", Description: "Control the handling of removable media and storage devices.", Level: "basic", ImplementationGuidance: "Encrypt removable media. Define procedures for media disposal."},
		{Framework: FrameworkID, ControlID: "IN.06", Title: "Mantenimiento de activos", Family: "Asset Management", Description: "Maintain information assets according to manufacturer specifications.", Level: "medium", ImplementationGuidance: "Schedule preventive maintenance. Keep maintenance records."},
		{Framework: FrameworkID, ControlID: "IN.07", Title: "Limpieza de soportes", Family: "Asset Management", Description: "Ensure secure deletion of information from media before reuse or disposal.", Level: "medium", ImplementationGuidance: "Use approved sanitization methods. Document media destruction."},
		{Framework: FrameworkID, ControlID: "IN.08", Title: "Prevención de fugas de información", Family: "Asset Management", Description: "Implement controls to prevent unauthorized disclosure of information.", Level: "high", ImplementationGuidance: "Deploy DLP solutions. Monitor data transfers for policy violations."},
		{Framework: FrameworkID, ControlID: "IN.09", Title: "Gestión de activos en la nube", Family: "Asset Management", Description: "Manage security of cloud-based information assets.", Level: "medium", ImplementationGuidance: "Maintain cloud asset inventory. Define shared responsibility model."},
		{Framework: FrameworkID, ControlID: "IN.10", Title: "Protección de activos móviles", Family: "Asset Management", Description: "Secure mobile devices and remote working equipment.", Level: "medium", ImplementationGuidance: "Enforce device encryption. Implement mobile device management (MDM)."},

		// Access Control (PL)
		{Framework: FrameworkID, ControlID: "PL.01", Title: "Control de acceso lógico", Family: "Access Control", Description: "Implement logical access controls based on least privilege principle.", Level: "basic", ImplementationGuidance: "Define access control policy. Implement role-based access control (RBAC)."},
		{Framework: FrameworkID, ControlID: "PL.02", Title: "Identificación y autenticación", Family: "Access Control", Description: "Ensure unique identification and authentication for all users.", Level: "basic", ImplementationGuidance: "Require unique user IDs. Enforce strong password policies."},
		{Framework: FrameworkID, ControlID: "PL.03", Title: "Gestión de derechos de acceso", Family: "Access Control", Description: "Manage user access rights throughout the employment lifecycle.", Level: "basic", ImplementationGuidance: "Implement access request and approval workflow. Review access rights periodically."},
		{Framework: FrameworkID, ControlID: "PL.04", Title: "Gestión de credenciales", Family: "Access Control", Description: "Secure management of authentication credentials.", Level: "medium", ImplementationGuidance: "Enforce password complexity. Implement credential rotation policies."},
		{Framework: FrameworkID, ControlID: "PL.05", Title: "Autenticación multifactor", Family: "Access Control", Description: "Require multi-factor authentication for privileged and remote access.", Level: "medium", ImplementationGuidance: "Deploy MFA solution. Require MFA for all administrative access."},
		{Framework: FrameworkID, ControlID: "PL.06", Title: "Control de acceso a la red", Family: "Access Control", Description: "Control access to network resources and segments.", Level: "medium", ImplementationGuidance: "Implement network segmentation. Use firewalls between security zones."},
		{Framework: FrameworkID, ControlID: "PL.07", Title: "Cifrado de comunicaciones", Family: "Access Control", Description: "Encrypt sensitive information during transmission.", Level: "medium", ImplementationGuidance: "Use TLS 1.2+ for all communications. Disable weak cipher suites."},
		{Framework: FrameworkID, ControlID: "PL.08", Title: "Cifrado de almacenamiento", Family: "Access Control", Description: "Encrypt sensitive information at rest.", Level: "high", ImplementationGuidance: "Encrypt databases and file systems containing sensitive data. Manage encryption keys securely."},
		{Framework: FrameworkID, ControlID: "PL.09", Title: "Firma electrónica", Family: "Access Control", Description: "Use qualified electronic signatures for official documents.", Level: "medium", ImplementationGuidance: "Implement qualified signature solutions per eIDAS regulation."},
		{Framework: FrameworkID, ControlID: "PL.10", Title: "Registro de accesos", Family: "Access Control", Description: "Log all access attempts for audit and forensic purposes.", Level: "medium", ImplementationGuidance: "Enable access logging on all systems. Protect log integrity."},
		{Framework: FrameworkID, ControlID: "PL.11", Title: "Control de acceso a servicios", Family: "Access Control", Description: "Control access to information services and applications.", Level: "medium", ImplementationGuidance: "Implement application-level access controls. Define service access policies."},
		{Framework: FrameworkID, ControlID: "PL.12", Title: "Protección de datos personales", Family: "Access Control", Description: "Ensure personal data is processed in compliance with applicable regulations.", Level: "high", ImplementationGuidance: "Implement data protection by design. Conduct DPIAs for high-risk processing."},
		{Framework: FrameworkID, ControlID: "PL.13", Title: "Gestión de sesiones", Family: "Access Control", Description: "Control user session establishment and termination.", Level: "medium", ImplementationGuidance: "Implement session timeouts. Secure session tokens."},
		{Framework: FrameworkID, ControlID: "PL.14", Title: "Privilegios de administrador", Family: "Access Control", Description: "Control and monitor privileged administrative access.", Level: "high", ImplementationGuidance: "Use privileged access management (PAM) solution. Require justification for privileged access."},

		// Continuity (CO)
		{Framework: FrameworkID, ControlID: "CO.01", Title: "Plan de continuidad", Family: "Continuity", Description: "Develop and maintain business continuity plans for critical services.", Level: "medium", ImplementationGuidance: "Define critical business functions. Develop BCP with recovery procedures."},
		{Framework: FrameworkID, ControlID: "CO.02", Title: "Plan de recuperación ante desastres", Family: "Continuity", Description: "Establish disaster recovery capabilities for information systems.", Level: "medium", ImplementationGuidance: "Define RTO/RPO targets. Maintain disaster recovery site or cloud failover."},
		{Framework: FrameworkID, ControlID: "CO.03", Title: "Copias de seguridad", Family: "Continuity", Description: "Perform regular backups of critical information and systems.", Level: "basic", ImplementationGuidance: "Define backup schedule. Test backup restoration periodically."},
		{Framework: FrameworkID, ControlID: "CO.04", Title: "Análisis de impacto", Family: "Continuity", Description: "Conduct business impact analysis for critical services.", Level: "medium", ImplementationGuidance: "Identify critical processes. Assess financial and operational impact of disruption."},
		{Framework: FrameworkID, ControlID: "CO.05", Title: "Pruebas de continuidad", Family: "Continuity", Description: "Regularly test continuity and recovery plans.", Level: "medium", ImplementationGuidance: "Conduct tabletop exercises annually. Perform full failover tests."},
		{Framework: FrameworkID, ControlID: "CO.06", Title: "Redundancia de componentes", Family: "Continuity", Description: "Implement redundancy for critical system components.", Level: "high", ImplementationGuidance: "Deploy redundant network paths, servers, and storage. Test failover mechanisms."},
		{Framework: FrameworkID, ControlID: "CO.07", Title: "Protección física", Family: "Continuity", Description: "Protect physical facilities housing information systems.", Level: "basic", ImplementationGuidance: "Implement physical access controls. Deploy environmental monitoring."},
		{Framework: FrameworkID, ControlID: "CO.08", Title: "Gestión de capacidad", Family: "Continuity", Description: "Monitor and plan capacity to ensure service availability.", Level: "medium", ImplementationGuidance: "Monitor resource utilization. Plan capacity upgrades proactively."},
		{Framework: FrameworkID, ControlID: "CO.09", Title: "Disponibilidad de servicios", Family: "Continuity", Description: "Ensure availability of critical information services.", Level: "high", ImplementationGuidance: "Implement load balancing. Define SLA targets and monitoring."},

		// Monitoring and Response (MO)
		{Framework: FrameworkID, ControlID: "MO.01", Title: "Monitorización continua", Family: "Monitoring", Description: "Implement continuous monitoring of information systems.", Level: "medium", ImplementationGuidance: "Deploy SIEM solution. Monitor security events 24/7."},
		{Framework: FrameworkID, ControlID: "MO.02", Title: "Gestión de incidentes", Family: "Monitoring", Description: "Establish incident detection, response, and recovery procedures.", Level: "medium", ImplementationGuidance: "Define incident classification. Create incident response playbooks."},
		{Framework: FrameworkID, ControlID: "MO.03", Title: "Gestión de vulnerabilidades", Family: "Monitoring", Description: "Identify, assess, and remediate vulnerabilities in information systems.", Level: "medium", ImplementationGuidance: "Conduct regular vulnerability scans. Prioritize remediation based on risk."},
		{Framework: FrameworkID, ControlID: "MO.04", Title: "Auditoría de seguridad", Family: "Monitoring", Description: "Conduct periodic security audits and assessments.", Level: "medium", ImplementationGuidance: "Schedule annual security audits. Address audit findings within defined timeframes."},
		{Framework: FrameworkID, ControlID: "MO.05", Title: "Análisis de registros", Family: "Monitoring", Description: "Collect and analyze security logs from all information systems.", Level: "medium", ImplementationGuidance: "Centralize log collection. Define log retention periods."},
		{Framework: FrameworkID, ControlID: "MO.06", Title: "Detección de intrusiones", Family: "Monitoring", Description: "Deploy intrusion detection and prevention systems.", Level: "high", ImplementationGuidance: "Deploy IDS/IPS at network perimeter. Keep signatures updated."},
		{Framework: FrameworkID, ControlID: "MO.07", Title: "Análisis forense", Family: "Monitoring", Description: "Maintain capability for digital forensic investigation.", Level: "high", ImplementationGuidance: "Define evidence preservation procedures. Train staff in forensic techniques."},
		{Framework: FrameworkID, ControlID: "MO.08", Title: "Mejora continua", Family: "Monitoring", Description: "Continuously improve the security posture based on lessons learned.", Level: "medium", ImplementationGuidance: "Conduct post-incident reviews. Update security controls based on findings."},
		{Framework: FrameworkID, ControlID: "MO.09", Title: "Notificación de incidentes", Family: "Monitoring", Description: "Report security incidents to relevant authorities within required timeframes.", Level: "high", ImplementationGuidance: "Define notification procedures per CCN-CERT requirements. Maintain contact lists."},
		{Framework: FrameworkID, ControlID: "MO.10", Title: "Gestión de cambios", Family: "Monitoring", Description: "Control changes to information systems through formal change management.", Level: "medium", ImplementationGuidance: "Implement change advisory board. Test changes in non-production before deployment."},
		{Framework: FrameworkID, ControlID: "MO.11", Title: "Protección del desarrollo", Family: "Monitoring", Description: "Implement secure software development practices.", Level: "high", ImplementationGuidance: "Follow secure SDLC. Conduct code reviews and security testing."},
		{Framework: FrameworkID, ControlID: "MO.12", Title: "Pruebas de penetración", Family: "Monitoring", Description: "Conduct periodic penetration testing of information systems.", Level: "high", ImplementationGuidance: "Engage qualified penetration testers annually. Remediate findings within defined SLAs."},
		{Framework: FrameworkID, ControlID: "MO.13", Title: "Gestión de parches", Family: "Monitoring", Description: "Apply security patches in a timely manner.", Level: "basic", ImplementationGuidance: "Maintain patch management process. Test patches before deployment."},
	}
}
