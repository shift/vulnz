package cobit

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
	COBITCatalogURL = "https://www.isaca.org/resources/cobit/cobit-2019-controls-catalog.json"
	FrameworkID     = "COBIT_2019"
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "cobit" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching COBIT 2019 catalog", "url", COBITCatalogURL)
	destPath := filepath.Join(os.TempDir(), "cobit_catalog.json")
	if err := p.download(ctx, COBITCatalogURL, destPath); err != nil {
		p.logger.Warn("COBIT catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)
	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("COBIT catalog parse failed, using embedded controls", "error", err)
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
		return nil, fmt.Errorf("decode COBIT catalog: %w", err)
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
	p.logger.Info("wrote COBIT controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	return p.writeControls(ctx, embeddedCOBITControls())
}

func embeddedCOBITControls() []grc.Control {
	return []grc.Control{
		// Governance System (EDM)
		{Framework: FrameworkID, ControlID: "EDM01", Title: "Ensured Governance Framework Setting and Maintenance", Family: "Evaluate, Direct and Monitor", Description: "Establish and maintain the governance system for enterprise IT.", Level: "high", ImplementationGuidance: "Define governance principles. Establish governance bodies and charters."},
		{Framework: FrameworkID, ControlID: "EDM02", Title: "Ensured Benefits Delivery", Family: "Evaluate, Direct and Monitor", Description: "Optimize value, capability, and benefit realization from IT-enabled investments.", Level: "high", ImplementationGuidance: "Define value metrics. Track benefits realization from IT investments."},
		{Framework: FrameworkID, ControlID: "EDM03", Title: "Ensured Risk Optimization", Family: "Evaluate, Direct and Monitor", Description: "Enable risk-aware culture and optimize risk posture considering business objectives.", Level: "high", ImplementationGuidance: "Define risk appetite. Integrate risk management into decision-making."},
		{Framework: FrameworkID, ControlID: "EDM04", Title: "Ensured Resource Optimization", Family: "Evaluate, Direct and Monitor", Description: "Optimize knowledge, people, and technology capabilities and investment.", Level: "high", ImplementationGuidance: "Assess resource capabilities. Optimize IT investment portfolio."},
		{Framework: FrameworkID, ControlID: "EDM05", Title: "Ensured Stakeholder Engagement", Family: "Evaluate, Direct and Monitor", Description: "Ensure stakeholder transparency through reporting and engagement.", Level: "high", ImplementationGuidance: "Define stakeholder communication plan. Publish regular governance reports."},

		// Align, Plan and Organize (APO)
		{Framework: FrameworkID, ControlID: "APO01", Title: "Managed I&T Management Framework", Family: "Align, Plan and Organize", Description: "Maintain an enabling I&T management framework for governance and management.", Level: "high", ImplementationGuidance: "Define I&T management structure. Establish policies and procedures."},
		{Framework: FrameworkID, ControlID: "APO02", Title: "Managed Strategy", Family: "Align, Plan and Organize", Description: "Maintain a strategy for I&T that supports enterprise strategy and stakeholder needs.", Level: "high", ImplementationGuidance: "Develop I&T strategy aligned with business objectives. Review annually."},
		{Framework: FrameworkID, ControlID: "APO03", Title: "Managed Enterprise Architecture", Family: "Align, Plan and Organize", Description: "Maintain an enterprise architecture that enables realization of business strategy.", Level: "high", ImplementationGuidance: "Develop enterprise architecture framework. Maintain architecture repository."},
		{Framework: FrameworkID, ControlID: "APO04", Title: "Managed Innovation", Family: "Align, Plan and Organize", Description: "Create and maintain ideas and innovative concepts for I&T-enabled change.", Level: "medium", ImplementationGuidance: "Establish innovation pipeline. Evaluate emerging technologies."},
		{Framework: FrameworkID, ControlID: "APO05", Title: "Managed Portfolio", Family: "Align, Plan and Organize", Description: "Maintain an I&T portfolio aligned with enterprise strategy and objectives.", Level: "high", ImplementationGuidance: "Maintain project portfolio. Prioritize investments based on value and risk."},
		{Framework: FrameworkID, ControlID: "APO06", Title: "Managed Budget and Costs", Family: "Align, Plan and Organize", Description: "Maintain transparency of I&T costs and enable financial management.", Level: "high", ImplementationGuidance: "Implement IT financial management. Track IT costs against budget."},
		{Framework: FrameworkID, ControlID: "APO07", Title: "Managed Human Resources", Family: "Align, Plan and Organize", Description: "Maintain sufficient and competent I&T staff to achieve enterprise objectives.", Level: "high", ImplementationGuidance: "Define I&T competency framework. Plan workforce development."},
		{Framework: FrameworkID, ControlID: "APO08", Title: "Managed Relationships", Family: "Align, Plan and Organize", Description: "Maintain a transparent understanding of stakeholder needs and engagement.", Level: "high", ImplementationGuidance: "Define stakeholder engagement model. Conduct regular stakeholder reviews."},
		{Framework: FrameworkID, ControlID: "APO09", Title: "Managed Service Agreements", Family: "Align, Plan and Organize", Description: "Define, negotiate, and agree on services to be delivered to stakeholders.", Level: "high", ImplementationGuidance: "Define SLAs for all services. Review service performance regularly."},
		{Framework: FrameworkID, ControlID: "APO10", Title: "Managed Vendors", Family: "Align, Plan and Organize", Description: "Manage vendor relationships and risks to achieve value from I&T-related investments.", Level: "high", ImplementationGuidance: "Assess vendor capabilities. Monitor vendor performance against SLAs."},
		{Framework: FrameworkID, ControlID: "APO11", Title: "Managed Quality", Family: "Align, Plan and Organize", Description: "Maintain quality of I&T products and services aligned with stakeholder needs.", Level: "high", ImplementationGuidance: "Define quality standards. Implement quality assurance processes."},
		{Framework: FrameworkID, ControlID: "APO12", Title: "Managed Risk", Family: "Align, Plan and Organize", Description: "Maintain a current view of I&T-related risk exposure for enterprise risk management.", Level: "high", ImplementationGuidance: "Maintain risk register. Conduct risk assessments at planned intervals."},
		{Framework: FrameworkID, ControlID: "APO13", Title: "Managed Security", Family: "Align, Plan and Organize", Description: "Maintain security of I&T assets and operations to protect enterprise value.", Level: "high", ImplementationGuidance: "Implement information security program. Monitor security posture continuously."},
		{Framework: FrameworkID, ControlID: "APO14", Title: "Managed Data", Family: "Align, Plan and Organize", Description: "Maintain data management capabilities to optimize data as an enterprise asset.", Level: "high", ImplementationGuidance: "Define data governance framework. Implement data quality management."},

		// Build, Acquire and Implement (BAI)
		{Framework: FrameworkID, ControlID: "BAI01", Title: "Managed Programs", Family: "Build, Acquire and Implement", Description: "Manage I&T-related programs to deliver value within investment constraints.", Level: "high", ImplementationGuidance: "Implement program management framework. Track program milestones and budgets."},
		{Framework: FrameworkID, ControlID: "BAI02", Title: "Managed Requirements Definition", Family: "Build, Acquire and Implement", Description: "Maintain a framework for requirements definition for I&T solutions.", Level: "high", ImplementationGuidance: "Define requirements elicitation process. Validate requirements with stakeholders."},
		{Framework: FrameworkID, ControlID: "BAI03", Title: "Managed Solutions Identification and Build", Family: "Build, Acquire and Implement", Description: "Maintain solutions that enable achievement of enterprise objectives.", Level: "high", ImplementationGuidance: "Evaluate build vs buy decisions. Implement solution development lifecycle."},
		{Framework: FrameworkID, ControlID: "BAI04", Title: "Managed Availability and Capacity", Family: "Build, Acquire and Implement", Description: "Optimize availability and capacity of I&T resources to meet current and future demand.", Level: "high", ImplementationGuidance: "Monitor resource utilization. Plan capacity based on growth projections."},
		{Framework: FrameworkID, ControlID: "BAI05", Title: "Managed Organizational Change Enablement", Family: "Build, Acquire and Implement", Description: "Enable organizational change resulting from I&T initiatives.", Level: "medium", ImplementationGuidance: "Develop change management plans. Communicate changes to affected stakeholders."},
		{Framework: FrameworkID, ControlID: "BAI06", Title: "Managed IT Changes", Family: "Build, Acquire and Implement", Description: "Enable changes to I&T solutions and infrastructure to be made without undue risk.", Level: "high", ImplementationGuidance: "Implement change management process. Assess impact of proposed changes."},
		{Framework: FrameworkID, ControlID: "BAI07", Title: "Managed IT Change Acceptance and Transitioning", Family: "Build, Acquire and Implement", Description: "Enable changes to be accepted and transitioned into business processes.", Level: "high", ImplementationGuidance: "Define acceptance criteria. Conduct user acceptance testing."},
		{Framework: FrameworkID, ControlID: "BAI08", Title: "Managed Knowledge", Family: "Build, Acquire and Implement", Description: "Maintain knowledge management to enable effective decision making and operations.", Level: "medium", ImplementationGuidance: "Implement knowledge management system. Capture lessons learned."},
		{Framework: FrameworkID, ControlID: "BAI09", Title: "Managed Assets", Family: "Build, Acquire and Implement", Description: "Maintain I&T-related assets throughout their lifecycle.", Level: "high", ImplementationGuidance: "Maintain asset inventory. Track asset lifecycle from acquisition to disposal."},
		{Framework: FrameworkID, ControlID: "BAI10", Title: "Managed Configuration", Family: "Build, Acquire and Implement", Description: "Maintain information about I&T assets and their interrelationships.", Level: "high", ImplementationGuidance: "Implement CMDB. Track configuration items and relationships."},
		{Framework: FrameworkID, ControlID: "BAI11", Title: "Managed Projects", Family: "Build, Acquire and Implement", Description: "Manage I&T-related projects to deliver value within constraints.", Level: "high", ImplementationGuidance: "Implement project management methodology. Track project performance."},

		// Deliver, Service and Support (DSS)
		{Framework: FrameworkID, ControlID: "DSS01", Title: "Managed Operations", Family: "Deliver, Service and Support", Description: "Manage I&T operations to meet stakeholder needs and enterprise objectives.", Level: "high", ImplementationGuidance: "Define operational procedures. Monitor service performance."},
		{Framework: FrameworkID, ControlID: "DSS02", Title: "Managed Service Requests and Incidents", Family: "Deliver, Service and Support", Description: "Manage service requests and incidents to resolution within agreed service levels.", Level: "high", ImplementationGuidance: "Implement service desk. Track incidents to resolution."},
		{Framework: FrameworkID, ControlID: "DSS03", Title: "Managed Problems", Family: "Deliver, Service and Support", Description: "Enable root-cause analysis of I&T-related incidents to prevent recurrence.", Level: "high", ImplementationGuidance: "Conduct root cause analysis for major incidents. Track problem resolution."},
		{Framework: FrameworkID, ControlID: "DSS04", Title: "Managed Continuity", Family: "Deliver, Service and Support", Description: "Maintain I&T-related continuity capabilities to support enterprise continuity.", Level: "high", ImplementationGuidance: "Develop BCP and DRP. Test recovery procedures regularly."},
		{Framework: FrameworkID, ControlID: "DSS05", Title: "Managed Security Services", Family: "Deliver, Service and Support", Description: "Regulate and control I&T security services to protect enterprise assets.", Level: "high", ImplementationGuidance: "Implement security operations center. Monitor and respond to security events."},
		{Framework: FrameworkID, ControlID: "DSS06", Title: "Managed Business Process Controls", Family: "Deliver, Service and Support", Description: "Maintain business process controls to achieve expected outcomes.", Level: "high", ImplementationGuidance: "Define business process controls. Monitor control effectiveness."},

		// Monitor, Evaluate and Assess (MEA)
		{Framework: FrameworkID, ControlID: "MEA01", Title: "Managed Performance and Conformance Monitoring", Family: "Monitor, Evaluate and Assess", Description: "Monitor and evaluate I&T performance against targets and conformance requirements.", Level: "high", ImplementationGuidance: "Define performance metrics. Monitor conformance with policies and regulations."},
		{Framework: FrameworkID, ControlID: "MEA02", Title: "Managed System of Internal Control", Family: "Monitor, Evaluate and Assess", Description: "Maintain a system of internal control over I&T to enable effective governance.", Level: "high", ImplementationGuidance: "Implement internal control framework. Test control effectiveness."},
		{Framework: FrameworkID, ControlID: "MEA03", Title: "Managed External Compliance Conformance", Family: "Monitor, Evaluate and Assess", Description: "Enable compliance with external legal and regulatory requirements.", Level: "high", ImplementationGuidance: "Maintain compliance register. Conduct compliance assessments."},
		{Framework: FrameworkID, ControlID: "MEA04", Title: "Managed Assurance Initiatives", Family: "Monitor, Evaluate and Assess", Description: "Provide assurance over the effectiveness of the governance system.", Level: "high", ImplementationGuidance: "Plan and execute assurance activities. Report assurance findings to governance body."},
	}
}
