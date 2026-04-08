package cspm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "CSPM"

// Provider implements cloud security posture management controls.
// CSPM covers configuration baselines, resource visibility, and drift detection
// for public cloud environments (AWS, Azure, GCP and multi-cloud).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "cspm"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading CSPM controls")
	return p.writeControls(ctx, embeddedCSPMControls())
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
	p.logger.Info("wrote CSPM controls to storage", "count", count)
	return count, nil
}

func embeddedCSPMControls() []grc.Control {
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-01",
			Title:                  "Cloud Asset Inventory",
			Family:                 "Visibility",
			Description:            "Maintain a complete and accurate inventory of all cloud resources across all accounts and regions. Asset discovery must be automated and run continuously to detect new resources within minutes of provisioning.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1078"},
			ImplementationGuidance: "Enable cloud provider asset management services (e.g. AWS Config, Azure Resource Graph). Export inventory to CMDB. Tag all resources with owner and environment.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-02",
			Title:                  "Secure Configuration Baseline",
			Family:                 "Configuration Management",
			Description:            "Define and enforce secure configuration baselines for all cloud resource types. Baselines must be derived from CIS Benchmarks or equivalent and reviewed at least quarterly.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-732", "CWE-1188"},
			ImplementationGuidance: "Implement policy-as-code (e.g. OPA, AWS Config Rules, Azure Policy). Fail builds that introduce non-compliant configurations. Remediate drift automatically where safe.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-03",
			Title:                  "Misconfiguration Detection and Remediation",
			Family:                 "Continuous Compliance",
			Description:            "Continuously scan cloud environments for security misconfigurations and remediate critical findings within defined SLAs. Critical misconfigurations (e.g. public S3 buckets, unrestricted security groups) must be resolved within 24 hours.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-732", "CWE-284"},
			ImplementationGuidance: "Deploy CSPM tooling (e.g. Prisma Cloud, Wiz, Defender for Cloud). Define severity-based remediation SLAs. Implement auto-remediation for safe, well-understood findings.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-04",
			Title:                  "Network Exposure Minimization",
			Family:                 "Network Security",
			Description:            "Ensure cloud workloads are not unnecessarily exposed to the internet. All inbound rules permitting traffic from 0.0.0.0/0 or ::/0 on sensitive ports must be reviewed and justified.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			ImplementationGuidance: "Audit security groups and firewall rules regularly. Use private endpoints for service-to-service communication. Implement cloud-native WAF for public-facing services.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-05",
			Title:                  "Identity and Privilege Governance",
			Family:                 "Identity Security",
			Description:            "Enforce least-privilege access for all cloud identities including human users, service accounts, and workload identities. Detect and remediate over-privileged roles and unused permissions.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			ImplementationGuidance: "Run IAM Access Analyzer or equivalent. Remove unused roles and permissions. Enforce MFA for all human identities. Use workload identity federation instead of long-lived keys.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-06",
			Title:                  "Data Classification and Protection",
			Family:                 "Data Security",
			Description:            "Classify cloud storage assets by sensitivity level and enforce appropriate protection controls. All sensitive data stores must use encryption at rest with customer-managed keys for the highest classification levels.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-312"},
			ImplementationGuidance: "Enable cloud DLP scanning on object storage. Enforce encryption-at-rest policies. Block public access to all storage buckets by default. Enable versioning and MFA-delete for critical data.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-07",
			Title:                  "Logging and Monitoring Coverage",
			Family:                 "Observability",
			Description:            "Ensure comprehensive logging is enabled across all cloud services and accounts. Logs must be forwarded to a centralized, immutable log store with retention of at least 12 months.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-778"},
			ImplementationGuidance: "Enable CloudTrail/Activity Log across all regions and accounts. Forward to centralized SIEM. Enable VPC Flow Logs and DNS query logs. Set log retention to meet compliance requirements.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CSPM-08",
			Title:                  "Drift Detection and Infrastructure Immutability",
			Family:                 "Configuration Management",
			Description:            "Detect and alert on configuration drift from approved infrastructure-as-code baselines. Production resources must not be modified outside the CI/CD pipeline.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-1188"},
			ImplementationGuidance: "Integrate drift detection into CI/CD (e.g. Terraform plan with drift checks). Alert on out-of-band changes via CloudTrail. Implement preventive controls using service control policies.",
		},
	}
}
