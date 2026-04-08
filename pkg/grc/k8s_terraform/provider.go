package k8s_terraform

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const FrameworkID = "K8S_Terraform_Security"

// Provider implements Kubernetes and Terraform infrastructure-as-code security controls.
// These controls cover secure cluster configuration, workload isolation, IaC policy
// enforcement, and supply chain security for containerised environments.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "k8s_terraform"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading Kubernetes and Terraform security controls")
	return p.writeControls(ctx, embeddedK8sTerraformControls())
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
	p.logger.Info("wrote Kubernetes/Terraform security controls to storage", "count", count)
	return count, nil
}

func embeddedK8sTerraformControls() []grc.Control {
	return []grc.Control{
		{
			Framework:              FrameworkID,
			ControlID:              "K8S-01",
			Title:                  "Pod Security Standards Enforcement",
			Family:                 "Workload Security",
			Description:            "Enforce Kubernetes Pod Security Standards (PSS) at the restricted or baseline level across all namespaces. Pods must not run as root, must use read-only root filesystems where possible, and must not mount the host network, PID, or IPC namespaces.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			ImplementationGuidance: "Configure Pod Security Admission controller to enforce 'restricted' profile in production namespaces. Use OPA Gatekeeper or Kyverno for additional policy enforcement. Fail CI builds that submit non-compliant manifests.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "K8S-02",
			Title:                  "Network Policy Enforcement",
			Family:                 "Network Security",
			Description:            "All Kubernetes namespaces must have default-deny network policies. Explicit allow rules must be defined for each required communication path. East-west traffic between pods must be restricted to the minimum necessary.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			ImplementationGuidance: "Deploy CNI plugin with network policy support (Calico, Cilium). Apply default-deny ingress and egress policies to all namespaces. Document and justify each allowed traffic flow. Use service mesh for mTLS between workloads.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "K8S-03",
			Title:                  "RBAC Least Privilege",
			Family:                 "Access Control",
			Description:            "Kubernetes RBAC must follow least privilege principles. ClusterAdmin bindings must be minimised. Service accounts must not be auto-mounted unless explicitly required. Wildcard permissions in ClusterRoles are prohibited.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			ImplementationGuidance: "Audit RBAC configuration with rbac-audit or polaris. Remove wildcards from ClusterRoles. Set automountServiceAccountToken: false by default. Restrict access to secrets to only pods that require them.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "K8S-04",
			Title:                  "Container Image Supply Chain Security",
			Family:                 "Supply Chain",
			Description:            "All container images must originate from approved registries, be scanned for vulnerabilities before deployment, and be signed using a supply chain security framework. Images with critical vulnerabilities must not be deployed to production.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-1357", "CWE-494"},
			ImplementationGuidance: "Use Sigstore/Cosign for image signing. Deploy Admission controller to enforce signature verification. Scan images with Trivy or Grype in CI. Maintain allowlist of approved base images. Enforce image digest pinning in manifests.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "K8S-05",
			Title:                  "Secret Management and Encryption",
			Family:                 "Secrets Management",
			Description:            "Kubernetes secrets must not contain plaintext sensitive values stored in version control. All secrets must be managed via an external secrets manager or encrypted at rest using envelope encryption with a KMS provider.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-312", "CWE-522", "CWE-798"},
			ImplementationGuidance: "Enable etcd encryption-at-rest with KMS provider. Use External Secrets Operator to sync from Vault or cloud secrets manager. Prohibit secrets in ConfigMaps and environment variables in plain Kubernetes manifests.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TF-01",
			Title:                  "Terraform State File Security",
			Family:                 "IaC Security",
			Description:            "Terraform state files must be stored in encrypted remote backends with access controls and state locking. State files must not be committed to version control as they may contain sensitive resource attributes.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-312", "CWE-522"},
			ImplementationGuidance: "Use S3+DynamoDB or Terraform Cloud as remote backend. Enable server-side encryption for state bucket. Restrict bucket access to CI/CD pipelines and authorised operators. Add *.tfstate to .gitignore.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TF-02",
			Title:                  "IaC Policy as Code",
			Family:                 "IaC Security",
			Description:            "All Terraform configurations must be validated against security policies before apply. Policy checks must run in CI/CD and block deployments that introduce insecure resource configurations such as open security groups or unencrypted storage.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-732", "CWE-1188"},
			ImplementationGuidance: "Integrate tfsec, Checkov, or OPA Conftest into CI pipeline. Define baseline policy set covering networking, encryption, logging, and IAM rules. Treat policy violations as build failures for high-severity findings.",
		},
		{
			Framework:              FrameworkID,
			ControlID:              "TF-03",
			Title:                  "Terraform Module Version Pinning",
			Family:                 "Supply Chain",
			Description:            "All Terraform module and provider version references must be pinned to specific versions. Using floating version constraints in production configurations is prohibited to prevent supply chain compromise via upstream module updates.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-1357", "CWE-494"},
			ImplementationGuidance: "Pin all provider versions in required_providers block. Pin all module sources to specific git tags or registry versions. Use dependency lock file (.terraform.lock.hcl) and commit it to version control.",
		},
	}
}
