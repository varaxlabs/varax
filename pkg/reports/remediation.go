package reports

// remediations maps check IDs to actionable remediation guidance.
var remediations = map[string]string{
	// CIS 1.2.x — API Server
	"CIS-1.2.1":  "Enable RBAC authorization mode on the API server with --authorization-mode=RBAC.",
	"CIS-1.2.2":  "Disable the AlwaysAdmit admission controller by removing it from --enable-admission-plugins.",
	"CIS-1.2.6":  "Ensure the API server uses a valid serving certificate with --tls-cert-file and --tls-private-key-file.",
	"CIS-1.2.7":  "Configure client CA authentication with --client-ca-file on the API server.",
	"CIS-1.2.8":  "Enable RBAC authorization by setting --authorization-mode to include RBAC.",
	"CIS-1.2.9":  "Enable the EventRateLimit admission controller to prevent event flooding.",
	"CIS-1.2.14": "Disable anonymous authentication with --anonymous-auth=false on the API server.",
	"CIS-1.2.16": "Enable audit logging with --audit-log-path on the API server.",
	"CIS-1.2.17": "Set audit log retention with --audit-log-maxage=30 or higher.",
	"CIS-1.2.18": "Set audit log backup retention with --audit-log-maxbackup=10 or higher.",
	"CIS-1.2.19": "Set audit log size limit with --audit-log-maxsize=100 or higher.",
	"CIS-1.2.20": "Configure an audit policy with --audit-policy-file specifying appropriate rules.",
	"CIS-1.2.21": "Ensure the API server request timeout is set appropriately with --request-timeout.",
	"CIS-1.2.23": "Enable encryption at rest by configuring --encryption-provider-config.",
	"CIS-1.2.24": "Configure encryption providers to use aescbc, aesgcm, or kms for secret encryption.",
	"CIS-1.2.25": "Ensure the API server uses TLS 1.2 or higher with --tls-min-version=VersionTLS12.",
	"CIS-1.2.26": "Configure strong TLS cipher suites with --tls-cipher-suites.",

	// CIS 1.3.x — Controller Manager
	"CIS-1.3.1": "Set --terminated-pod-gc-threshold to an appropriate value (e.g., 12500) to prevent resource exhaustion.",
	"CIS-1.3.6": "Rotate service account credentials by configuring --use-service-account-credentials=true.",

	// CIS 2.x — etcd
	"CIS-2.1": "Enable client TLS authentication for etcd with --client-cert-auth=true.",
	"CIS-2.2": "Configure etcd to use TLS encryption with --peer-client-cert-auth=true for peer connections.",
	"CIS-2.4": "Enable peer TLS authentication for etcd cluster members.",

	// CIS 3.x — Logging
	"CIS-3.2": "Configure a comprehensive audit policy. See https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/.",

	// CIS 4.2.x — Kubelet
	"CIS-4.2.1":  "Disable anonymous kubelet authentication with --anonymous-auth=false.",
	"CIS-4.2.2":  "Set kubelet authorization mode to Webhook with --authorization-mode=Webhook.",
	"CIS-4.2.3":  "Configure kubelet client TLS with --client-ca-file.",
	"CIS-4.2.4":  "Enable kubelet HTTPS with --tls-cert-file and --tls-private-key-file.",
	"CIS-4.2.5":  "Enable kubelet streaming connection idle timeout with --streaming-connection-idle-timeout.",
	"CIS-4.2.6":  "Protect kernel defaults with --protect-kernel-defaults=true.",
	"CIS-4.2.7":  "Set --make-iptables-util-chains=true on the kubelet.",
	"CIS-4.2.9":  "Enable event recording with appropriate --event-qps settings.",
	"CIS-4.2.12": "Verify kubelet TLS certificate rotation with --rotate-certificates=true.",

	// CIS 5.1.x — RBAC and Service Accounts
	"CIS-5.1.1": "Review and minimize cluster-admin ClusterRoleBindings. Replace with namespace-scoped Roles where possible.",
	"CIS-5.1.2": "Restrict access to Kubernetes secrets with fine-grained RBAC policies per namespace.",
	"CIS-5.1.3": "Remove wildcard (*) permissions from Roles and ClusterRoles. Specify explicit resources and verbs.",
	"CIS-5.1.4": "Create Roles in specific namespaces rather than ClusterRoles to enforce namespace isolation.",
	"CIS-5.1.5": "Avoid using the default service account. Create dedicated service accounts for each workload.",
	"CIS-5.1.6": "Disable automatic service account token mounting with automountServiceAccountToken: false.",
	"CIS-5.1.7": "Avoid granting system:masters group membership. Use RBAC with specific permissions instead.",
	"CIS-5.1.8": "Remove bind, escalate, and impersonate permissions from Roles unless explicitly required.",

	// CIS 5.2.x — Pod Security
	"CIS-5.2.1":  "Set allowPrivilegeEscalation: false in pod security contexts.",
	"CIS-5.2.2":  "Do not run containers as the root user. Set runAsNonRoot: true in the pod security context.",
	"CIS-5.2.3":  "Do not allow privileged containers. Set privileged: false in security contexts.",
	"CIS-5.2.4":  "Set readOnlyRootFilesystem: true to prevent container filesystem writes.",
	"CIS-5.2.5":  "Do not allow containers to share the host network namespace. Set hostNetwork: false.",
	"CIS-5.2.6":  "Do not allow containers to share the host PID namespace. Set hostPID: false.",
	"CIS-5.2.7":  "Do not allow containers to share the host IPC namespace. Set hostIPC: false.",
	"CIS-5.2.8":  "Do not allow containers to use host ports. Remove hostPort from container specs.",
	"CIS-5.2.9":  "Drop all Linux capabilities and add only those required. Use capabilities.drop: [ALL].",
	"CIS-5.2.10": "Do not add NET_RAW capability to containers unless required.",
	"CIS-5.2.11": "Do not add SYS_ADMIN capability. Refactor workloads to avoid requiring this capability.",
	"CIS-5.2.12": "Restrict added Linux capabilities to the minimum required set.",
	"CIS-5.2.13": "Apply a Seccomp profile to all containers. Set seccompProfile.type: RuntimeDefault.",

	// CIS 5.3.x — Network Policies
	"CIS-5.3.1": "Apply NetworkPolicies to all namespaces to control ingress traffic between pods.",
	"CIS-5.3.2": "Apply NetworkPolicies to restrict egress traffic from pods to only required destinations.",

	// CIS 5.4.x — Secrets Management
	"CIS-5.4.1": "Use Kubernetes secrets or an external secrets manager instead of environment variables for sensitive data.",

	// CIS 5.7.x — General Policies
	"CIS-5.7.1": "Define resource limits (CPU and memory) for all containers to prevent resource exhaustion.",
	"CIS-5.7.2": "Apply Pod Security Standards (Restricted profile) to enforce workload security baselines.",
	"CIS-5.7.3": "Apply Pod Security Standards at the namespace level using the pod-security.kubernetes.io labels.",
	"CIS-5.7.4": "Ensure the default namespace is not actively used for workloads. Create dedicated namespaces.",

	// NSA-CISA
	"NSA-AA-1": "Use strong authentication mechanisms. Disable static token files and use OIDC or certificate-based auth.",
	"NSA-AA-2": "Implement multi-factor authentication for cluster access where possible.",
	"NSA-AA-3": "Implement centralized identity management for Kubernetes access control.",
	"NSA-AA-4": "Regularly review and audit user access permissions and remove stale accounts.",
	"NSA-AA-5": "Rotate service account tokens regularly and use short-lived tokens where possible.",
	"NSA-NS-1": "Apply default-deny NetworkPolicies in all namespaces.",
	"NSA-NS-2": "Segment workloads into separate namespaces based on sensitivity and function.",
	"NSA-NS-3": "Restrict external network access to only required pods using egress NetworkPolicies.",
	"NSA-PS-1": "Run containers as non-root. Set runAsNonRoot: true and specify a non-zero runAsUser.",
	"NSA-PS-2": "Use read-only root filesystems for all containers.",
	"NSA-PS-3": "Drop all capabilities and add only those explicitly needed.",
	"NSA-PS-4": "Prevent privilege escalation with allowPrivilegeEscalation: false.",
	"NSA-PS-8": "Set resource requests and limits for all containers.",
	"NSA-SC-1": "Use signed container images and verify signatures before deployment.",
	"NSA-SC-2": "Scan container images for vulnerabilities before deployment using an image scanning tool.",
	"NSA-LM-1": "Enable and configure audit logging for all clusters.",
	"NSA-LM-2": "Centralize log collection and implement alerting for security-relevant events.",
	"NSA-VM-1": "Implement a vulnerability management process for container images and cluster components.",

	// PSS
	"PSS-1.1": "Apply the Baseline Pod Security Standard to all namespaces at minimum.",
	"PSS-1.2": "Apply the Restricted Pod Security Standard to sensitive workloads.",
	"PSS-1.3": "Enforce Pod Security Standards using namespace labels: pod-security.kubernetes.io/enforce: restricted.",
	"PSS-2.1": "Enforce Pod Security Admission at the cluster level using a default configuration.",
	"PSS-2.2": "Enable Pod Security Admission audit and warn modes to detect violations without blocking.",

	// RBAC
	"RBAC-1": "Review ClusterRoleBindings and remove unnecessary cluster-wide permissions.",
	"RBAC-2": "Apply least-privilege RBAC policies. Replace broad permissions with specific resource/verb combinations.",
	"RBAC-3": "Remove wildcard permissions from all Roles and ClusterRoles.",
	"RBAC-4": "Audit RoleBindings regularly and remove permissions for users/groups that no longer need access.",

	// Workload Hygiene
	"WH-001": "Pin container images to specific digests (@sha256:...) or semver tags. Avoid mutable tags like :latest, :dev, :main.",
	"WH-002": "Set CPU and memory requests and limits on all containers to prevent resource exhaustion and ensure fair scheduling.",
	"WH-003": "Define liveness and readiness probes on all containers to enable self-healing and traffic management.",

	// Supply Chain
	"SC-001": "Add SBOM attestation annotations to container images using tools like Syft, Trivy, or cosign attach sbom.",
	"SC-002": "Sign container images with Cosign/Sigstore and add signature annotations. Enforce verification at admission.",
	"SC-003": "Only deploy images from approved registries. Configure admission policies to enforce a registry allowlist.",

	// Ingress Hardening
	"IH-001": "Configure TLS on all Ingress resources. Use cert-manager to automate certificate provisioning.",
	"IH-002": "Create egress NetworkPolicies per namespace to restrict outbound traffic to only required destinations.",

	// Namespace Governance
	"NG-001": "Create ResourceQuotas in each namespace to enforce CPU, memory, and pod count limits.",
	"NG-002": "Create LimitRanges in each namespace to set default container resource constraints.",
	"NG-003": "Apply standard Kubernetes labels (app.kubernetes.io/name, component, managed-by) to all resources.",

	// Workload Hygiene (additional)
	"WH-004": "Scale critical workloads to 2+ replicas for high availability, or annotate with varax.io/single-replica-ok if single replica is intentional.",
	"WH-005": "Create PodDisruptionBudgets for multi-replica workloads to ensure controlled maintenance and upgrades.",

	// API Hygiene
	"AH-001": "Migrate resources from deprecated API versions to their stable replacements before they are removed.",
	"AH-002": "Evaluate use of alpha/beta APIs and plan migration to stable versions when available.",
}

// Remediation returns the remediation guidance for a check ID, or empty string if none exists.
func Remediation(checkID string) string {
	return remediations[checkID]
}
