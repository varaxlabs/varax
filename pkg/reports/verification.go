package reports

// VerificationCommand is a kubectl one-liner an auditor can run to independently verify evidence.
type VerificationCommand struct {
	Description string `json:"description"`
	Command     string `json:"command"`
}

// verificationCommands maps evidence artifact types to kubectl verification commands.
var verificationCommands = map[string][]VerificationCommand{
	"rbac-cluster-admin": {
		{
			Description: "Count cluster-admin bindings",
			Command:     `kubectl get clusterrolebindings -o json | jq '[.items[] | select(.roleRef.name=="cluster-admin")] | length'`,
		},
		{
			Description: "List cluster-admin binding details",
			Command:     `kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | {name: .metadata.name, subjects: .subjects}'`,
		},
	},
	"rbac-sa-token-mount": {
		{
			Description: "List service accounts with auto-mount enabled",
			Command:     `kubectl get serviceaccounts -A -o json | jq '.items[] | select(.automountServiceAccountToken == true) | {ns: .metadata.namespace, name: .metadata.name}'`,
		},
	},
	"rbac-namespace-scope": {
		{
			Description: "Count namespace-scoped vs cluster-scoped bindings",
			Command:     `echo "RoleBindings: $(kubectl get rolebindings -A --no-headers 2>/dev/null | wc -l), ClusterRoleBindings: $(kubectl get clusterrolebindings --no-headers 2>/dev/null | wc -l)"`,
		},
	},
	"rbac-wildcard-roles": {
		{
			Description: "List ClusterRoles with wildcard permissions",
			Command:     `kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.resources[]? == "*") or (.verbs[]? == "*")) | .metadata.name'`,
		},
	},
	"network-policy-coverage": {
		{
			Description: "List namespaces without NetworkPolicies",
			Command:     `kubectl get namespaces -o json | jq -r '.items[].metadata.name' | while read ns; do count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l); [ "$count" -eq 0 ] && echo "$ns"; done`,
		},
		{
			Description: "Count NetworkPolicies per namespace",
			Command:     `kubectl get networkpolicies -A --no-headers 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn`,
		},
	},
	"default-deny-status": {
		{
			Description: "Check for default-deny NetworkPolicies",
			Command:     `kubectl get networkpolicies -A -o json | jq '.items[] | select(.spec.podSelector == {} and (.spec.ingress | length) == 0 and (.spec.egress | length) == 0) | {ns: .metadata.namespace, name: .metadata.name}'`,
		},
	},
	"audit-logging": {
		{
			Description: "Verify audit logging configuration (self-hosted)",
			Command:     `kubectl get pods -n kube-system -l component=kube-apiserver -o json | jq '.items[0].spec.containers[0].args[] | select(startswith("--audit-"))'`,
		},
		{
			Description: "Verify EKS audit logging status",
			Command:     `aws eks describe-cluster --name CLUSTER_NAME --query 'cluster.logging.clusterLogging[?contains(types, ` + "`audit`" + `)]'`,
		},
	},
	"encryption-tls": {
		{
			Description: "Verify API server TLS configuration",
			Command:     `kubectl get pods -n kube-system -l component=kube-apiserver -o json | jq '.items[0].spec.containers[0].args[] | select(startswith("--tls-"))'`,
		},
		{
			Description: "Verify etcd TLS configuration",
			Command:     `kubectl get pods -n kube-system -l component=etcd -o json | jq '.items[0].spec.containers[0].args[] | select(startswith("--cert-") or startswith("--peer-cert-") or startswith("--trusted-ca-"))'`,
		},
	},
	"pss-enforcement": {
		{
			Description: "Show Pod Security Standard labels per namespace",
			Command:     `kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, pss: (.metadata.labels | with_entries(select(.key | startswith("pod-security"))))}'`,
		},
	},
}

// CommandsForControl returns all verification commands relevant to a control's evidence profile.
func CommandsForControl(controlID string) []VerificationCommand {
	profiles := EvidenceProfilesForControl(controlID)
	if len(profiles) == 0 {
		return nil
	}

	var commands []VerificationCommand
	seen := make(map[string]bool) // deduplicate by description
	for _, profile := range profiles {
		for _, cmd := range verificationCommands[profile] {
			if !seen[cmd.Description] {
				commands = append(commands, cmd)
				seen[cmd.Description] = true
			}
		}
	}
	return commands
}
