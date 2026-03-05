package azure

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// AKSClusterInfo contains the identifiers needed to interact with an AKS cluster.
type AKSClusterInfo struct {
	SubscriptionID string
	ResourceGroup  string
	ClusterName    string
}

// DetectAKSClusterInfo extracts AKS cluster info from node metadata.
// It parses the node providerID (format: azure:///subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/...)
// and looks for the cluster name in node labels.
func DetectAKSClusterInfo(nodes []corev1.Node) (*AKSClusterInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes provided")
	}

	node := nodes[0]

	// Parse subscription ID and resource group from providerID
	subscriptionID, resourceGroup, err := parseProviderID(node.Spec.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AKS providerID %q: %w", node.Spec.ProviderID, err)
	}

	// Get cluster name from AKS node labels
	clusterName := detectAKSClusterName(node.Labels)
	if clusterName == "" {
		return nil, fmt.Errorf("could not determine AKS cluster name from node labels")
	}

	return &AKSClusterInfo{
		SubscriptionID: subscriptionID,
		ResourceGroup:  resourceGroup,
		ClusterName:    clusterName,
	}, nil
}

// parseProviderID extracts subscription ID and resource group from an Azure providerID.
// Format: azure:///subscriptions/{sub}/resourceGroups/{rg}/providers/...
func parseProviderID(providerID string) (subscriptionID, resourceGroup string, err error) {
	// Normalize: remove azure:// or azure:/// prefix
	id := providerID
	id = strings.TrimPrefix(id, "azure:///")
	id = strings.TrimPrefix(id, "azure://")

	parts := strings.Split(id, "/")

	// Find subscriptions/XXX and resourceGroups/XXX
	for i := 0; i < len(parts)-1; i++ {
		switch strings.ToLower(parts[i]) {
		case "subscriptions":
			subscriptionID = parts[i+1]
		case "resourcegroups":
			resourceGroup = parts[i+1]
		}
	}

	if subscriptionID == "" {
		return "", "", fmt.Errorf("subscription ID not found in providerID")
	}
	if resourceGroup == "" {
		return "", "", fmt.Errorf("resource group not found in providerID")
	}

	return subscriptionID, resourceGroup, nil
}

// detectAKSClusterName extracts the cluster name from AKS node labels.
func detectAKSClusterName(labels map[string]string) string {
	// AKS sets this label on managed nodes
	if name, ok := labels["kubernetes.azure.com/cluster"]; ok {
		return name
	}
	// Fallback: some AKS setups use agentpool labels that embed the cluster name
	if name, ok := labels["kubernetes.azure.com/agentpool-name"]; ok {
		return name
	}
	return ""
}
