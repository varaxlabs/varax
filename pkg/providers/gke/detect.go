package gke

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// GKEClusterInfo contains the identifiers needed to interact with a GKE cluster.
type GKEClusterInfo struct {
	Project     string
	Location    string
	ClusterName string
}

// DetectGKEClusterInfo extracts GKE cluster info from node metadata.
// It parses the node providerID (format: gce://PROJECT/ZONE/INSTANCE_NAME)
// and looks for the cluster name in node labels.
func DetectGKEClusterInfo(nodes []corev1.Node) (*GKEClusterInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes provided")
	}

	node := nodes[0]

	project, location, err := parseGCEProviderID(node.Spec.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GKE providerID %q: %w", node.Spec.ProviderID, err)
	}

	clusterName := detectGKEClusterName(node.Labels)
	if clusterName == "" {
		return nil, fmt.Errorf("could not determine GKE cluster name from node labels")
	}

	return &GKEClusterInfo{
		Project:     project,
		Location:    location,
		ClusterName: clusterName,
	}, nil
}

// parseGCEProviderID extracts project and zone from a GCE providerID.
// Format: gce://PROJECT/ZONE/INSTANCE_NAME
func parseGCEProviderID(providerID string) (project, location string, err error) {
	trimmed := strings.TrimPrefix(providerID, "gce://")
	if trimmed == providerID {
		return "", "", fmt.Errorf("not a GCE providerID")
	}

	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GCE providerID format")
	}

	project = parts[0]
	location = parts[1]

	if project == "" || location == "" {
		return "", "", fmt.Errorf("empty project or location in providerID")
	}

	// Convert zone to region for GKE (e.g., us-central1-a -> us-central1)
	// Keep the full zone — GKE API accepts both zone and region
	return project, location, nil
}

// detectGKEClusterName extracts the cluster name from GKE node labels.
func detectGKEClusterName(labels map[string]string) string {
	if name, ok := labels["cloud.google.com/gke-cluster-name"]; ok {
		return name
	}
	// Fallback to generic label
	if name, ok := labels["cluster-name"]; ok {
		return name
	}
	return ""
}
