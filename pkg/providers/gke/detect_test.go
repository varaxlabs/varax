package gke

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func gkeNode(providerID string, labels map[string]string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "gke-node-1",
			Labels: labels,
		},
		Spec: corev1.NodeSpec{
			ProviderID: providerID,
		},
	}
}

func TestDetectGKEClusterInfo_Success(t *testing.T) {
	node := gkeNode(
		"gce://my-project/us-central1-a/gke-my-cluster-default-pool-abc12345-wxyz",
		map[string]string{"cloud.google.com/gke-cluster-name": "my-cluster"},
	)

	info, err := DetectGKEClusterInfo([]corev1.Node{node})
	require.NoError(t, err)
	assert.Equal(t, "my-project", info.Project)
	assert.Equal(t, "us-central1-a", info.Location)
	assert.Equal(t, "my-cluster", info.ClusterName)
}

func TestDetectGKEClusterInfo_NoNodes(t *testing.T) {
	_, err := DetectGKEClusterInfo(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no nodes provided")
}

func TestDetectGKEClusterInfo_BadProviderID(t *testing.T) {
	node := gkeNode(
		"azure:///subscriptions/sub-1/resourceGroups/rg-1",
		map[string]string{"cloud.google.com/gke-cluster-name": "my-cluster"},
	)

	_, err := DetectGKEClusterInfo([]corev1.Node{node})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a GCE providerID")
}

func TestDetectGKEClusterInfo_MissingClusterLabel(t *testing.T) {
	node := gkeNode(
		"gce://my-project/us-central1-a/instance-1",
		map[string]string{},
	)

	_, err := DetectGKEClusterInfo([]corev1.Node{node})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine GKE cluster name")
}

func TestParseGCEProviderID_Variants(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		wantProj   string
		wantLoc    string
		wantErr    bool
	}{
		{
			name:       "standard format",
			providerID: "gce://my-project/us-central1-a/instance-1",
			wantProj:   "my-project",
			wantLoc:    "us-central1-a",
		},
		{
			name:       "different zone",
			providerID: "gce://prod-project/europe-west1-b/node-abc",
			wantProj:   "prod-project",
			wantLoc:    "europe-west1-b",
		},
		{
			name:       "not gce prefix",
			providerID: "aws:///us-east-1/i-12345",
			wantErr:    true,
		},
		{
			name:       "missing parts",
			providerID: "gce://project-only",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proj, loc, err := parseGCEProviderID(tt.providerID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantProj, proj)
			assert.Equal(t, tt.wantLoc, loc)
		})
	}
}
