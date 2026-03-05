package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func aksNode(providerID string, labels map[string]string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "aks-node-1",
			Labels: labels,
		},
		Spec: corev1.NodeSpec{
			ProviderID: providerID,
		},
	}
}

func TestDetectAKSClusterInfo_Success(t *testing.T) {
	node := aksNode(
		"azure:///subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachineScaleSets/aks-default-12345678-vmss/virtualMachines/0",
		map[string]string{"kubernetes.azure.com/cluster": "my-cluster"},
	)

	info, err := DetectAKSClusterInfo([]corev1.Node{node})
	require.NoError(t, err)
	assert.Equal(t, "sub-123", info.SubscriptionID)
	assert.Equal(t, "my-rg", info.ResourceGroup)
	assert.Equal(t, "my-cluster", info.ClusterName)
}

func TestDetectAKSClusterInfo_NoNodes(t *testing.T) {
	_, err := DetectAKSClusterInfo(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no nodes provided")
}

func TestDetectAKSClusterInfo_BadProviderID(t *testing.T) {
	node := aksNode(
		"gce://project/zone/instance",
		map[string]string{"kubernetes.azure.com/cluster": "my-cluster"},
	)

	_, err := DetectAKSClusterInfo([]corev1.Node{node})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subscription ID not found")
}

func TestDetectAKSClusterInfo_MissingClusterLabel(t *testing.T) {
	node := aksNode(
		"azure:///subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0",
		map[string]string{},
	)

	_, err := DetectAKSClusterInfo([]corev1.Node{node})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine AKS cluster name")
}

func TestParseProviderID_Variants(t *testing.T) {
	tests := []struct {
		name           string
		providerID     string
		wantSub        string
		wantRG         string
		wantErr        bool
	}{
		{
			name:       "standard triple-slash",
			providerID: "azure:///subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0",
			wantSub:    "sub-1",
			wantRG:     "rg-1",
		},
		{
			name:       "no prefix",
			providerID: "/subscriptions/sub-2/resourceGroups/rg-2/providers/Microsoft.Compute/foo",
			wantSub:    "sub-2",
			wantRG:     "rg-2",
		},
		{
			name:       "missing subscription",
			providerID: "azure:///resourceGroups/rg-1/providers/foo",
			wantErr:    true,
		},
		{
			name:       "missing resource group",
			providerID: "azure:///subscriptions/sub-1/providers/foo",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, rg, err := parseProviderID(tt.providerID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSub, sub)
			assert.Equal(t, tt.wantRG, rg)
		})
	}
}
