package providers

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DetectProvider inspects node labels to determine the cloud provider.
func DetectProvider(ctx context.Context, client kubernetes.Interface) (ProviderType, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return ProviderSelfHosted, err
	}

	if len(nodes.Items) == 0 {
		return ProviderSelfHosted, nil
	}

	labels := nodes.Items[0].Labels
	for key := range labels {
		if strings.HasPrefix(key, "eks.amazonaws.com/") {
			return ProviderEKS, nil
		}
		if strings.HasPrefix(key, "kubernetes.azure.com/") {
			return ProviderAKS, nil
		}
		if strings.HasPrefix(key, "cloud.google.com/") {
			return ProviderGKE, nil
		}
	}

	return ProviderSelfHosted, nil
}
