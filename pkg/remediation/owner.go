package remediation

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WorkloadOwner identifies the controller that owns a pod.
type WorkloadOwner struct {
	Kind      string
	Name      string
	Namespace string
}

// ResolveOwner walks the OwnerReference chain from a pod to its controller.
// Pod -> ReplicaSet -> Deployment (most common)
// Pod -> StatefulSet
// Pod -> DaemonSet
// Bare Pod -> Pod itself
func ResolveOwner(ctx context.Context, client kubernetes.Interface, namespace, podName string) (*WorkloadOwner, error) {
	pod, err := client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	if len(pod.OwnerReferences) == 0 {
		return &WorkloadOwner{Kind: "Pod", Name: podName, Namespace: namespace}, nil
	}

	owner := pod.OwnerReferences[0]
	switch owner.Kind {
	case "ReplicaSet":
		return resolveReplicaSetOwner(ctx, client, namespace, owner.Name)
	case "StatefulSet":
		return &WorkloadOwner{Kind: "StatefulSet", Name: owner.Name, Namespace: namespace}, nil
	case "DaemonSet":
		return &WorkloadOwner{Kind: "DaemonSet", Name: owner.Name, Namespace: namespace}, nil
	default:
		return &WorkloadOwner{Kind: "Pod", Name: podName, Namespace: namespace}, nil
	}
}

func resolveReplicaSetOwner(ctx context.Context, client kubernetes.Interface, namespace, rsName string) (*WorkloadOwner, error) {
	rs, err := client.AppsV1().ReplicaSets(namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ReplicaSet %s/%s: %w", namespace, rsName, err)
	}

	for _, ref := range rs.OwnerReferences {
		if ref.Kind == "Deployment" {
			return &WorkloadOwner{Kind: "Deployment", Name: ref.Name, Namespace: namespace}, nil
		}
	}

	// ReplicaSet without Deployment owner — treat as bare RS, patch the pod directly
	return &WorkloadOwner{Kind: "Pod", Name: rsName, Namespace: namespace}, nil
}
