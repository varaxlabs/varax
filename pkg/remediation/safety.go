package remediation

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	exclusionLabel     = "remediation.varax.io/skip"
	remediatedAnnotation = "remediation.varax.io/last-remediated"
)

// isSystemNamespace returns true for kube-system, kube-public, kube-node-lease.
func isSystemNamespace(ns string) bool {
	return ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease"
}

// hasExclusionLabel checks whether a resource has the skip label set to "true".
func hasExclusionLabel(ctx context.Context, client kubernetes.Interface, kind, namespace, name string) bool {
	var labels map[string]string
	switch kind {
	case "Deployment":
		obj, err := client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		labels = obj.Labels
	case "StatefulSet":
		obj, err := client.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		labels = obj.Labels
	case "DaemonSet":
		obj, err := client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		labels = obj.Labels
	case "Pod":
		obj, err := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		labels = obj.Labels
	case "ServiceAccount":
		obj, err := client.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		labels = obj.Labels
	default:
		return false
	}
	return labels[exclusionLabel] == "true"
}

// annotateResource adds the remediation timestamp annotation to a resource.
func annotateResource(ctx context.Context, client kubernetes.Interface, kind, namespace, name string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, remediatedAnnotation, ts))

	switch kind {
	case "Deployment":
		_, err := client.AppsV1().Deployments(namespace).Patch(ctx, name, "application/strategic-merge-patch+json", patch, metav1.PatchOptions{})
		return err
	case "StatefulSet":
		_, err := client.AppsV1().StatefulSets(namespace).Patch(ctx, name, "application/strategic-merge-patch+json", patch, metav1.PatchOptions{})
		return err
	case "DaemonSet":
		_, err := client.AppsV1().DaemonSets(namespace).Patch(ctx, name, "application/strategic-merge-patch+json", patch, metav1.PatchOptions{})
		return err
	case "Pod":
		_, err := client.CoreV1().Pods(namespace).Patch(ctx, name, "application/strategic-merge-patch+json", patch, metav1.PatchOptions{})
		return err
	case "ServiceAccount":
		_, err := client.CoreV1().ServiceAccounts(namespace).Patch(ctx, name, "application/strategic-merge-patch+json", patch, metav1.PatchOptions{})
		return err
	}
	return nil
}
