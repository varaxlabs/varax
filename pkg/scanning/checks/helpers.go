package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// isManagedCluster checks cached node labels for EKS/AKS/GKE markers.
func isManagedCluster(ctx context.Context, client kubernetes.Interface) bool {
	nodes, err := scanning.ListNodes(ctx, client)
	if err != nil || len(nodes) == 0 {
		return false
	}
	for key := range nodes[0].Labels {
		if strings.HasPrefix(key, "eks.amazonaws.com/") ||
			strings.HasPrefix(key, "kubernetes.azure.com/") ||
			strings.HasPrefix(key, "cloud.google.com/") {
			return true
		}
	}
	return false
}

// getControlPlanePod fetches a named pod from kube-system.
func getControlPlanePod(ctx context.Context, client kubernetes.Interface, componentName string) (*corev1.Pod, error) {
	pods, err := scanning.ListPods(ctx, client, "kube-system")
	if err != nil {
		return nil, err
	}
	for i := range pods {
		if pods[i].Name == componentName || strings.HasPrefix(pods[i].Name, componentName+"-") {
			return &pods[i], nil
		}
	}
	return nil, fmt.Errorf("pod %s not found in kube-system", componentName)
}

// getPodArgs extracts command-line args from the first container of a pod.
func getPodArgs(pod *corev1.Pod) []string {
	if len(pod.Spec.Containers) == 0 {
		return nil
	}
	c := pod.Spec.Containers[0]
	args := make([]string, 0, len(c.Command)+len(c.Args))
	args = append(args, c.Command...)
	args = append(args, c.Args...)
	return args
}

// getArgValue extracts a flag value from args in --flag=value format.
func getArgValue(args []string, prefix string) (string, bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix+"=") {
			return strings.TrimPrefix(arg, prefix+"="), true
		}
		if arg == prefix {
			return "", true
		}
	}
	return "", false
}

// hasArg checks if a flag is present in the args list.
func hasArg(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}
	return false
}

// baseResult creates a CheckResult pre-filled from a Check's metadata.
func baseResult(c scanning.Check) models.CheckResult {
	return models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}
}

// controlPlaneCheckSkip returns a skip result for managed clusters where
// control plane components are not accessible.
func controlPlaneCheckSkip(c scanning.Check) models.CheckResult {
	result := baseResult(c)
	result.Status = models.StatusSkip
	result.Message = "Control plane not accessible on managed cluster"
	return result
}

// runControlPlaneArgCheck is a common pattern for checks that inspect a
// control plane component's command-line arguments.
func runControlPlaneArgCheck(ctx context.Context, client kubernetes.Interface, c scanning.Check, component string, checkFn func(args []string) (bool, string)) models.CheckResult {
	result := baseResult(c)

	if isManagedCluster(ctx, client) {
		return controlPlaneCheckSkip(c)
	}

	pod, err := getControlPlanePod(ctx, client, component)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("Could not find %s pod: %v", component, err)
		return result
	}

	args := getPodArgs(pod)
	pass, msg := checkFn(args)

	if pass {
		result.Status = models.StatusPass
		result.Message = msg
	} else {
		result.Status = models.StatusFail
		result.Message = msg
		result.Evidence = []models.Evidence{{
			Message: msg,
			Resource: models.Resource{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: "kube-system",
			},
		}}
	}

	return result
}

// runPodSpecCheck is a common pattern for checks that inspect a PodSpec-level
// boolean field (e.g., hostPID, hostIPC, hostNetwork). The checkFn receives each
// non-system-namespace pod and returns evidence if the pod violates the check.
func runPodSpecCheck(ctx context.Context, client kubernetes.Interface, c scanning.Check, checkFn func(pod corev1.Pod) *models.Evidence) models.CheckResult {
	result := baseResult(c)

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if ev := checkFn(pod); ev != nil {
			evidence = append(evidence, *ev)
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No violations found in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d violation(s)", len(evidence))
		result.Evidence = evidence
	}
	return result
}

// runContainerCheck is a common pattern for checks that inspect each container
// in each pod. The checkFn is called for every container in non-system-namespace
// pods and should return evidence if the container violates the check.
func runContainerCheck(ctx context.Context, client kubernetes.Interface, c scanning.Check, checkFn func(container corev1.Container, pod corev1.Pod) *models.Evidence) models.CheckResult {
	result := baseResult(c)

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range allContainers(pod) {
			if ev := checkFn(container, pod); ev != nil {
				evidence = append(evidence, *ev)
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No violations found in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d violation(s)", len(evidence))
		result.Evidence = evidence
	}
	return result
}

// isSystemNamespace returns true for kube-system, kube-public, kube-node-lease.
func isSystemNamespace(ns string) bool {
	return ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease"
}

// isSystemRole returns true for roles prefixed with "system:".
func isSystemRole(name string) bool {
	return strings.HasPrefix(name, "system:")
}

// allContainers returns a new slice combining init and regular containers
// without mutating the original slices.
func allContainers(pod corev1.Pod) []corev1.Container {
	containers := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	containers = append(containers, pod.Spec.InitContainers...)
	containers = append(containers, pod.Spec.Containers...)
	return containers
}
