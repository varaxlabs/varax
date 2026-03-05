package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// getAPIServerPod is a convenience wrapper for getting the kube-apiserver pod.
func getAPIServerPod(ctx context.Context, client kubernetes.Interface) (*corev1.Pod, error) {
	return getControlPlanePod(ctx, client, "kube-apiserver")
}

// getNodeKubeletConfig retrieves kubelet configuration from a node's proxy endpoint.
// Returns nil if not accessible.
func getNodeKubeletConfig(ctx context.Context, client kubernetes.Interface, nodeName string) (*corev1.Node, error) {
	return client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
}
