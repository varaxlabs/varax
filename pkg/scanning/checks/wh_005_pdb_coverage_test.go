package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPDBCoverageCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "ha-deploy", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32Ptr(3),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			},
		},
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Name: "web-pdb", Namespace: "default"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			},
		},
	)

	result := (&PDBCoverageCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPDBCoverageCheck_Fail_NoPDB(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "ha-deploy", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32Ptr(3),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			},
		},
	)

	result := (&PDBCoverageCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestPDBCoverageCheck_Pass_SingleReplica(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "single-deploy", Namespace: "default"},
			Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
		},
	)

	result := (&PDBCoverageCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPDBCoverageCheck_Fail_StatefulSetNoPDB(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "ha-sts", Namespace: "default"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: int32Ptr(3),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			},
		},
	)

	result := (&PDBCoverageCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Message, "StatefulSet")
}

func TestPDBCoverageCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "system-deploy", Namespace: "kube-system"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32Ptr(3),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dns"}},
			},
		},
	)

	result := (&PDBCoverageCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
