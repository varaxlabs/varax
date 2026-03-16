package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func int32Ptr(i int32) *int32 { return &i }

func TestReplicaMinimumsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "ha-deploy", Namespace: "default"},
			Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(3)},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestReplicaMinimumsCheck_Fail_SingleReplica(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "single-deploy", Namespace: "default"},
			Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestReplicaMinimumsCheck_Fail_NilReplicas(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "nil-deploy", Namespace: "default"},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestReplicaMinimumsCheck_Pass_Exempt(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "exempt-deploy", Namespace: "default",
				Annotations: map[string]string{"varax.io/single-replica-ok": "true"},
			},
			Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestReplicaMinimumsCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "system-deploy", Namespace: "kube-system"},
			Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestReplicaMinimumsCheck_StatefulSet(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "single-sts", Namespace: "default"},
			Spec:       appsv1.StatefulSetSpec{Replicas: int32Ptr(1)},
		},
	)

	result := (&ReplicaMinimumsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}
