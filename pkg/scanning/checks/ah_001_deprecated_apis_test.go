package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDeprecatedAPICheck_Pass(t *testing.T) {
	// The fake clientset serves standard stable APIs; none are in the deprecated list.
	client := fake.NewSimpleClientset()
	result := (&DeprecatedAPICheck{}).Run(context.Background(), client)

	// The fake discovery returns v1, apps/v1, etc. — no deprecated APIs
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestDeprecatedAPICheck_HasBenchmark(t *testing.T) {
	check := &DeprecatedAPICheck{}
	assert.Equal(t, "AH-001", check.ID())
	assert.Equal(t, BenchmarkAPIHygiene, check.Benchmark())
	assert.Equal(t, models.SeverityMedium, check.Severity())
}
