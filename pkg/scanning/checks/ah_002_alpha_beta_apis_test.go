package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAlphaBetaAPICheck_RunsWithoutError(t *testing.T) {
	client := fake.NewSimpleClientset()
	result := (&AlphaBetaAPICheck{}).Run(context.Background(), client)

	// The fake discovery serves a known set of APIs. The check should
	// complete without skipping, producing either pass or fail.
	assert.NotEqual(t, models.StatusSkip, result.Status)
}

func TestAlphaBetaAPICheck_HasBenchmark(t *testing.T) {
	check := &AlphaBetaAPICheck{}
	assert.Equal(t, "AH-002", check.ID())
	assert.Equal(t, BenchmarkAPIHygiene, check.Benchmark())
	assert.Equal(t, models.SeverityLow, check.Severity())
}
