package remediation

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes"
)

// Remediator plans remediation actions for a specific check.
type Remediator interface {
	CheckID() string
	Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]RemediationAction, error)
}

// RemediatorRegistry maps check IDs to their remediators.
type RemediatorRegistry struct {
	remediators map[string]Remediator
}

// NewRemediatorRegistry creates an empty registry.
func NewRemediatorRegistry() *RemediatorRegistry {
	return &RemediatorRegistry{remediators: make(map[string]Remediator)}
}

// Register adds a remediator for its check ID.
func (r *RemediatorRegistry) Register(rem Remediator) {
	r.remediators[rem.CheckID()] = rem
}

// Get returns the remediator for a check ID, or nil.
func (r *RemediatorRegistry) Get(checkID string) Remediator {
	return r.remediators[checkID]
}

// Has returns whether a remediator exists for the check ID.
func (r *RemediatorRegistry) Has(checkID string) bool {
	_, ok := r.remediators[checkID]
	return ok
}
