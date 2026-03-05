package storage

import (
	"time"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

// Store is the interface for persisting scan results.
type Store interface {
	// SaveScanResult persists a scan result.
	SaveScanResult(result *models.ScanResult) error

	// GetLatestScanResult returns the most recent scan result.
	GetLatestScanResult() (*models.ScanResult, error)

	// ListScanResults returns scan results in reverse chronological order, up to limit.
	ListScanResults(limit int) ([]models.ScanResult, error)

	// SaveEvidenceBundle persists an evidence bundle.
	SaveEvidenceBundle(bundle *evidence.EvidenceBundle) error

	// GetLatestEvidenceBundle returns the most recent evidence bundle.
	GetLatestEvidenceBundle() (*evidence.EvidenceBundle, error)

	// PruneOlderThan removes scan results and evidence bundles older than the given duration.
	PruneOlderThan(maxAge time.Duration) (int, error)

	// Close releases any resources held by the store.
	Close() error
}
