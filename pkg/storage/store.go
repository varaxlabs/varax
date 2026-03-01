package storage

import "github.com/kubeshield/operator/pkg/models"

// Store is the interface for persisting scan results.
type Store interface {
	// SaveScanResult persists a scan result.
	SaveScanResult(result *models.ScanResult) error

	// GetLatestScanResult returns the most recent scan result.
	GetLatestScanResult() (*models.ScanResult, error)

	// ListScanResults returns scan results in reverse chronological order, up to limit.
	ListScanResults(limit int) ([]models.ScanResult, error)

	// Close releases any resources held by the store.
	Close() error
}
