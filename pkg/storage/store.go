package storage

import (
	"time"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
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

	// SaveRemediationReport persists a remediation report.
	SaveRemediationReport(report *remediation.RemediationReport) error

	// GetLatestRemediationReport returns the most recent remediation report.
	GetLatestRemediationReport() (*remediation.RemediationReport, error)

	// ListRemediationReports returns remediation reports in reverse chronological order, up to limit.
	ListRemediationReports(limit int) ([]remediation.RemediationReport, error)

	// PruneOlderThan removes scan results, evidence bundles, and remediation reports older than the given duration.
	PruneOlderThan(maxAge time.Duration) (int, error)

	// SaveLicense persists a license key string.
	SaveLicense(key string) error

	// GetLicense returns the stored license key, or empty string if none.
	GetLicense() (string, error)

	// Close releases any resources held by the store.
	Close() error
}
