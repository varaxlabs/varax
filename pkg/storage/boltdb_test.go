package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

func tempDBPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.db")
}

func TestBoltStore_SaveAndGetLatest(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	result := &models.ScanResult{
		ID:        "scan-1",
		Timestamp: time.Now().UTC().Truncate(time.Millisecond),
		Duration:  5 * time.Second,
		Results: []models.CheckResult{
			{ID: "CIS-5.1.1", Status: models.StatusPass, Name: "Test check"},
		},
		Summary: models.ScanSummary{TotalChecks: 1, PassCount: 1},
	}

	err = store.SaveScanResult(result)
	require.NoError(t, err)

	latest, err := store.GetLatestScanResult()
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, result.ID, latest.ID)
	assert.Equal(t, result.Summary.PassCount, latest.Summary.PassCount)
	assert.Len(t, latest.Results, 1)
}

func TestBoltStore_GetLatestEmpty(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	latest, err := store.GetLatestScanResult()
	require.NoError(t, err)
	assert.Nil(t, latest)
}

func TestBoltStore_ListScanResults(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		result := &models.ScanResult{
			ID:        "scan-" + string(rune('a'+i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Summary:   models.ScanSummary{TotalChecks: i + 1},
		}
		require.NoError(t, store.SaveScanResult(result))
	}

	results, err := store.ListScanResults(3)
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// Should be in reverse chronological order
	assert.Equal(t, 5, results[0].Summary.TotalChecks)
	assert.Equal(t, 4, results[1].Summary.TotalChecks)
	assert.Equal(t, 3, results[2].Summary.TotalChecks)
}

func TestBoltStore_InvalidPath(t *testing.T) {
	_, err := NewBoltStore("/nonexistent/path/db")
	assert.Error(t, err)
}

func TestBoltStore_SaveAndGetLatestEvidenceBundle(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	bundle := &evidence.EvidenceBundle{
		CollectedAt: time.Now().UTC().Truncate(time.Millisecond),
		ClusterName: "test-cluster",
		Items: []evidence.EvidenceItem{
			{
				Category:    "rbac",
				Description: "Cluster roles with wildcard permissions",
				Data:        map[string]string{"role": "admin"},
				Timestamp:   time.Now().UTC().Truncate(time.Millisecond),
			},
		},
	}

	err = store.SaveEvidenceBundle(bundle)
	require.NoError(t, err)

	latest, err := store.GetLatestEvidenceBundle()
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, bundle.CollectedAt, latest.CollectedAt)
	assert.Equal(t, bundle.ClusterName, latest.ClusterName)
	assert.Len(t, latest.Items, 1)
	assert.Equal(t, "rbac", latest.Items[0].Category)
	assert.Equal(t, "Cluster roles with wildcard permissions", latest.Items[0].Description)
}

func TestBoltStore_GetLatestEvidenceBundleEmpty(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	latest, err := store.GetLatestEvidenceBundle()
	require.NoError(t, err)
	assert.Nil(t, latest)
}

func TestBoltStore_GetLatestEvidenceBundleMultiple(t *testing.T) {
	store, err := NewBoltStore(tempDBPath(t))
	require.NoError(t, err)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)

	older := &evidence.EvidenceBundle{
		CollectedAt: now.Add(-10 * time.Minute),
		ClusterName: "cluster-old",
		Items: []evidence.EvidenceItem{
			{Category: "network", Description: "Old evidence", Timestamp: now.Add(-10 * time.Minute)},
		},
	}

	newer := &evidence.EvidenceBundle{
		CollectedAt: now,
		ClusterName: "cluster-new",
		Items: []evidence.EvidenceItem{
			{Category: "rbac", Description: "New evidence", Timestamp: now},
		},
	}

	require.NoError(t, store.SaveEvidenceBundle(older))
	require.NoError(t, store.SaveEvidenceBundle(newer))

	latest, err := store.GetLatestEvidenceBundle()
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, newer.CollectedAt, latest.CollectedAt)
	assert.Equal(t, "cluster-new", latest.ClusterName)
	assert.Len(t, latest.Items, 1)
	assert.Equal(t, "rbac", latest.Items[0].Category)
	assert.Equal(t, "New evidence", latest.Items[0].Description)
}

func TestBoltStore_Close(t *testing.T) {
	path := tempDBPath(t)
	store, err := NewBoltStore(path)
	require.NoError(t, err)

	err = store.Close()
	assert.NoError(t, err)

	// File should exist
	_, err = os.Stat(path)
	assert.NoError(t, err)
}
