package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	bolt "go.etcd.io/bbolt"
)

var (
	scanBucket     = []byte("scans")
	evidenceBucket = []byte("evidence")
)

// BoltStore implements Store using BoltDB.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens or creates a BoltDB at the given path.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open BoltDB at %s: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(scanBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(evidenceBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	return &BoltStore{db: db}, nil
}

func (s *BoltStore) SaveScanResult(result *models.ScanResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(scanBucket)

		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal scan result: %w", err)
		}

		// Use RFC3339 timestamp as key for natural ordering
		key := []byte(result.Timestamp.UTC().Format(time.RFC3339Nano))
		return b.Put(key, data)
	})
}

func (s *BoltStore) GetLatestScanResult() (*models.ScanResult, error) {
	var result *models.ScanResult

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(scanBucket)
		c := b.Cursor()

		k, v := c.Last()
		if k == nil {
			return nil
		}

		result = &models.ScanResult{}
		return json.Unmarshal(v, result)
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *BoltStore) ListScanResults(limit int) ([]models.ScanResult, error) {
	var results []models.ScanResult

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(scanBucket)
		c := b.Cursor()

		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var r models.ScanResult
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			results = append(results, r)
			count++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *BoltStore) SaveEvidenceBundle(bundle *evidence.EvidenceBundle) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(evidenceBucket)

		data, err := json.Marshal(bundle)
		if err != nil {
			return fmt.Errorf("failed to marshal evidence bundle: %w", err)
		}

		key := []byte(bundle.CollectedAt.UTC().Format(time.RFC3339Nano))
		return b.Put(key, data)
	})
}

func (s *BoltStore) GetLatestEvidenceBundle() (*evidence.EvidenceBundle, error) {
	var bundle *evidence.EvidenceBundle

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(evidenceBucket)
		c := b.Cursor()

		k, v := c.Last()
		if k == nil {
			return nil
		}

		bundle = &evidence.EvidenceBundle{}
		return json.Unmarshal(v, bundle)
	})

	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func (s *BoltStore) PruneOlderThan(maxAge time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339Nano)
	pruned := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, bucketName := range [][]byte{scanBucket, evidenceBucket} {
			b := tx.Bucket(bucketName)
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if string(k) < cutoff {
					if err := b.Delete(k); err != nil {
						return err
					}
					pruned++
				} else {
					break // keys are ordered chronologically
				}
			}
		}
		return nil
	})

	return pruned, err
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}
