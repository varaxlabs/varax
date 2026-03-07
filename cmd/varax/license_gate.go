package main

import (
	"fmt"
	"os"

	"github.com/varax/operator/pkg/license"
	"github.com/varax/operator/pkg/storage"
)

func loadLicense() (*license.License, error) {
	var key string

	// Env var takes precedence (useful for CI/operator)
	key = os.Getenv("VARAX_LICENSE")

	if key == "" {
		store, err := storage.NewBoltStore(defaultDBPath())
		if err != nil {
			return nil, license.ErrNoLicense
		}
		defer func() { _ = store.Close() }()

		key, err = store.GetLicense()
		if err != nil || key == "" {
			return nil, license.ErrNoLicense
		}
	}

	l, err := license.ParseAndValidate(key)
	if err != nil {
		return nil, err
	}

	if l.IsInGracePeriod() {
		fmt.Fprintf(os.Stderr, "Warning: Your Varax license expired %d day(s) ago. Please renew to avoid interruption.\n", -l.DaysUntilExpiry())
	}

	return l, nil
}

func requireProFeature(feature string) error {
	l, err := loadLicense()
	if err != nil {
		return fmt.Errorf(`This feature requires a Varax Pro license.

Activate a license:  varax license activate <KEY>
Purchase at:         https://varax.io/pricing

Free tier includes: scanning, SOC2 mapping, Prometheus metrics, score tracking.`)
	}

	if !l.HasFeature(feature) {
		return fmt.Errorf("your license plan (%s) does not include the %q feature — upgrade at https://varax.io/pricing", l.Plan, feature)
	}

	return nil
}
