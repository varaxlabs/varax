package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidFormat    = errors.New("invalid license format")
	ErrInvalidSignature = errors.New("invalid license signature")
	ErrExpired          = errors.New("license expired")
	ErrNoLicense        = errors.New("no license found")
)

const GracePeriod = 5 * 24 * time.Hour

type License struct {
	Org      string   `json:"org"`
	Plan     string   `json:"plan"`
	Issued   time.Time `json:"issued"`
	Expires  time.Time `json:"expires"`
	Features []string `json:"features"`
}

func ParseAndValidate(key string) (*License, error) {
	return parseAndValidateWithKey(key, publicKey)
}

func parseAndValidateWithKey(key string, pubKey ed25519.PublicKey) (*License, error) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidFormat
	}

	payloadB64 := parts[0]
	sigB64 := parts[1]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidFormat)
	}

	if !ed25519.Verify(pubKey, []byte(payloadB64), sig) {
		return nil, ErrInvalidSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidFormat)
	}

	var l License
	if err := json.Unmarshal(payloadBytes, &l); err != nil {
		return nil, fmt.Errorf("%w: invalid payload JSON", ErrInvalidFormat)
	}

	now := time.Now()

	// Clock skew protection
	if l.Issued.After(now) {
		return nil, fmt.Errorf("%w: license issued in the future", ErrInvalidFormat)
	}

	// Hard expiry check (past grace period)
	if now.After(l.Expires.Add(GracePeriod)) {
		return nil, ErrExpired
	}

	return &l, nil
}

func (l *License) HasFeature(feature string) bool {
	for _, f := range l.Features {
		if f == feature {
			return true
		}
	}
	return false
}

func (l *License) IsInGracePeriod() bool {
	now := time.Now()
	return now.After(l.Expires) && !now.After(l.Expires.Add(GracePeriod))
}

func (l *License) DaysUntilExpiry() int {
	d := time.Until(l.Expires)
	return int(d.Hours() / 24)
}
