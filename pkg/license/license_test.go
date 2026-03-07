package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func signForTesting(t *testing.T, l License, privKey ed25519.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(l)
	require.NoError(t, err)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(privKey, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return payloadB64 + "." + sigB64
}

func validLicense() License {
	return License{
		Org:      "Acme Corp",
		Plan:     "pro-annual",
		Issued:   time.Now().Add(-24 * time.Hour),
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		Features: []string{FeatureReports, FeatureEvidence},
	}
}

func TestParseAndValidate_ValidKey(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := validLicense()
	key := signForTesting(t, l, priv)

	result, err := parseAndValidateWithKey(key, pub)
	require.NoError(t, err)
	assert.Equal(t, "Acme Corp", result.Org)
	assert.Equal(t, "pro-annual", result.Plan)
	assert.True(t, result.HasFeature(FeatureReports))
	assert.True(t, result.HasFeature(FeatureEvidence))
	assert.False(t, result.HasFeature(FeatureRemediation))
}

func TestParseAndValidate_ExpiredInGracePeriod(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := License{
		Org:      "Grace Co",
		Plan:     "pro-monthly",
		Issued:   time.Now().Add(-60 * 24 * time.Hour),
		Expires:  time.Now().Add(-2 * 24 * time.Hour), // expired 2 days ago, within 5-day grace
		Features: []string{FeatureReports},
	}
	key := signForTesting(t, l, priv)

	result, err := parseAndValidateWithKey(key, pub)
	require.NoError(t, err)
	assert.True(t, result.IsInGracePeriod())
}

func TestParseAndValidate_HardExpired(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := License{
		Org:      "Old Corp",
		Plan:     "pro-annual",
		Issued:   time.Now().Add(-400 * 24 * time.Hour),
		Expires:  time.Now().Add(-10 * 24 * time.Hour), // expired 10 days ago, past 5-day grace
		Features: []string{FeatureReports},
	}
	key := signForTesting(t, l, priv)

	_, err := parseAndValidateWithKey(key, pub)
	assert.ErrorIs(t, err, ErrExpired)
}

func TestParseAndValidate_InvalidSignature(t *testing.T) {
	pub, _ := generateTestKeypair(t)
	_, otherPriv := generateTestKeypair(t)
	l := validLicense()
	key := signForTesting(t, l, otherPriv) // signed with wrong key

	_, err := parseAndValidateWithKey(key, pub)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestParseAndValidate_TamperedPayload(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := validLicense()
	key := signForTesting(t, l, priv)

	// Tamper with the payload (change first char)
	tamperedKey := "x" + key[1:]
	_, err := parseAndValidateWithKey(tamperedKey, pub)
	assert.Error(t, err)
}

func TestParseAndValidate_InvalidFormat(t *testing.T) {
	pub, _ := generateTestKeypair(t)

	_, err := parseAndValidateWithKey("not-a-valid-key", pub)
	assert.ErrorIs(t, err, ErrInvalidFormat)

	_, err = parseAndValidateWithKey("", pub)
	assert.ErrorIs(t, err, ErrInvalidFormat)
}

func TestParseAndValidate_ClockSkew(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := License{
		Org:      "Future Corp",
		Plan:     "pro-annual",
		Issued:   time.Now().Add(48 * time.Hour), // issued in the future
		Expires:  time.Now().Add(400 * 24 * time.Hour),
		Features: []string{FeatureReports},
	}
	key := signForTesting(t, l, priv)

	_, err := parseAndValidateWithKey(key, pub)
	assert.ErrorIs(t, err, ErrInvalidFormat)
}

func TestHasFeature(t *testing.T) {
	l := &License{Features: []string{"reports", "evidence"}}
	assert.True(t, l.HasFeature("reports"))
	assert.True(t, l.HasFeature("evidence"))
	assert.False(t, l.HasFeature("remediation"))
	assert.False(t, l.HasFeature(""))
}

func TestDaysUntilExpiry(t *testing.T) {
	l := &License{Expires: time.Now().Add(30 * 24 * time.Hour)}
	days := l.DaysUntilExpiry()
	assert.InDelta(t, 30, days, 1)
}

func TestDaysUntilExpiry_Expired(t *testing.T) {
	l := &License{Expires: time.Now().Add(-5 * 24 * time.Hour)}
	days := l.DaysUntilExpiry()
	assert.InDelta(t, -5, days, 1)
}

func TestIsInGracePeriod_NotExpired(t *testing.T) {
	l := &License{Expires: time.Now().Add(30 * 24 * time.Hour)}
	assert.False(t, l.IsInGracePeriod())
}

func TestIsInGracePeriod_PastGrace(t *testing.T) {
	l := &License{Expires: time.Now().Add(-10 * 24 * time.Hour)}
	assert.False(t, l.IsInGracePeriod())
}

func TestIsProFeature(t *testing.T) {
	assert.True(t, IsProFeature(FeatureReports))
	assert.True(t, IsProFeature(FeatureEvidence))
	assert.True(t, IsProFeature(FeatureRemediation))
	assert.True(t, IsProFeature(FeatureScheduledReports))
	assert.False(t, IsProFeature("scanning"))
	assert.False(t, IsProFeature(""))
}
