package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden test vectors for cross-implementation validation.
// The Cloudflare Worker (signer) must produce identical output
// for the same inputs. See docs/license-key-spec.md.

const (
	// Fixed 32-byte seed (hex) — deterministic keypair for testing only.
	goldenSeedHex = "4b7a2c0e1f3a5d6b8c9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"
)

func TestGoldenVectors(t *testing.T) {
	// Derive deterministic keypair from fixed seed
	seed, err := hex.DecodeString(goldenSeedHex)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize, "seed must be 32 bytes")

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	t.Logf("Public key (hex): %s", hex.EncodeToString(pub))

	// Fixed timestamps matching the spec example
	issued := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)

	// Build payload using map[string]interface{} — same as cmd/keygen/main.go.
	// json.Marshal sorts map keys alphabetically, producing a deterministic field order.
	payload := map[string]interface{}{
		"org":      "Acme Corp",
		"plan":     "pro-annual",
		"issued":   issued,
		"expires":  expires,
		"features": []string{"reports", "evidence", "remediation", "scheduled-reports", "explore"},
	}

	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	// Verify alphabetical key order
	expectedFieldOrder := `"expires":`
	assert.True(t, strings.HasPrefix(string(payloadJSON), "{"+expectedFieldOrder),
		"JSON keys must be alphabetically sorted (map marshal); got: %s", string(payloadJSON))

	t.Logf("Payload JSON: %s", string(payloadJSON))

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	t.Logf("payloadB64: %s", payloadB64)

	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	t.Logf("sigB64: %s", sigB64)

	licenseKey := payloadB64 + "." + sigB64
	t.Logf("License key: %s", licenseKey)

	// Assert exact intermediate values.
	// If these change, update docs/license-key-spec.md golden vectors section.
	assert.Equal(t,
		`{"expires":"2027-01-15T00:00:00Z","features":["reports","evidence","remediation","scheduled-reports","explore"],"issued":"2026-01-15T00:00:00Z","org":"Acme Corp","plan":"pro-annual"}`,
		string(payloadJSON),
		"payload JSON must match exactly (alphabetical key order)")

	assert.Equal(t,
		"eyJleHBpcmVzIjoiMjAyNy0wMS0xNVQwMDowMDowMFoiLCJmZWF0dXJlcyI6WyJyZXBvcnRzIiwiZXZpZGVuY2UiLCJyZW1lZGlhdGlvbiIsInNjaGVkdWxlZC1yZXBvcnRzIiwiZXhwbG9yZSJdLCJpc3N1ZWQiOiIyMDI2LTAxLTE1VDAwOjAwOjAwWiIsIm9yZyI6IkFjbWUgQ29ycCIsInBsYW4iOiJwcm8tYW5udWFsIn0",
		payloadB64,
		"payloadB64 must match exactly")

	assert.Equal(t,
		"Y66LnOrt64zN82wqjZeStwsyITsX94Qr24QILc8rcLTttlQf0XThJW2stfBsCZQQVDh4LlQ9O-ewOuXsK2AMBg",
		sigB64,
		"sigB64 must match exactly")

	// Verify the key round-trips through parseAndValidateWithKey.
	// Use a custom time check: the golden timestamps are in the past/future
	// relative to "now", so we validate signature + parse only.
	result, err := parseAndValidateWithKey(licenseKey, pub)
	require.NoError(t, err, "golden license key must validate")

	assert.Equal(t, "Acme Corp", result.Org)
	assert.Equal(t, "pro-annual", result.Plan)
	assert.Equal(t, issued, result.Issued.UTC())
	assert.Equal(t, expires, result.Expires.UTC())
	assert.Equal(t, []string{"reports", "evidence", "remediation", "scheduled-reports", "explore"}, result.Features)

	// Verify signature is deterministic — Ed25519 signatures are deterministic
	sig2 := ed25519.Sign(priv, []byte(payloadB64))
	assert.Equal(t, sig, sig2, "Ed25519 signatures must be deterministic")
}
