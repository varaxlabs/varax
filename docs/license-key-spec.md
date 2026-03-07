# License Key Format Specification

This document is the contract between the Go CLI (verifier) and the Cloudflare Worker (signer).

## Key Format

```
<base64url_payload>.<base64url_signature>
```

Two base64url-encoded segments separated by a single `.` character.

## Signing Algorithm

1. Serialize the payload as JSON (compact, no trailing newline)
2. base64url-encode the JSON bytes (no padding) to produce `payloadB64`
3. Ed25519-sign the **string bytes** of `payloadB64` — i.e., `sign([]byte(payloadB64))`, NOT the raw JSON
4. base64url-encode the 64-byte signature (no padding) to produce `sigB64`
5. Concatenate: `payloadB64 + "." + sigB64`

> **Critical detail:** the signature is computed over `[]byte(payloadB64)`, not over the raw JSON bytes. See `pkg/license/license.go:52`.

## Payload Schema

```json
{
  "org": "Acme Corp",
  "plan": "pro-annual",
  "issued": "2026-01-15T00:00:00Z",
  "expires": "2027-01-15T00:00:00Z",
  "features": ["reports", "evidence", "remediation", "scheduled-reports", "explore"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `org` | string | Customer organization name |
| `plan` | string | Plan identifier (see below) |
| `issued` | string | RFC 3339 timestamp, second precision, UTC |
| `expires` | string | RFC 3339 timestamp, second precision, UTC |
| `features` | string[] | Enabled feature strings (see below) |

### Plan Strings

| Plan | Description |
|------|-------------|
| `pro-annual` | Annual Pro subscription |
| `pro-monthly` | Monthly Pro subscription |

### Feature Strings

| Feature | Description |
|---------|-------------|
| `reports` | HTML readiness and executive reports |
| `evidence` | Evidence export for auditors |
| `remediation` | Auto-remediation of violations |
| `scheduled-reports` | Scheduled report generation |
| `explore` | Full-screen TUI explorer |

Source: `pkg/license/features.go`

## Key Material

- **Private key:** raw 64-byte Ed25519 private key (binary, not PEM-wrapped). Used by the Cloudflare Worker to sign.
- **Public key:** raw 32-byte Ed25519 public key. Embedded in the CLI binary at `pkg/license/pubkey.go`.

The private key must NEVER be embedded in client code or committed to this repository.

## Validation Rules

The CLI (`pkg/license/license.go`) enforces:

1. Key must contain exactly one `.` separator
2. Both segments must be valid base64url (no padding)
3. Ed25519 signature must verify against the embedded public key
4. `issued` must not be in the future (clock skew protection)
5. `expires` + 5-day grace period must not have passed

During the grace period (between `expires` and `expires + 5 days`), the license is still valid but the CLI warns the user to renew.

## Cloudflare Worker Implementation Notes

### Signing with Web Crypto API

```javascript
// Import the raw 32-byte private seed (not the full 64-byte key)
const privateKey = await crypto.subtle.importKey(
  "raw",
  privateKeyBytes,   // Uint8Array, 32 bytes (seed)
  { name: "Ed25519" },
  false,
  ["sign"]
);

// base64url encode without padding
function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Build the key
const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(payload)));
const signature = await crypto.subtle.sign(
  "Ed25519",
  privateKey,
  new TextEncoder().encode(payloadB64)  // sign the base64url STRING bytes
);
const key = payloadB64 + "." + base64url(signature);
```

> **Note:** Web Crypto `importKey("raw", ...)` for Ed25519 expects the 32-byte seed, not the full 64-byte private key. The seed is the first 32 bytes of the 64-byte key.

## Refresh API Contract

### Endpoint

```
POST /v1/license/refresh
```

Default base URL: `https://api.varax.io/v1`

Override via `VARAX_API_URL` environment variable.

### Request

```json
{
  "key": "<current_license_key>"
}
```

Headers:
- `Content-Type: application/json`
- `User-Agent: varax`

### Response Codes

| Status | Meaning | CLI Error |
|--------|---------|-----------|
| 200 | Success — new key in response body | — |
| 401 | Subscription inactive | `ErrSubscriptionInactive` |
| 404 | License not recognized | `ErrLicenseNotFound` |
| 429 | Rate limited | `ErrRateLimited` |
| 5xx | Server error | `ErrServerError` |

### Success Response (200)

```json
{
  "key": "<new_license_key>"
}
```

### Error Response (non-200)

```json
{
  "error": "human-readable error message"
}
```
