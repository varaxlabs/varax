package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// EvidenceBundle is the top-level container for all collected evidence.
type EvidenceBundle struct {
	CollectedAt time.Time      `json:"collectedAt"`
	ClusterName string         `json:"clusterName"`
	Items       []EvidenceItem `json:"items"`
}

// EvidenceItem represents a single piece of auditor-ready evidence.
type EvidenceItem struct {
	Category    string    `json:"category"`
	Type        string    `json:"type,omitempty"`
	Description string    `json:"description"`
	Data        any       `json:"data"`
	Timestamp   time.Time `json:"timestamp"`
	SHA256      string    `json:"sha256,omitempty"`
}

// computeSHA256 returns the hex-encoded SHA256 hash of the JSON-marshaled data.
func computeSHA256(data any) string {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}
