package evidence

import "time"

// EvidenceBundle is the top-level container for all collected evidence.
type EvidenceBundle struct {
	CollectedAt time.Time      `json:"collectedAt"`
	ClusterName string         `json:"clusterName"`
	Items       []EvidenceItem `json:"items"`
}

// EvidenceItem represents a single piece of auditor-ready evidence.
type EvidenceItem struct {
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Data        any       `json:"data"`
	Timestamp   time.Time `json:"timestamp"`
}
