package explore

import (
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type viewID int

const (
	viewControls viewID = iota
	viewControlDetail
	viewCheckDetail
)

// Data holds all data needed by the explore TUI.
type Data struct {
	Compliance       *models.ComplianceResult
	Scan             *models.ScanResult
	Evidence         *evidence.EvidenceBundle
	HistoricalScores []float64
}

// navigationMsg triggers a view transition.
type navigationMsg struct {
	target    viewID
	controlIdx int
	checkIdx   int
}
