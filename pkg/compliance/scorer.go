package compliance

import "github.com/kubeshield/operator/pkg/models"

// Scorer calculates compliance scores from control results.
type Scorer struct{}

// Calculate returns the compliance score as a percentage.
// Score = (passing assessed controls / total assessed controls) * 100
func (s *Scorer) Calculate(results []models.ControlResult) float64 {
	assessed := 0
	passing := 0

	for _, r := range results {
		if r.Status == models.ControlStatusNotAssessed {
			continue
		}
		assessed++
		if r.Status == models.ControlStatusPass {
			passing++
		}
	}

	if assessed == 0 {
		return 0
	}

	return float64(passing) / float64(assessed) * 100
}
