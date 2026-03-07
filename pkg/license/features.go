package license

const (
	FeatureReports          = "reports"
	FeatureEvidence         = "evidence"
	FeatureRemediation      = "remediation"
	FeatureScheduledReports = "scheduled-reports"
	FeatureExplore          = "explore"
)

var proFeatures = map[string]bool{
	FeatureReports:          true,
	FeatureEvidence:         true,
	FeatureRemediation:      true,
	FeatureScheduledReports: true,
	FeatureExplore:          true,
}

func IsProFeature(feature string) bool {
	return proFeatures[feature]
}
