package model

type VersionAssessment struct {
	RequestedVersion string          `json:"requested_version"`
	IsValidSemver    bool            `json:"is_valid_semver"`
	IsVulnerable     bool            `json:"is_vulnerable"`
	AffectingVulns   []AffectingVuln `json:"affecting_vulns,omitempty"`
	FixAvailable     bool            `json:"fix_available"`
	NearestFix       string          `json:"nearest_fix,omitempty"`
}

type AffectingVuln struct {
	ID          string `json:"id"`
	FixedIn     string `json:"fixed_in,omitempty"`
	MatchMethod string `json:"match_method"`
}
