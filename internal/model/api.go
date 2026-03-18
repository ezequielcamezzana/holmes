package model

import "time"

type ResolveRequest struct {
	Name          string `json:"name"`
	Ecosystem     string `json:"ecosystem"`
	Version       string `json:"version"`
	RepositoryURL string `json:"repository_url"`
	PURL          string `json:"purl"`
}

type CaseReport struct {
	Investigations  []Investigation    `json:"investigations"`
	Package         *PackageData       `json:"package,omitempty"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities,omitempty"`
	VersionCheck    *VersionAssessment `json:"version_check,omitempty"`
	ResolvedAt      time.Time          `json:"resolved_at"`
}
