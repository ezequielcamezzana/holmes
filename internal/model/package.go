package model

import "time"

type PackageData struct {
	Name           string        `json:"name"`
	Ecosystem      string        `json:"ecosystem"`
	Description    string        `json:"description"`
	RepoURL        string        `json:"repo_url"`
	Homepage       string        `json:"homepage"`
	PURLs          []string      `json:"purls"`
	CPEs           []string      `json:"cpes,omitempty"`
	Licenses       []string      `json:"licenses"`
	Languages      []string      `json:"languages,omitempty"`
	Keywords       []string      `json:"keywords,omitempty"`
	Versions       []VersionInfo `json:"versions,omitempty"`
	LatestVersion  string        `json:"latest_version"`
	CreatedAt      time.Time     `json:"created_at"`
	LastUpdatedAt  time.Time     `json:"last_updated_at"`
	LastReleasedAt time.Time     `json:"last_released_at"`
	Usage          *UsageInfo    `json:"usage,omitempty"`
	Maintainers    []Maintainer  `json:"maintainers,omitempty"`
	IsCritical     bool          `json:"is_critical"`
	Advisories     []Advisory    `json:"advisories,omitempty"`
}

type Advisory struct {
	UUID        string            `json:"uuid,omitempty"`
	URL         string            `json:"url,omitempty"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	CVSSScore   float64           `json:"cvss_score,omitempty"`
	CVSSVector  string            `json:"cvss_vector,omitempty"`
	Identifiers []string          `json:"identifiers,omitempty"`
	References  []string          `json:"references,omitempty"`
	PublishedAt time.Time         `json:"published_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	Packages    []AdvisoryPackage `json:"packages,omitempty"`
}

type AdvisoryPackage struct {
	Ecosystem          string                 `json:"ecosystem,omitempty"`
	PackageName        string                 `json:"package_name,omitempty"`
	PURL               string                 `json:"purl,omitempty"`
	AffectedVersions   []string               `json:"affected_versions,omitempty"`
	UnaffectedVersions []string               `json:"unaffected_versions,omitempty"`
	VersionRanges      []AdvisoryVersionRange `json:"version_ranges,omitempty"`
}

type AdvisoryVersionRange struct {
	VulnerableRange     string `json:"vulnerable_range,omitempty"`
	FirstPatchedVersion string `json:"first_patched_version,omitempty"`
}

type VersionInfo struct {
	Version    string    `json:"version"`
	ReleasedAt time.Time `json:"released_at"`
}

type UsageInfo struct {
	Stars      int `json:"stars"`
	Forks      int `json:"forks"`
	Dependents int `json:"dependents"`
	Downloads  int `json:"downloads"`
}

type Maintainer struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	Email string `json:"email"`
	Role  string `json:"role"`
}
