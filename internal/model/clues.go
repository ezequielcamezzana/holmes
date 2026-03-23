package model

// Clues holds both input and accumulated evidence through the detective pipeline.
type Clues struct {
	RawName   string
	Ecosystem string
	RepoURL   string
	Version   string
	PURL      string
	CPE       string // CPE 2.3 string — used by the NVD detective (future)

	ResolvedName string
	PackageData  *PackageData
	PURLs        []string

	Vulnerabilities []Vulnerability
	VersionCheck    *VersionAssessment
}
