package model

// Clues holds both input and accumulated evidence through the detective pipeline.
type Clues struct {
	RawName   string
	Ecosystem string
	RepoURL   string
	Version   string
	PURL      string

	ResolvedName string
	PackageData  *PackageData
	PURLs        []string

	Vulnerabilities []Vulnerability
	VersionCheck    *VersionAssessment
}
