package resolver

import (
	"context"
	"strings"
	"time"

	"holmes/internal/detective"
	"holmes/internal/model"
)

type Resolver struct {
	pipeline []detective.Detective
}

func New(detectives ...detective.Detective) *Resolver {
	return &Resolver{pipeline: detectives}
}

// versionFromPURL extracts the version from a PURL string.
// "pkg:golang/golang.org/x/sys@v0.38.0" → "v0.38.0"
func versionFromPURL(purl string) string {
	s := strings.SplitN(purl, "?", 2)[0]
	s = strings.SplitN(s, "#", 2)[0]
	if idx := strings.LastIndex(s, "@"); idx >= 0 {
		return s[idx+1:]
	}
	return ""
}

func (r *Resolver) Resolve(ctx context.Context, req model.ResolveRequest) model.CaseReport {
	version := req.Version
	if version == "" && req.PURL != "" {
		version = versionFromPURL(req.PURL)
	}
	clues := &model.Clues{
		RawName:   req.Name,
		Ecosystem: req.Ecosystem,
		RepoURL:   req.RepositoryURL,
		Version:   version,
		PURL:      req.PURL,
	}
	report := model.CaseReport{Investigations: make([]model.Investigation, 0, len(r.pipeline))}
	for _, d := range r.pipeline {
		inv, err := d.Investigate(ctx, clues)
		if err != nil {
			inv.Status = model.StatusFailed
			inv.Error = err.Error()
		}
		report.Investigations = append(report.Investigations, inv)
	}
	report.Package = clues.PackageData
	report.Vulnerabilities = clues.Vulnerabilities
	report.VersionCheck = clues.VersionCheck
	report.ResolvedAt = time.Now().UTC()
	return report
}
