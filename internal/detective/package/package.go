package pkg

import (
	"context"
	"strings"
	"time"

	"holmes/internal/cache"
	"holmes/internal/model"
	"holmes/internal/service/adapters"
)

type Detective struct {
	eco   *adapters.EcosystemsAdapter
	store cache.DomainStore
}

func New(eco *adapters.EcosystemsAdapter, store cache.DomainStore) *Detective {
	return &Detective{eco: eco, store: store}
}

func (d *Detective) Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "package", Status: model.StatusSuccess}

	// Check domain cache first.
	if d.store != nil {
		term, termEco := lookupTerm(clues)
		if term != "" {
			if pd, err := d.store.FindPackage(ctx, term, termEco); err == nil && pd != nil {
				applyPackageData(clues, pd)
				inv.Result = pd
				return inv, nil
			}
		}
	}

	var (
		pd  *model.PackageData
		err error
	)
	switch {
	case clues.ResolvedName != "" && clues.Ecosystem != "":
		pd, _, _, err = d.eco.FetchByName(ctx, clues.Ecosystem, clues.ResolvedName)
	case clues.RawName != "" && clues.Ecosystem != "":
		pd, _, _, err = d.eco.FetchByName(ctx, clues.Ecosystem, clues.RawName)
	case clues.PURL != "":
		pd, _, _, err = d.eco.LookupByPURL(ctx, clues.PURL)
	case clues.RepoURL != "":
		pd, _, _, err = d.eco.LookupByRepo(ctx, clues.RepoURL)
	default:
		inv.Status = model.StatusSkipped
		inv.Error = "insufficient clues for package lookup"
		return inv, nil
	}
	if err != nil {
		inv.Status = model.StatusFailed
		inv.Error = err.Error()
		return inv, nil
	}

	if pd != nil {
		if d.store != nil {
			_ = d.store.SavePackage(ctx, pd, buildLookupTerms(clues, pd), 7*24*time.Hour)
		}
		applyPackageData(clues, pd)
	}
	inv.Result = pd
	return inv, nil
}

// applyPackageData sets package data on clues, expands advisory PURLs for later OSV queries,
// and converts each advisory to a Vulnerability with origin "ecosystems".
func applyPackageData(clues *model.Clues, pd *model.PackageData) {
	clues.PackageData = pd

	// Merge package-level PURLs with any additional PURLs from advisory packages.
	purls := make([]string, 0, len(pd.PURLs))
	purls = append(purls, pd.PURLs...)
	for _, adv := range pd.Advisories {
		for _, p := range adv.Packages {
			if p.PURL != "" {
				purls = append(purls, p.PURL)
			}
		}
	}
	clues.PURLs = uniqueStrings(purls)

	for _, adv := range pd.Advisories {
		if v := advisoryToVuln(adv); v.ID != "" {
			clues.Vulnerabilities = append(clues.Vulnerabilities, v)
		}
	}
}

func advisoryToVuln(a model.Advisory) model.Vulnerability {
	v := model.Vulnerability{
		ID:          advisoryID(a),
		Origin:      "ecosystems",
		Summary:     a.Title,
		Description: a.Description,
		Severity:    a.Severity,
		PublishedAt: a.PublishedAt,
		UpdatedAt:   a.UpdatedAt,
	}
	if len(a.Identifiers) > 1 {
		v.Aliases = uniqueStrings(a.Identifiers[1:])
	}
	if a.CVSSScore > 0 || a.CVSSVector != "" {
		v.CVSS = &model.CVSSInfo{Score: a.CVSSScore, Vector: a.CVSSVector}
	}
	for _, ref := range a.References {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		v.References = append(v.References, model.Reference{Type: "WEB", URL: ref})
	}
	for _, p := range a.Packages {
		v.AffectedVersions = append(v.AffectedVersions, p.AffectedVersions...)
		v.UnaffectedVersions = append(v.UnaffectedVersions, p.UnaffectedVersions...)
		for _, vr := range p.VersionRanges {
			if ar := advisoryRangeToAffectedRange(p.PURL, vr); ar != nil {
				v.AffectedRanges = append(v.AffectedRanges, *ar)
			}
			if vr.FirstPatchedVersion != "" {
				v.FixedVersions = append(v.FixedVersions, vr.FirstPatchedVersion)
			}
		}
	}
	v.AffectedVersions = uniqueStrings(v.AffectedVersions)
	v.UnaffectedVersions = uniqueStrings(v.UnaffectedVersions)
	v.FixedVersions = uniqueStrings(v.FixedVersions)
	v.References = uniqueReferences(v.References)
	return v
}

// advisoryRangeToAffectedRange parses a ">=X, <Y" style vulnerable_range into an AffectedRange.
// Returns nil if there is neither an introduced version nor a fixed version to report.
func advisoryRangeToAffectedRange(purl string, vr model.AdvisoryVersionRange) *model.AffectedRange {
	introduced := ""
	for _, part := range strings.Split(strings.TrimSpace(vr.VulnerableRange), ",") {
		p := strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(p, ">="):
			introduced = strings.TrimSpace(strings.TrimPrefix(p, ">="))
		case strings.HasPrefix(p, ">"):
			introduced = strings.TrimSpace(strings.TrimPrefix(p, ">"))
		case strings.HasPrefix(p, "="):
			introduced = strings.TrimSpace(strings.TrimPrefix(p, "="))
		}
	}
	if introduced == "" && strings.TrimSpace(vr.FirstPatchedVersion) == "" {
		return nil
	}
	return &model.AffectedRange{
		Type:       "ECOSYSTEM",
		PURL:       purl,
		Introduced: introduced,
		Fixed:      strings.TrimSpace(vr.FirstPatchedVersion),
	}
}

func advisoryID(a model.Advisory) string {
	if len(a.Identifiers) > 0 && strings.TrimSpace(a.Identifiers[0]) != "" {
		return strings.TrimSpace(a.Identifiers[0])
	}
	if strings.TrimSpace(a.UUID) != "" {
		return strings.TrimSpace(a.UUID)
	}
	return strings.TrimSpace(a.URL)
}

// lookupTerm returns the cache lookup key for the current clues state.
func lookupTerm(clues *model.Clues) (string, string) {
	if clues.ResolvedName != "" && clues.Ecosystem != "" {
		return clues.ResolvedName, strings.ToLower(clues.Ecosystem)
	}
	if clues.RawName != "" && clues.Ecosystem != "" {
		return clues.RawName, strings.ToLower(clues.Ecosystem)
	}
	if clues.PURL != "" {
		return clues.PURL, ""
	}
	if clues.RepoURL != "" {
		return clues.RepoURL, ""
	}
	return "", ""
}

// buildLookupTerms collects all identifiers that should resolve to this package.
func buildLookupTerms(clues *model.Clues, pd *model.PackageData) []cache.LookupTerm {
	seen := map[string]struct{}{}
	add := func(term, eco string) []cache.LookupTerm {
		if term == "" {
			return nil
		}
		k := term + "|" + eco
		if _, ok := seen[k]; ok {
			return nil
		}
		seen[k] = struct{}{}
		return []cache.LookupTerm{{Term: term, Ecosystem: eco}}
	}

	var terms []cache.LookupTerm
	terms = append(terms, add(pd.Name, pd.Ecosystem)...)
	if clues.RawName != "" {
		terms = append(terms, add(clues.RawName, strings.ToLower(clues.Ecosystem))...)
	}
	if clues.ResolvedName != "" {
		terms = append(terms, add(clues.ResolvedName, strings.ToLower(clues.Ecosystem))...)
	}
	if clues.RepoURL != "" {
		terms = append(terms, add(clues.RepoURL, "")...)
	}
	if clues.PURL != "" {
		terms = append(terms, add(clues.PURL, "")...)
	}
	for _, p := range pd.PURLs {
		terms = append(terms, add(p, "")...)
	}
	return terms
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func uniqueReferences(in []model.Reference) []model.Reference {
	seen := map[string]struct{}{}
	out := make([]model.Reference, 0, len(in))
	for _, r := range in {
		if strings.TrimSpace(r.URL) == "" {
			continue
		}
		k := r.Type + "|" + r.URL
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}
