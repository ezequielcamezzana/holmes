package vuln

import (
	"context"
	"sort"
	"strings"
	"time"

	"holmes/internal/cache"
	"holmes/internal/model"
	"holmes/internal/service/adapters"
)

type Detective struct {
	osv   *adapters.OSVAdapter
	store cache.DomainStore
}

func New(osv *adapters.OSVAdapter, store cache.DomainStore) *Detective {
	return &Detective{osv: osv, store: store}
}

func (d *Detective) Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "vulnerability", Status: model.StatusSuccess}
	byID := map[string]model.Vulnerability{}

	// Phase 1: ecosyste.ms advisories embedded in PackageData.
	if clues.PackageData != nil {
		for _, adv := range clues.PackageData.Advisories {
			v := advisoryToVuln(adv)
			if v.ID == "" {
				continue
			}
			byID[v.ID] = v
			for _, p := range adv.Packages {
				if p.PURL != "" {
					clues.PURLs = append(clues.PURLs, p.PURL)
				}
			}
		}
		// Persist ecosystems advisories (7-day TTL — refreshed with the package).
		if d.store != nil && len(byID) > 0 {
			ecoVulns := make([]model.Vulnerability, 0, len(byID))
			for _, v := range byID {
				ecoVulns = append(ecoVulns, v)
			}
			_ = d.store.SaveVulns(ctx, ecoVulns, 7*24*time.Hour)
		}
	}
	clues.PURLs = uniqueStrings(clues.PURLs)

	// Phase 2: check domain cache for a prior OSV query on this package.
	pkgName, pkgEco := packageIdentifier(clues)
	if d.store != nil && pkgName != "" {
		if ids, ok, _ := d.store.GetVulnQuery(ctx, pkgName, pkgEco); ok {
			for _, id := range ids {
				if v, _ := d.store.GetVuln(ctx, id); v != nil {
					if existing, exists := byID[id]; exists {
						byID[id] = mergeVulnerabilities(existing, *v)
					} else {
						byID[id] = *v
					}
				}
			}
			clues.Vulnerabilities = buildFinal(byID)
			inv.Result = map[string]int{"count": len(clues.Vulnerabilities)}
			return inv, nil
		}
	}

	// Phase 2: no cache hit — query OSV.
	queries := buildOSVQueries(clues)
	if len(queries) == 0 && len(byID) == 0 {
		inv.Status = model.StatusSkipped
		inv.Error = "no identifiers available for vulnerability lookup"
		return inv, nil
	}

	var osvVulnIDs []string
	if len(queries) > 0 {
		osvVulns, err := d.osv.QueryBatch(ctx, queries)
		if err != nil {
			if len(byID) > 0 {
				clues.Vulnerabilities = buildFinal(byID)
				inv.Error = "osv query failed, returned advisories-only data: " + err.Error()
				inv.Result = map[string]any{"count": len(clues.Vulnerabilities), "source": "ecosystems_fallback"}
				return inv, nil
			}
			inv.Status = model.StatusFailed
			inv.Error = err.Error()
			return inv, nil
		}

		for _, osvV := range osvVulns {
			// Fetch full record if the batch returned a stub (id+modified only).
			// Only skip the HTTP call if we already have an OSV-origin record in the
			// domain store — an ecosystems-origin record is not a substitute.
			if len(osvV.AffectedRanges) == 0 && len(osvV.AffectedVersions) == 0 && osvV.ID != "" {
				fetched := false
				if d.store != nil {
					if cached, _ := d.store.GetVuln(ctx, osvV.ID); cached != nil && cached.Origin == "osv" {
						osvV = *cached
						fetched = true
					}
				}
				if !fetched {
					if full, err := d.osv.GetVulnByID(ctx, osvV.ID); err == nil && full != nil {
						osvV = *full
					}
				}
			}
			if existing, ok := byID[osvV.ID]; ok {
				byID[osvV.ID] = mergeVulnerabilities(existing, osvV)
			} else {
				byID[osvV.ID] = osvV
			}
			if osvV.ID != "" {
				osvVulnIDs = append(osvVulnIDs, osvV.ID)
			}
		}

		// Persist OSV vulns and record the query result.
		if d.store != nil {
			osvVulnsToSave := make([]model.Vulnerability, 0, len(osvVulnIDs))
			for _, id := range osvVulnIDs {
				if v, ok := byID[id]; ok {
					osvVulnsToSave = append(osvVulnsToSave, v)
				}
			}
			_ = d.store.SaveVulns(ctx, osvVulnsToSave, 24*time.Hour)
			if pkgName != "" {
				_ = d.store.SaveVulnQuery(ctx, pkgName, pkgEco, osvVulnIDs, 24*time.Hour)
			}
		}
	}

	clues.Vulnerabilities = buildFinal(byID)
	inv.Result = map[string]int{"count": len(clues.Vulnerabilities)}
	return inv, nil
}

func buildFinal(byID map[string]model.Vulnerability) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func packageIdentifier(clues *model.Clues) (string, string) {
	if clues.PackageData != nil {
		return clues.PackageData.Name, clues.PackageData.Ecosystem
	}
	name := clues.ResolvedName
	if name == "" {
		name = clues.RawName
	}
	return name, strings.ToLower(clues.Ecosystem)
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
			ar := advisoryRangeToAffectedRange(p.PURL, vr)
			if ar != nil {
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

func advisoryRangeToAffectedRange(purl string, vr model.AdvisoryVersionRange) *model.AffectedRange {
	introduced := ""
	rangeText := strings.TrimSpace(vr.VulnerableRange)
	for _, part := range strings.Split(rangeText, ",") {
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

func mergeVulnerabilities(primary, incoming model.Vulnerability) model.Vulnerability {
	out := primary
	out.Aliases = uniqueStrings(append(out.Aliases, incoming.Aliases...))
	if out.Summary == "" {
		out.Summary = incoming.Summary
	}
	if out.Description == "" {
		out.Description = incoming.Description
	}
	if out.Severity == "" {
		out.Severity = incoming.Severity
	}
	if out.CVSS == nil || (out.CVSS.Score == 0 && out.CVSS.Vector == "") {
		out.CVSS = incoming.CVSS
	}
	out.AffectedVersions = uniqueStrings(append(out.AffectedVersions, incoming.AffectedVersions...))
	out.UnaffectedVersions = uniqueStrings(append(out.UnaffectedVersions, incoming.UnaffectedVersions...))
	out.FixedVersions = uniqueStrings(append(out.FixedVersions, incoming.FixedVersions...))
	out.AffectedRanges = uniqueAffectedRanges(append(out.AffectedRanges, incoming.AffectedRanges...))
	out.References = uniqueReferences(append(out.References, incoming.References...))
	out.PublishedAt = choosePublished(out.PublishedAt, incoming.PublishedAt)
	out.UpdatedAt = chooseUpdated(out.UpdatedAt, incoming.UpdatedAt)
	if out.Origin != incoming.Origin {
		out.Origin = "both"
	}
	return out
}

func buildOSVQueries(clues *model.Clues) []adapters.OSVBatchQuery {
	queries := make([]adapters.OSVBatchQuery, 0)
	for _, p := range uniqueStrings(clues.PURLs) {
		if p == "" {
			continue
		}
		q := adapters.OSVBatchQuery{}
		q.Package.PURL = p
		queries = append(queries, q)
	}
	name := clues.ResolvedName
	if name == "" {
		name = clues.RawName
	}
	if name == "" && clues.PackageData != nil {
		name = clues.PackageData.Name
	}
	eco := clues.Ecosystem
	if eco == "" && clues.PackageData != nil {
		eco = clues.PackageData.Ecosystem
	}
	if name != "" && eco != "" {
		if osvEco, ok := normalizeOSVEcosystem(eco); ok {
			q := adapters.OSVBatchQuery{}
			q.Package.Name = name
			q.Package.Ecosystem = osvEco
			queries = append(queries, q)
		}
	}
	if clues.RepoURL != "" {
		q := adapters.OSVBatchQuery{}
		q.Package.Name = clues.RepoURL
		q.Package.Ecosystem = "GIT"
		queries = append(queries, q)
	}
	return queries
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

func normalizeOSVEcosystem(e string) (string, bool) {
	switch strings.ToLower(e) {
	case "go", "golang":
		return "Go", true
	case "npm":
		return "npm", true
	case "pypi":
		return "PyPI", true
	default:
		return "", false
	}
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

func uniqueAffectedRanges(in []model.AffectedRange) []model.AffectedRange {
	seen := map[string]struct{}{}
	out := make([]model.AffectedRange, 0, len(in))
	for _, r := range in {
		k := strings.Join([]string{r.Type, r.RepoURL, r.PURL, r.Introduced, r.Fixed, r.VersionIntroduced, r.VersionFixed}, "|")
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
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

func choosePublished(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.Before(a) {
		return b
	}
	return a
}

func chooseUpdated(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.After(a) {
		return b
	}
	return a
}
