package version

import (
	"context"
	"strconv"
	"strings"

	"holmes/internal/model"
)

type Detective struct{}

func New() *Detective { return &Detective{} }

func (d *Detective) Investigate(_ context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "version", Status: model.StatusSuccess}
	if clues.Version == "" {
		inv.Status = model.StatusSkipped
		inv.Error = "version not provided"
		return inv, nil
	}
	assessment := &model.VersionAssessment{RequestedVersion: clues.Version}
	vNorm, ok := normalizeSemver(clues.Version)
	if !ok {
		assessment.IsValidSemver = false
		clues.VersionCheck = assessment
		inv.Result = assessment
		return inv, nil
	}
	assessment.IsValidSemver = true
	// Strip the version from the PURL so we can match against range PURLs (which have no version).
	// For URL-based lookups clues.PURL is empty; fall back to the canonical PURL from package data.
	purlBase := stripPURLVersion(clues.PURL)
	if purlBase == "" && clues.PackageData != nil && len(clues.PackageData.PURLs) > 0 {
		purlBase = clues.PackageData.PURLs[0]
	}

	candidateFixes := make([]string, 0)
	for _, vuln := range clues.Vulnerabilities {
		if match, method, rangeFix := matchesVuln(clues.Version, vNorm, purlBase, vuln); match {
			fix := rangeFix
			if fix == "" {
				// Explicit-list match: derive fix from PURL-filtered ranges.
				fix = nearestFixFromRanges(vNorm, purlBase, vuln.AffectedRanges)
				if fix == "" {
					// Last resort: global FixedVersions (ecosystems-origin data).
					fix = nearestFixAbove(vNorm, vuln.FixedVersions)
				}
			}
			assessment.AffectingVulns = append(assessment.AffectingVulns, model.AffectingVuln{ID: vuln.ID, MatchMethod: method, FixedIn: fix})
			if fix != "" {
				candidateFixes = append(candidateFixes, fix)
			}
		}
	}
	assessment.IsVulnerable = len(assessment.AffectingVulns) > 0
	if fix := nearestFixAbove(vNorm, candidateFixes); fix != "" {
		assessment.FixAvailable = true
		assessment.NearestFix = fix
	}
	clues.VersionCheck = assessment
	inv.Result = assessment
	return inv, nil
}

// matchesVuln returns (matched, method, rangeFix).
// rangeFix is the fixed version from the specific matching range (may be empty for explicit-list matches).
// packagePURL is the base PURL of the queried package (no version) used to filter AffectedRanges.
func matchesVuln(rawVersion, version string, packagePURL string, vuln model.Vulnerability) (bool, string, string) {
	if len(vuln.UnaffectedVersions) > 0 {
		for _, uv := range vuln.UnaffectedVersions {
			if canonicalVersionEq(rawVersion, uv) {
				return false, "explicit_unaffected", ""
			}
			norm, ok := normalizeSemver(uv)
			if ok && compareSemver(version, norm) == 0 {
				return false, "explicit_unaffected", ""
			}
		}
	}
	if len(vuln.AffectedVersions) > 0 {
		for _, av := range vuln.AffectedVersions {
			if canonicalVersionEq(rawVersion, av) {
				return true, "explicit_list", ""
			}
			norm, ok := normalizeSemver(av)
			if ok && compareSemver(version, norm) == 0 {
				return true, "explicit_list", ""
			}
		}
		return false, "explicit_list", ""
	}
	ranges := relevantRanges(vuln.AffectedRanges, packagePURL)
	for _, r := range ranges {
		if strings.EqualFold(r.Type, "ECOSYSTEM") || strings.EqualFold(r.Type, "SEMVER") {
			introduced := firstNonEmpty(r.Introduced, r.VersionIntroduced)
			fixed := firstNonEmpty(r.Fixed, r.VersionFixed)
			if inRange(version, introduced, fixed) {
				return true, "range_check", fixed
			}
		}
		if strings.EqualFold(r.Type, "GIT") {
			// GIT ranges use commit hashes for Introduced/Fixed, which cannot
			// be used for semver comparison. Only check if semver equivalents
			// are available in database_specific.versions (VersionIntroduced/VersionFixed).
			if r.VersionIntroduced == "" && r.VersionFixed == "" {
				continue
			}
			if inRange(version, r.VersionIntroduced, r.VersionFixed) {
				return true, "range_check", r.VersionFixed
			}
		}
	}
	return false, "", ""
}

// relevantRanges filters AffectedRanges to those matching the given packagePURL.
// If packagePURL is empty or no ranges match, all ranges are returned (safe fallback).
func relevantRanges(ranges []model.AffectedRange, packagePURL string) []model.AffectedRange {
	if packagePURL == "" {
		return ranges
	}
	matched := make([]model.AffectedRange, 0, len(ranges))
	for _, r := range ranges {
		if r.PURL == "" || strings.EqualFold(r.PURL, packagePURL) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return ranges // no PURL data — fall back to all ranges
	}
	return matched
}

// stripPURLVersion removes the @version suffix from a PURL.
// "pkg:golang/golang.org/x/sys@v0.38.0" → "pkg:golang/golang.org/x/sys"
func stripPURLVersion(purl string) string {
	if idx := strings.LastIndex(purl, "@"); idx >= 0 {
		return purl[:idx]
	}
	return purl
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func canonicalVersionEq(a, b string) bool {
	normalize := func(v string) string {
		return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	}
	return normalize(a) == normalize(b)
}

func inRange(version, introduced, fixed string) bool {
	if introduced == "" || introduced == "0" {
		introduced = "0.0.0"
	}
	intro, ok := normalizeSemver(introduced)
	if !ok {
		intro = "0.0.0"
	}
	if compareSemver(version, intro) < 0 {
		return false
	}
	if fixed == "" {
		return true
	}
	fNorm, ok := normalizeSemver(fixed)
	if !ok {
		return true
	}
	return compareSemver(version, fNorm) < 0
}

// nearestFixFromRanges finds the nearest fix version above current from
// PURL-filtered AffectedRanges. Uses both VersionFixed (semver) and Fixed
// (which may be a semver or a pseudo-version).
func nearestFixFromRanges(current, packagePURL string, ranges []model.AffectedRange) string {
	fixes := make([]string, 0, len(ranges))
	for _, r := range relevantRanges(ranges, packagePURL) {
		if f := firstNonEmpty(r.VersionFixed, r.Fixed); f != "" {
			fixes = append(fixes, f)
		}
	}
	return nearestFixAbove(current, fixes)
}

func nearestFixAbove(current string, fixes []string) string {
	nearest := ""
	for _, fix := range fixes {
		norm, ok := normalizeSemver(fix)
		if !ok {
			continue
		}
		if compareSemver(norm, current) <= 0 {
			continue
		}
		if nearest == "" || compareSemver(norm, nearest) < 0 {
			nearest = norm
		}
	}
	return nearest
}

func normalizeSemver(v string) (string, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	parts := strings.SplitN(v, "-", 2)
	core := parts[0]
	segs := strings.Split(core, ".")
	if len(segs) != 3 {
		return "", false
	}
	for _, s := range segs {
		if s == "" {
			return "", false
		}
		if _, err := strconv.Atoi(s); err != nil {
			return "", false
		}
	}
	if len(parts) == 2 {
		return core + "-" + parts[1], true
	}
	return core, true
}

func compareSemver(a, b string) int {
	aa := strings.SplitN(a, "-", 2)
	bb := strings.SplitN(b, "-", 2)
	aCore := strings.Split(aa[0], ".")
	bCore := strings.Split(bb[0], ".")
	for i := 0; i < 3; i++ {
		ai, _ := strconv.Atoi(aCore[i])
		bi, _ := strconv.Atoi(bCore[i])
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	if len(aa) == 1 && len(bb) == 2 {
		return 1
	}
	if len(aa) == 2 && len(bb) == 1 {
		return -1
	}
	if len(aa) == 2 && len(bb) == 2 {
		if aa[1] < bb[1] {
			return -1
		}
		if aa[1] > bb[1] {
			return 1
		}
	}
	return 0
}
