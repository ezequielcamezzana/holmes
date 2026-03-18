package vuln

import (
	"testing"
	"time"

	"holmes/internal/model"
)

func TestMergeVulnerabilities_AdvisoryAndOSV(t *testing.T) {
	eco := model.Vulnerability{
		ID:                 "GHSA-1",
		Origin:             "ecosystems",
		AffectedVersions:   []string{"1.0.0"},
		UnaffectedVersions: []string{"1.0.1"},
		PublishedAt:        time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
	}
	osv := model.Vulnerability{
		ID:             "GHSA-1",
		Origin:         "osv",
		AffectedRanges: []model.AffectedRange{{Type: "GIT", VersionIntroduced: "1.0.0", VersionFixed: "1.0.2"}},
		UpdatedAt:      time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
	}

	got := mergeVulnerabilities(eco, osv)
	if got.Origin != "both" {
		t.Fatalf("expected origin both, got %q", got.Origin)
	}
	if len(got.UnaffectedVersions) != 1 || got.UnaffectedVersions[0] != "1.0.1" {
		t.Fatalf("expected unaffected versions preserved, got %#v", got.UnaffectedVersions)
	}
	if len(got.AffectedRanges) != 1 || got.AffectedRanges[0].Type != "GIT" {
		t.Fatalf("expected merged GIT range, got %#v", got.AffectedRanges)
	}
}
