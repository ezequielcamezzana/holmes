package version

import (
	"context"
	"testing"

	"holmes/internal/model"
)

func TestVersionDetectiveExplicitAffectedVersion(t *testing.T) {
	d := New()
	clues := &model.Clues{
		Version: "v1.2.1",
		Vulnerabilities: []model.Vulnerability{
			{ID: "GHSA-1", Origin: "osv", AffectedVersions: []string{"1.2.1", "1.2.2"}, FixedVersions: []string{"1.2.3"}},
		},
	}
	inv, err := d.Investigate(context.Background(), clues)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != model.StatusSuccess {
		t.Fatalf("expected success, got %s", inv.Status)
	}
	if !clues.VersionCheck.IsVulnerable {
		t.Fatal("expected vulnerable")
	}
	if clues.VersionCheck.NearestFix != "1.2.3" {
		t.Fatalf("expected nearest fix 1.2.3, got %s", clues.VersionCheck.NearestFix)
	}
}

func TestVersionDetectiveRangeCheck(t *testing.T) {
	d := New()
	clues := &model.Clues{
		Version: "1.5.0",
		Vulnerabilities: []model.Vulnerability{
			{ID: "GHSA-2", Origin: "osv", AffectedRanges: []model.AffectedRange{{Type: "ECOSYSTEM", Introduced: "1.0.0", Fixed: "2.0.0"}}, FixedVersions: []string{"2.0.0"}},
		},
	}
	_, err := d.Investigate(context.Background(), clues)
	if err != nil {
		t.Fatal(err)
	}
	if !clues.VersionCheck.IsVulnerable {
		t.Fatal("expected version to be vulnerable in range")
	}
	if len(clues.VersionCheck.AffectingVulns) != 1 || clues.VersionCheck.AffectingVulns[0].MatchMethod != "range_check" {
		t.Fatal("expected range_check match")
	}
}

func TestVersionDetectiveSemverRangeType(t *testing.T) {
	d := New()
	clues := &model.Clues{
		Version: "0.8.1",
		Vulnerabilities: []model.Vulnerability{
			{
				ID:     "GHSA-axios",
				Origin: "both",
				AffectedRanges: []model.AffectedRange{
					{Type: "SEMVER", Introduced: "0", Fixed: "0.18.1"},
				},
				FixedVersions: []string{"0.18.1"},
			},
		},
	}
	_, err := d.Investigate(context.Background(), clues)
	if err != nil {
		t.Fatal(err)
	}
	if !clues.VersionCheck.IsVulnerable {
		t.Fatal("expected 0.8.1 to match SEMVER range 0 - 0.18.1")
	}
	if clues.VersionCheck.NearestFix != "0.18.1" {
		t.Fatalf("expected nearest fix 0.18.1, got %s", clues.VersionCheck.NearestFix)
	}
}

func TestVersionDetectiveExplicitAffectedFlaskCase(t *testing.T) {
	d := New()
	clues := &model.Clues{
		Version: "0.3.1",
		Vulnerabilities: []model.Vulnerability{
			{
				ID:                 "GHSA-562c-5r94-xh97",
				Origin:             "ecosystems",
				AffectedVersions:   []string{"0.3.1", "0.5.1"},
				UnaffectedVersions: []string{"0.12.3"},
				FixedVersions:      []string{"0.12.3"},
			},
		},
	}
	_, err := d.Investigate(context.Background(), clues)
	if err != nil {
		t.Fatal(err)
	}
	if !clues.VersionCheck.IsVulnerable {
		t.Fatal("expected 0.3.1 to be vulnerable by explicit affected_versions")
	}
	if clues.VersionCheck.NearestFix != "0.12.3" {
		t.Fatalf("expected nearest fix 0.12.3, got %s", clues.VersionCheck.NearestFix)
	}
}

func TestNormalizeSemver(t *testing.T) {
	if _, ok := normalizeSemver("1.2"); ok {
		t.Fatal("expected invalid semver")
	}
	v, ok := normalizeSemver("v1.2.3")
	if !ok || v != "1.2.3" {
		t.Fatalf("unexpected normalized version %q (ok=%v)", v, ok)
	}
}
