package adapters

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"holmes/internal/model"
	"holmes/internal/service"
)

type OSVAdapter struct {
	client *service.CachedClient
}

func NewOSVAdapter(client *service.CachedClient) *OSVAdapter {
	return &OSVAdapter{client: client}
}

type OSVBatchQuery struct {
	Package struct {
		Name      string `json:"name,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package"`
}

type osvBatchRequest struct {
	Queries []OSVBatchQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			PURL string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Repo   string `json:"repo"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
			DatabaseSpecific struct {
				Versions []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				} `json:"versions"`
			} `json:"database_specific"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
}

func (a *OSVAdapter) QueryBatch(ctx context.Context, queries []OSVBatchQuery) ([]model.Vulnerability, error) {
	body, _ := json.Marshal(osvBatchRequest{Queries: queries})
	var res osvBatchResponse
	err := a.client.FetchJSON(ctx, "osv", service.Request{
		URL:     "https://api.osv.dev/v1/querybatch",
		Method:  http.MethodPost,
		Body:    body,
		Headers: map[string]string{"Content-Type": "application/json"},
	}, &res)
	if err != nil {
		return nil, err
	}
	out := make([]model.Vulnerability, 0)
	for _, r := range res.Results {
		for _, v := range r.Vulns {
			out = append(out, mapOSVVuln(v))
		}
	}
	return dedupeVulns(out), nil
}

func (a *OSVAdapter) GetVulnByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	var res osvVuln
	err := a.client.FetchJSON(ctx, "osv", service.Request{
		URL:    "https://api.osv.dev/v1/vulns/" + id,
		Method: http.MethodGet,
	}, &res)
	if err != nil {
		return nil, err
	}
	v := mapOSVVuln(res)
	return &v, nil
}

func mapOSVVuln(in osvVuln) model.Vulnerability {
	v := model.Vulnerability{
		ID:          in.ID,
		Origin:      "osv",
		Aliases:     in.Aliases,
		Summary:     in.Summary,
		Description: in.Details,
		References:  make([]model.Reference, 0, len(in.References)),
		PublishedAt: parseRFC3339(in.Published),
		UpdatedAt:   parseRFC3339(in.Modified),
	}
	for _, r := range in.References {
		v.References = append(v.References, model.Reference{Type: r.Type, URL: r.URL})
	}
	if len(in.Severity) > 0 {
		score, vector, version := parseCVSS(in.Severity[0].Score)
		if score > 0 || vector != "" {
			v.CVSS = &model.CVSSInfo{Score: score, Vector: vector, Version: version}
		}
	}
	if in.DatabaseSpecific.Severity != "" {
		v.Severity = in.DatabaseSpecific.Severity
	} else if v.CVSS != nil && v.CVSS.Score > 0 {
		v.Severity = cvssScoreToSeverity(v.CVSS.Score)
	}
	affectedSeen := map[string]struct{}{}
	for _, aff := range in.Affected {
		for _, version := range aff.Versions {
			if _, ok := affectedSeen[version]; !ok {
				affectedSeen[version] = struct{}{}
				v.AffectedVersions = append(v.AffectedVersions, version)
			}
		}
		for _, r := range aff.Ranges {
			ar := model.AffectedRange{
				Type:    r.Type,
				RepoURL: r.Repo,
				PURL:    aff.Package.PURL,
			}
			// Extract semver introduced/fixed from database_specific.versions.
			// For GIT ranges these are the human-readable semver equivalents of
			// the commit-hash events.
			for _, dbv := range r.DatabaseSpecific.Versions {
				if dbv.Introduced != "" && ar.VersionIntroduced == "" {
					ar.VersionIntroduced = dbv.Introduced
				}
				if dbv.Fixed != "" && ar.VersionFixed == "" {
					ar.VersionFixed = dbv.Fixed
				}
			}
			for _, ev := range r.Events {
				if ar.Introduced == "" && ev.Introduced != "" {
					ar.Introduced = ev.Introduced
				}
				if ev.Fixed != "" {
					ar.Fixed = ev.Fixed
				}
			}
			v.AffectedRanges = append(v.AffectedRanges, ar)
		}
	}
	// FixedVersions is intentionally NOT populated here. Each affected package
	// in an OSV record has its own fix version stored in AffectedRanges[].Fixed /
	// AffectedRanges[].VersionFixed, keyed by PURL. Aggregating them into a flat
	// list would mix versions from different packages (e.g. stdlib and x/sys).
	return v
}

func parseCVSS(raw string) (float64, string, string) {
	if raw == "" {
		return 0, "", ""
	}
	version := ""
	score := 0.0
	switch {
	case strings.HasPrefix(raw, "CVSS:3.1"):
		version = "3.1"
		score = computeCVSS3Score(raw)
	case strings.HasPrefix(raw, "CVSS:3.0"):
		version = "3.0"
		score = computeCVSS3Score(raw)
	case strings.HasPrefix(raw, "CVSS:4.0"):
		version = "4.0"
	}
	return score, raw, version
}

func computeCVSS3Score(vector string) float64 {
	idx := strings.Index(vector, "/")
	if idx < 0 {
		return 0
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector[idx+1:], "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	scope := m["S"]
	av := cvss3AV(m["AV"])
	ac := cvss3AC(m["AC"])
	pr := cvss3PR(m["PR"], scope)
	ui := cvss3UI(m["UI"])
	conf := cvss3Impact(m["C"])
	integ := cvss3Impact(m["I"])
	avail := cvss3Impact(m["A"])

	iscBase := 1.0 - (1.0-conf)*(1.0-integ)*(1.0-avail)
	if iscBase == 0 {
		return 0
	}
	var isc float64
	if scope == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}
	exploit := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = math.Min(isc+exploit, 10)
	} else {
		base = math.Min(1.08*(isc+exploit), 10)
	}
	return math.Ceil(base*10) / 10
}

func cvss3AV(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.20
	}
	return 0
}

func cvss3AC(v string) float64 {
	switch v {
	case "L":
		return 0.77
	case "H":
		return 0.44
	}
	return 0
}

func cvss3PR(v, scope string) float64 {
	if scope == "C" {
		switch v {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.50
		}
	} else {
		switch v {
		case "N":
			return 0.85
		case "L":
			return 0.62
		case "H":
			return 0.27
		}
	}
	return 0
}

func cvss3UI(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "R":
		return 0.62
	}
	return 0
}

func cvss3Impact(v string) float64 {
	switch v {
	case "N":
		return 0
	case "L":
		return 0.22
	case "H":
		return 0.56
	}
	return 0
}

func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func parseRFC3339(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func dedupeVulns(in []model.Vulnerability) []model.Vulnerability {
	byID := map[string]model.Vulnerability{}
	for _, v := range in {
		if v.ID == "" {
			continue
		}
		old, ok := byID[v.ID]
		if !ok || (old.Origin != "osv" && v.Origin == "osv") {
			byID[v.ID] = v
		}
	}
	out := make([]model.Vulnerability, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	return out
}
