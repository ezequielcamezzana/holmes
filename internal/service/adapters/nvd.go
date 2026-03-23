package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"holmes/internal/model"
)

const (
	nvdBaseURL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize   = 2000
	nvdMaxRetries = 10
	nvdDefaultWait = 30 * time.Second
)

type NVDAdapter struct {
	client *http.Client
	apiKey string
}

func NewNVDAdapter(client *http.Client, apiKey string) *NVDAdapter {
	return &NVDAdapter{client: client, apiKey: apiKey}
}

// ── NVD API response types ────────────────────────────────────────────────────

type nvdResponse struct {
	TotalResults   int          `json:"totalResults"`
	StartIndex     int          `json:"startIndex"`
	ResultsPerPage int          `json:"resultsPerPage"`
	Vulnerabilities []nvdCVEItem `json:"vulnerabilities"`
}

type nvdCVEItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string           `json:"id"`
	Published      string           `json:"published"`
	LastModified   string           `json:"lastModified"`
	Descriptions   []nvdDescription `json:"descriptions"`
	Metrics        nvdMetrics       `json:"metrics"`
	Configurations []nvdConfig      `json:"configurations"`
	References     []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode     `json:"children"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdReference struct {
	URL string `json:"url"`
}

// ── Query ─────────────────────────────────────────────────────────────────────

// QueryByCPE fetches all CVEs for the given CPE string from NVD with pagination.
// If the CPE's version field is '*' or '-', virtualMatchString is used;
// otherwise cpeName is used for exact version matching.
// 429 responses are retried up to nvdMaxRetries times, honouring the
// Retry-After header (default: nvdDefaultWait).
func (a *NVDAdapter) QueryByCPE(ctx context.Context, cpe string) ([]model.Vulnerability, error) {
	param := "cpeName"
	parts := strings.SplitN(cpe, ":", 13)
	if len(parts) >= 6 {
		v := parts[5]
		if v == "*" || v == "-" {
			param = "virtualMatchString"
		}
	}

	var all []model.Vulnerability
	startIndex := 0
	for {
		url := fmt.Sprintf("%s?%s=%s&resultsPerPage=%d&startIndex=%d",
			nvdBaseURL, param, cpe, nvdPageSize, startIndex)

		var res nvdResponse
		if err := a.fetchWithRetry(ctx, url, &res); err != nil {
			return nil, err
		}

		for _, item := range res.Vulnerabilities {
			all = append(all, mapNVDVuln(item.CVE))
		}

		startIndex += res.ResultsPerPage
		if startIndex >= res.TotalResults || len(res.Vulnerabilities) == 0 {
			break
		}
	}
	return all, nil
}

// fetchWithRetry performs a GET request to url, retrying on HTTP 429 up to
// nvdMaxRetries times. The wait duration is read from the Retry-After response
// header; nvdDefaultWait is used when the header is absent.
func (a *NVDAdapter) fetchWithRetry(ctx context.Context, url string, out any) error {
	for attempt := 0; attempt <= nvdMaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if a.apiKey != "" {
			req.Header.Set("apiKey", a.apiKey)
		}

		resp, err := a.client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfterDuration(resp)
			resp.Body.Close()
			log.Printf("[nvd] rate limited (429) — waiting %s before retry %d/%d",
				wait.Round(time.Second), attempt+1, nvdMaxRetries)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			return fmt.Errorf("nvd: http %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		log.Printf("[200][%s]", url)
		return json.Unmarshal(body, out)
	}
	return fmt.Errorf("nvd: exceeded %d retries (rate limited)", nvdMaxRetries)
}

// retryAfterDuration reads the Retry-After header from a 429 response.
// Falls back to nvdDefaultWait if the header is absent or unparseable.
func retryAfterDuration(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return nvdDefaultWait
}

// ── Mapping ───────────────────────────────────────────────────────────────────

func mapNVDVuln(cve nvdCVE) model.Vulnerability {
	v := model.Vulnerability{
		ID:          cve.ID,
		Origin:      "nvd",
		PublishedAt: parseNVDTime(cve.Published),
		UpdatedAt:   parseNVDTime(cve.LastModified),
	}

	// English description.
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			v.Summary = d.Value
			v.Description = d.Value
			break
		}
	}

	// CVSS: prefer V31 > V30 > V2.
	switch {
	case len(cve.Metrics.CVSSMetricV31) > 0:
		d := cve.Metrics.CVSSMetricV31[0].CVSSData
		v.CVSS = &model.CVSSInfo{Score: d.BaseScore, Vector: d.VectorString, Version: "3.1"}
		v.Severity = d.BaseSeverity
	case len(cve.Metrics.CVSSMetricV30) > 0:
		d := cve.Metrics.CVSSMetricV30[0].CVSSData
		v.CVSS = &model.CVSSInfo{Score: d.BaseScore, Vector: d.VectorString, Version: "3.0"}
		v.Severity = d.BaseSeverity
	case len(cve.Metrics.CVSSMetricV2) > 0:
		d := cve.Metrics.CVSSMetricV2[0].CVSSData
		v.CVSS = &model.CVSSInfo{Score: d.BaseScore, Vector: d.VectorString, Version: "2.0"}
		v.Severity = cvssScoreToSeverity(d.BaseScore)
	}

	// References.
	for _, r := range cve.References {
		if r.URL != "" {
			v.References = append(v.References, model.Reference{Type: "WEB", URL: r.URL})
		}
	}

	// AffectedRanges — flatten all vulnerable cpeMatch entries across all nodes.
	for _, cfg := range cve.Configurations {
		collectCPEMatches(cfg.Nodes, &v.AffectedRanges)
	}

	return v
}

// collectCPEMatches recursively walks config nodes and extracts NVD_CPE ranges.
func collectCPEMatches(nodes []nvdNode, out *[]model.AffectedRange) {
	for _, node := range nodes {
		for _, m := range node.CPEMatch {
			if !m.Vulnerable {
				continue
			}
			introduced := m.VersionStartIncluding
			if introduced == "" {
				introduced = m.VersionStartExcluding
			}
			ar := model.AffectedRange{
				Type:         "NVD_CPE",
				Introduced:   introduced,
				Fixed:        m.VersionEndExcluding,
				LastAffected: m.VersionEndIncluding,
			}
			*out = append(*out, ar)
		}
		collectCPEMatches(node.Children, out)
	}
}

func parseNVDTime(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil {
		return time.Time{}
	}
	return t
}
