package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"holmes/internal/model"
	"holmes/internal/service"
)

type EcosystemsAdapter struct {
	client *service.CachedClient
}

func NewEcosystemsAdapter(client *service.CachedClient) *EcosystemsAdapter {
	return &EcosystemsAdapter{client: client}
}

type ecosystemsPkgResponse struct {
	Name                     string   `json:"name"`
	Ecosystem                string   `json:"ecosystem"`
	Description              string   `json:"description"`
	RepositoryURL            string   `json:"repository_url"`
	Homepage                 string   `json:"homepage"`
	PURL                     string   `json:"purl"`
	NormalizedLicenses       []string `json:"normalized_licenses"`
	KeywordsArray            []string `json:"keywords_array"`
	LatestReleaseNumber      string   `json:"latest_release_number"`
	FirstReleasePublishedAt  string   `json:"first_release_published_at"`
	LatestReleasePublishedAt string   `json:"latest_release_published_at"`
	UpdatedAt                string   `json:"updated_at"`
	Downloads                int      `json:"downloads"`
	DependentPackagesCount   int      `json:"dependent_packages_count"`
	RepoMetadata             struct {
		StargazersCount int    `json:"stargazers_count"`
		ForksCount      int    `json:"forks_count"`
		Language        string `json:"language"`
	} `json:"repo_metadata"`
	Maintainers []struct {
		Name  string `json:"name"`
		Login string `json:"login"`
		Email string `json:"email"`
		Role  string `json:"role"`
	} `json:"maintainers"`
	Critical   bool `json:"critical"`
	Advisories []struct {
		UUID        string          `json:"uuid"`
		URL         string          `json:"url"`
		Identifiers []string        `json:"identifiers"`
		Title       string          `json:"title"`
		Description string          `json:"description"`
		CVSSScore   float64         `json:"cvss_score"`
		CVSSVector  string          `json:"cvss_vector"`
		Severity    string          `json:"severity"`
		PublishedAt string          `json:"published_at"`
		UpdatedAt   string          `json:"updated_at"`
		References  json.RawMessage `json:"references"`
		Packages    []struct {
			Ecosystem          string   `json:"ecosystem"`
			PackageName        string   `json:"package_name"`
			PURL               string   `json:"purl"`
			AffectedVersions   []string `json:"affected_versions"`
			UnaffectedVersions []string `json:"unaffected_versions"`
			Versions           []struct {
				VulnerableVersionRange string `json:"vulnerable_version_range"`
				FirstPatchedVersion    string `json:"first_patched_version"`
			} `json:"versions"`
		} `json:"packages"`
	} `json:"advisories"`
}

func registryForEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npmjs.org"
	case "python", "pypi":
		return "pypi.org"
	case "go", "golang":
		return "proxy.golang.org"
	default:
		return ""
	}
}

func (a *EcosystemsAdapter) FetchByName(ctx context.Context, ecosystem, name string) (*model.PackageData, []string, []model.Advisory, error) {
	registry := registryForEcosystem(ecosystem)
	if registry == "" {
		return nil, nil, nil, fmt.Errorf("unsupported ecosystem for ecosystems lookup: %s", ecosystem)
	}
	var res ecosystemsPkgResponse
	err := a.client.FetchJSON(ctx, "ecosystems", service.Request{
		URL:    fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s", url.PathEscape(registry), url.PathEscape(name)),
		Method: http.MethodGet,
	}, &res)
	if err != nil {
		return nil, nil, nil, err
	}
	return mapEcosystemPackage(res)
}

func (a *EcosystemsAdapter) LookupByRepo(ctx context.Context, repoURL string) (*model.PackageData, []string, []model.Advisory, error) {
	var list []ecosystemsPkgResponse
	err := a.client.FetchJSON(ctx, "ecosystems", service.Request{
		URL:    "https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url=" + url.QueryEscape(repoURL) + "&sort=name&order=asc",
		Method: http.MethodGet,
	}, &list)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(list) == 0 {
		return nil, nil, nil, fmt.Errorf("no package found for repository URL")
	}
	return mapEcosystemPackage(list[0])
}

func (a *EcosystemsAdapter) LookupByPURL(ctx context.Context, purl string) (*model.PackageData, []string, []model.Advisory, error) {
	var list []ecosystemsPkgResponse
	err := a.client.FetchJSON(ctx, "ecosystems", service.Request{
		URL:    "https://packages.ecosyste.ms/api/v1/packages/lookup?purl=" + url.QueryEscape(purl) + "&sort=name&order=asc",
		Method: http.MethodGet,
	}, &list)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(list) == 0 {
		return nil, nil, nil, fmt.Errorf("no package found for purl")
	}
	return mapEcosystemPackage(list[0])
}

func mapEcosystemPackage(in ecosystemsPkgResponse) (*model.PackageData, []string, []model.Advisory, error) {
	pd := &model.PackageData{
		Name:          in.Name,
		Ecosystem:     strings.ToLower(in.Ecosystem),
		Description:   in.Description,
		RepoURL:       in.RepositoryURL,
		Homepage:      in.Homepage,
		Licenses:      in.NormalizedLicenses,
		Keywords:      in.KeywordsArray,
		LatestVersion: in.LatestReleaseNumber,
		Usage: &model.UsageInfo{
			Stars:      in.RepoMetadata.StargazersCount,
			Forks:      in.RepoMetadata.ForksCount,
			Dependents: in.DependentPackagesCount,
			Downloads:  in.Downloads,
		},
		IsCritical: in.Critical,
	}
	if in.PURL != "" {
		pd.PURLs = []string{in.PURL}
	}
	if in.RepoMetadata.Language != "" {
		pd.Languages = []string{in.RepoMetadata.Language}
	}
	for _, m := range in.Maintainers {
		pd.Maintainers = append(pd.Maintainers, model.Maintainer{Name: m.Name, Login: m.Login, Email: m.Email, Role: m.Role})
	}
	pd.CreatedAt = parseTime(in.FirstReleasePublishedAt)
	pd.LastReleasedAt = parseTime(in.LatestReleasePublishedAt)
	pd.LastUpdatedAt = parseTime(in.UpdatedAt)

	advisories := make([]model.Advisory, 0, len(in.Advisories))
	purls := append([]string{}, pd.PURLs...)
	for _, a := range in.Advisories {
		advPackages := make([]model.AdvisoryPackage, 0, len(a.Packages))
		for _, ap := range a.Packages {
			ranges := make([]model.AdvisoryVersionRange, 0, len(ap.Versions))
			for _, vr := range ap.Versions {
				ranges = append(ranges, model.AdvisoryVersionRange{
					VulnerableRange:     strings.TrimSpace(vr.VulnerableVersionRange),
					FirstPatchedVersion: strings.TrimSpace(vr.FirstPatchedVersion),
				})
			}
			advPackages = append(advPackages, model.AdvisoryPackage{
				Ecosystem:          ap.Ecosystem,
				PackageName:        ap.PackageName,
				PURL:               ap.PURL,
				AffectedVersions:   uniqueStrings(ap.AffectedVersions),
				UnaffectedVersions: uniqueStrings(ap.UnaffectedVersions),
				VersionRanges:      ranges,
			})
			if ap.PURL != "" {
				purls = append(purls, ap.PURL)
			}
		}
		advisories = append(advisories, model.Advisory{
			UUID:        a.UUID,
			URL:         a.URL,
			Identifiers: a.Identifiers,
			Title:       a.Title,
			Description: a.Description,
			CVSSScore:   a.CVSSScore,
			CVSSVector:  a.CVSSVector,
			Severity:    a.Severity,
			References:  parseAdvisoryReferenceURLs(a.References),
			PublishedAt: parseTime(a.PublishedAt),
			UpdatedAt:   parseTime(a.UpdatedAt),
			Packages:    advPackages,
		})
	}
	pd.Advisories = advisories
	return pd, uniqueStrings(purls), advisories, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err == nil {
		return t
	}
	t, err = time.Parse("2006-01-02T15:04:05.000Z", v)
	if err == nil {
		return t
	}
	return time.Time{}
}

func parseAdvisoryReferenceURLs(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	type refObj struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}

	var objs []refObj
	if err := json.Unmarshal(raw, &objs); err == nil {
		refs := make([]string, 0, len(objs))
		for _, r := range objs {
			if r.URL == "" {
				continue
			}
			refs = append(refs, r.URL)
		}
		return refs
	}

	var urls []string
	if err := json.Unmarshal(raw, &urls); err == nil {
		refs := make([]string, 0, len(urls))
		for _, u := range urls {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			refs = append(refs, u)
		}
		return refs
	}

	return nil
}
