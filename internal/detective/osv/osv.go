package osv

import (
	"context"
	"strings"
	"sync"
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
	inv := model.Investigation{Detective: "osv", Status: model.StatusSuccess}

	pkgName, pkgEco := packageIdentifier(clues)

	// Short-circuit: return cached OSV results for this package.
	if d.store != nil && pkgName != "" {
		if ids, ok, _ := d.store.GetVulnQuery(ctx, pkgName, pkgEco); ok {
			for _, id := range ids {
				if v, _ := d.store.GetVuln(ctx, id); v != nil && v.Origin == "osv" {
					clues.Vulnerabilities = append(clues.Vulnerabilities, *v)
				}
			}
			inv.Result = map[string]int{"count": len(ids)}
			return inv, nil
		}
	}

	queries := buildOSVQueries(clues)
	if len(queries) == 0 {
		inv.Status = model.StatusSkipped
		inv.Error = "no identifiers available for osv lookup"
		return inv, nil
	}

	osvVulns, err := d.osv.QueryBatch(ctx, queries)
	if err != nil {
		inv.Status = model.StatusFailed
		inv.Error = err.Error()
		return inv, nil
	}

	// Separate complete records from stubs.
	// OSV batch responses sometimes return id-only stubs with no range or version data.
	// Multiple queries (PURL, name+eco, repo) can return the same vuln — deduplicate by ID.
	seen := map[string]bool{}
	var complete, toFetch []model.Vulnerability
	for _, v := range osvVulns {
		if seen[v.ID] {
			continue
		}
		seen[v.ID] = true
		if v.ID == "" || len(v.AffectedRanges) > 0 || len(v.AffectedVersions) > 0 {
			complete = append(complete, v)
			continue
		}
		// Stub: check domain cache for the previously-fetched full record.
		if d.store != nil {
			if cached, _ := d.store.GetVuln(ctx, v.ID); cached != nil && cached.Origin == "osv" {
				complete = append(complete, *cached)
				continue
			}
		}
		toFetch = append(toFetch, v)
	}

	// Resolve stubs in parallel — each requires an extra API call to /vulns/{id}.
	if len(toFetch) > 0 {
		complete = append(complete, fetchStubs(ctx, d.osv, toFetch)...)
	}

	// Persist results and record the query so future calls can skip the network.
	if d.store != nil {
		if len(complete) > 0 {
			_ = d.store.SaveVulns(ctx, complete, 24*time.Hour)
		}
		if pkgName != "" {
			ids := make([]string, 0, len(complete))
			for _, v := range complete {
				if v.ID != "" {
					ids = append(ids, v.ID)
				}
			}
			// Save even when empty — avoids re-querying a genuinely vuln-free package.
			_ = d.store.SaveVulnQuery(ctx, pkgName, pkgEco, ids, 24*time.Hour)
		}
	}

	clues.Vulnerabilities = append(clues.Vulnerabilities, complete...)
	inv.Result = map[string]int{"count": len(complete)}
	return inv, nil
}

// fetchStubs resolves id-only OSV stubs to full records in parallel.
// Falls back to the stub itself if the fetch fails.
func fetchStubs(ctx context.Context, osv *adapters.OSVAdapter, stubs []model.Vulnerability) []model.Vulnerability {
	out := make([]model.Vulnerability, len(stubs))
	var wg sync.WaitGroup
	for i, stub := range stubs {
		wg.Add(1)
		i, stub := i, stub
		go func() {
			defer wg.Done()
			if full, err := osv.GetVulnByID(ctx, stub.ID); err == nil && full != nil {
				out[i] = *full
			} else {
				out[i] = stub
			}
		}()
	}
	wg.Wait()
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

func buildOSVQueries(clues *model.Clues) []adapters.OSVBatchQuery {
	var queries []adapters.OSVBatchQuery
	for _, p := range uniqueStrings(clues.PURLs) {
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
