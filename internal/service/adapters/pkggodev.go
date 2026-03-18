package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"holmes/internal/service"
)

type GoAdapter struct {
	client *service.CachedClient
}

func NewGoAdapter(client *service.CachedClient) *GoAdapter {
	return &GoAdapter{client: client}
}

var (
	goSearchResultHrefRe        = regexp.MustCompile(`href="/([^"?#]+)"[^>]*data-gtmc="search result"`)
	goSymbolResultPackageHrefRe = regexp.MustCompile(`href="/([^"?#]+)"[^>]*data-gtmc="symbol search result package"`)
	goHeaderPathRe              = regexp.MustCompile(`<span class="SearchSnippet-header-path">\(([^)]+)\)</span>`)
)

func (a *GoAdapter) ResolveName(ctx context.Context, name string) (string, error) {
	body, err := a.client.FetchBytes(ctx, service.Request{
		Key:    fmt.Sprintf("go:%s:pkggo:search", name),
		URL:    "https://pkg.go.dev/search?q=" + url.QueryEscape(name) + "&m=module",
		Method: http.MethodGet,
	})
	if err != nil {
		return "", err
	}
	path := extractBestGoModulePath(string(body), name)
	if path == "" {
		return "", fmt.Errorf("no go module result found")
	}
	path = normalizeGoResolvedPath(name, path)
	return path, nil
}

func extractBestGoModulePath(html, query string) string {
	paths := collectGoModulePaths(html)
	if len(paths) == 0 {
		return ""
	}
	sort.SliceStable(paths, func(i, j int) bool {
		return scoreGoPath(paths[i], query) > scoreGoPath(paths[j], query)
	})
	return paths[0]
}

func collectGoModulePaths(html string) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, m := range goSearchResultHrefRe.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		path := strings.TrimSpace(m[1])
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	for _, m := range goSymbolResultPackageHrefRe.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		path := strings.TrimSpace(m[1])
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	if len(out) > 0 {
		return out
	}
	if m := goHeaderPathRe.FindStringSubmatch(html); len(m) >= 2 {
		path := strings.TrimSpace(m[1])
		if path != "" {
			return []string{path}
		}
	}
	return nil
}

func scoreGoPath(path, query string) int {
	p := strings.ToLower(strings.TrimSpace(path))
	q := strings.ToLower(strings.TrimSpace(query))
	if p == "" || q == "" {
		return 0
	}

	score := 0
	segs := strings.Split(p, "/")
	depth := len(segs)
	score -= depth * 5 // prefer shallower paths

	if p == q || strings.TrimPrefix(p, "github.com/") == q {
		score += 300
	}

	// For queries like owner/repo, strongly prefer exact repo root.
	if strings.Contains(q, "/") && !strings.Contains(q, ".") {
		repo := "github.com/" + q
		if p == repo {
			score += 250
		}
		if strings.HasPrefix(p, repo+"/") {
			score += 120
		}
	}

	base := segs[depth-1]
	if base == q {
		score += 170
	}

	// Prefer exact owner/repo segment match over owner-only matches.
	if depth >= 3 && segs[2] == q {
		score += 220 // repo segment
	}
	if depth >= 2 && segs[1] == q {
		score += 80 // owner segment
	}

	if strings.Contains(p, q) {
		score += 40
	}

	return score
}

func normalizeGoResolvedPath(query, resolved string) string {
	q := strings.TrimSpace(query)
	if !strings.Contains(q, "/") || strings.Contains(q, ".") {
		return resolved
	}
	root := "github.com/" + q
	if strings.EqualFold(resolved, root) || strings.HasPrefix(strings.ToLower(resolved), strings.ToLower(root)+"/") {
		return root
	}
	return resolved
}
