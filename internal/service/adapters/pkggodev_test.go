package adapters

import "testing"

func TestExtractFirstGoModulePath(t *testing.T) {
	html := `<div class="SearchSnippet-headerContainer"><a href="/github.com/charmbracelet/bubbletea" data-gtmc="search result">bubbletea</a></div>`
	got := extractBestGoModulePath(html, "bubbletea")
	if got != "github.com/charmbracelet/bubbletea" {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestExtractFirstGoModulePathFallbackSpan(t *testing.T) {
	html := `<span class="SearchSnippet-header-path">(charm.land/bubbletea/v2)</span>`
	got := extractBestGoModulePath(html, "bubbletea")
	if got != "charm.land/bubbletea/v2" {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestExtractFirstGoModulePathSymbolPackageFallback(t *testing.T) {
	html := `<a href="/github.com/hamba/statter/v2/reporter/victoriametrics" data-gtmc="symbol search result package">pkg</a>`
	got := extractBestGoModulePath(html, "VictoriaMetrics")
	if got != "github.com/hamba/statter/v2/reporter/victoriametrics" {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestExtractBestGoModulePathPrefersRepoRootForOwnerRepoQuery(t *testing.T) {
	html := `
<a href="/github.com/VictoriaMetrics/VictoriaMetrics/lib/logger" data-gtmc="search result">logger</a>
<a href="/github.com/VictoriaMetrics/VictoriaMetrics" data-gtmc="search result">root</a>
<a href="/github.com/VictoriaMetrics/metrics" data-gtmc="search result">metrics</a>`
	got := extractBestGoModulePath(html, "VictoriaMetrics/VictoriaMetrics")
	if got != "github.com/VictoriaMetrics/VictoriaMetrics" {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestNormalizeGoResolvedPathOwnerRepo(t *testing.T) {
	got := normalizeGoResolvedPath("VictoriaMetrics/VictoriaMetrics", "github.com/VictoriaMetrics/VictoriaMetrics/lib/logger")
	if got != "github.com/VictoriaMetrics/VictoriaMetrics" {
		t.Fatalf("unexpected normalized path: %q", got)
	}
}
