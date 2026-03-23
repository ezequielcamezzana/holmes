package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/progress"

	"holmes/internal/model"
)

type scanResult struct {
	purl      string
	name      string
	version   string
	ecosystem string
	report    model.CaseReport
	err       error
}

func (r scanResult) displayName() string {
	label := r.name
	if r.version != "" {
		label += "@" + r.version
	}
	if r.ecosystem != "" {
		label += " [" + r.ecosystem + "]"
	}
	return label
}

// ── CycloneDX types ──────────────────────────────────────────────────────────

type cdxBOM struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber,omitempty"`
	Version      int               `json:"version,omitempty"`
	Components   []json.RawMessage `json:"components"`
}

// cdxNestedComponent is used solely to detect and recurse into sub-components.
type cdxNestedComponent struct {
	Components []json.RawMessage `json:"components"`
}

type cdxComponentMeta struct {
	BOMRef      string `json:"bom-ref"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	PURL        string `json:"purl"`
	CPE         string `json:"cpe"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

type cdxEnrichedBOM struct {
	BOMFormat       string            `json:"bomFormat"`
	SpecVersion     string            `json:"specVersion"`
	SerialNumber    string            `json:"serialNumber,omitempty"`
	Version         int               `json:"version,omitempty"`
	Components      []json.RawMessage `json:"components"`
	Vulnerabilities []cdxVuln         `json:"vulnerabilities,omitempty"`
}

type cdxVuln struct {
	BOMRef      string       `json:"bom-ref,omitempty"`
	ID          string       `json:"id"`
	Source      cdxSource    `json:"source"`
	Ratings     []cdxRating  `json:"ratings,omitempty"`
	Description string       `json:"description,omitempty"`
	Advisories  []cdxRef     `json:"advisories,omitempty"`
	Affects     []cdxAffects `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Vector   string  `json:"vector,omitempty"`
}

type cdxRef struct {
	URL string `json:"url"`
}

type cdxAffects struct {
	Ref      string       `json:"ref"`
	Versions []cdxVersion `json:"versions,omitempty"`
}

type cdxVersion struct {
	Version string `json:"version,omitempty"`
	Status  string `json:"status,omitempty"`
}

// ── Command ───────────────────────────────────────────────────────────────────

func cmdScan(res Resolver, args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	output := fs.String("output", "", "write text report to file (in addition to stdout)")
	enrich := fs.String("enrich", "", "write enriched CycloneDX SBOM to file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: holmes scan [flags] <sbom.json>\n\nFlags:")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	sbomPath := fs.Arg(0)
	// Go's flag package stops at the first non-flag arg, so flags placed after
	// the sbom path (e.g. scan file.json --enrich out.json) are left unparsed.
	// Re-parse the remaining args so flags work in any order.
	if fs.NArg() > 1 {
		_ = fs.Parse(fs.Args()[1:])
	}

	if sbomPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	components, rawBOM, err := parseSBOM(sbomPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading SBOM: %v\n", err)
		os.Exit(1)
	}
	if len(components) == 0 {
		fmt.Fprintln(os.Stderr, "no components with PURLs or CPEs found in SBOM")
		os.Exit(0)
	}

	ctx := context.Background()
	total := len(components)
	results := make([]scanResult, total)

	const workers = 10
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	bar := newProgressBar(total)
	for i, comp := range components {
		wg.Add(1)
		i, comp := i, comp
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Derive display fields. For PURL components use PURL parsing;
			// for CPE-only components fall back to the component's name/version fields.
			name, eco, ver := parsePURL(comp.PURL)
			if comp.PURL == "" {
				name = comp.meta.Name
				ver = comp.meta.Version
			}

			report, err := res.Resolve(ctx, model.ResolveRequest{
				PURL:    comp.PURL,
				CPE:     comp.CPE,
				Version: ver,
			})

			mu.Lock()
			done++
			label := name
			if ver != "" {
				label += "@" + ver
			}
			bar.update(done, label)
			results[i] = scanResult{
				purl:      comp.PURL,
				name:      name,
				version:   ver,
				ecosystem: eco,
				report:    report,
				err:       err,
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	bar.done()

	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "\nerror resolving %s: %v\n", r.purl, r.err)
			os.Exit(1)
		}
	}

	// Styled report → stdout.
	printScanReport(sbomPath, results)

	// Plain text → file (no ANSI codes).
	if *output != "" {
		var sb strings.Builder
		writeScanReport(&sb, sbomPath, results)
		if err := os.WriteFile(*output, []byte(sb.String()), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "report written to %s\n", *output)
		}
	}

	// Enriched SBOM.
	if *enrich != "" {
		enriched, err := buildEnrichedBOM(rawBOM, components, results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error building enriched SBOM: %v\n", err)
			os.Exit(1)
		}
		data, err := json.MarshalIndent(enriched, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding enriched SBOM: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*enrich, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing enriched SBOM: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "enriched SBOM written to %s\n", *enrich)
	}
}

// ── SBOM parsing ─────────────────────────────────────────────────────────────

type sbomComponent struct {
	PURL string
	CPE  string
	meta cdxComponentMeta
}

// collectComponents recursively walks the CycloneDX component tree and collects
// all components that have a PURL or CPE, deduplicating by PURL (preferred) then CPE.
func collectComponents(raws []json.RawMessage, seen map[string]struct{}, out *[]sbomComponent) {
	for _, raw := range raws {
		var meta cdxComponentMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		p := strings.TrimSpace(meta.PURL)
		c := strings.TrimSpace(meta.CPE)

		switch {
		case p != "":
			// PURL takes priority — deduplicate by PURL.
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				*out = append(*out, sbomComponent{PURL: p, CPE: c, meta: meta})
			}
		case c != "":
			// CPE-only component — deduplicate by CPE.
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				*out = append(*out, sbomComponent{CPE: c, meta: meta})
			}
		}

		// Recurse into nested components (syft-style SBOMs wrap packages this way).
		var nested cdxNestedComponent
		if err := json.Unmarshal(raw, &nested); err == nil && len(nested.Components) > 0 {
			collectComponents(nested.Components, seen, out)
		}
	}
}

func parseSBOM(path string) ([]sbomComponent, *cdxBOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, nil, fmt.Errorf("invalid CycloneDX JSON: %w", err)
	}

	seen := map[string]struct{}{}
	var out []sbomComponent
	collectComponents(bom.Components, seen, &out)
	return out, &bom, nil
}

// ── PURL parsing ─────────────────────────────────────────────────────────────

// parsePURL extracts name, ecosystem, and version from a PURL string.
// Format: pkg:type/[namespace/]name@version[?qualifiers][#subpath]
func parsePURL(purl string) (name, ecosystem, version string) {
	s := strings.TrimPrefix(purl, "pkg:")
	s = strings.SplitN(s, "?", 2)[0]
	s = strings.SplitN(s, "#", 2)[0]
	slashIdx := strings.Index(s, "/")
	if slashIdx < 0 {
		return purl, "", ""
	}
	ecosystem = s[:slashIdx]
	rest := s[slashIdx+1:]
	if atIdx := strings.LastIndex(rest, "@"); atIdx >= 0 {
		version = rest[atIdx+1:]
		rest = rest[:atIdx]
	}
	parts := strings.Split(rest, "/")
	name = parts[len(parts)-1]
	return name, ecosystem, version
}

// ── Enrichment ────────────────────────────────────────────────────────────────

func buildEnrichedBOM(bom *cdxBOM, components []sbomComponent, results []scanResult) (*cdxEnrichedBOM, error) {
	// Build result lookup by PURL.
	byPURL := map[string]scanResult{}
	for _, r := range results {
		byPURL[r.purl] = r
	}

	// Enrich each component in the BOM.
	enrichedComponents := make([]json.RawMessage, 0, len(bom.Components))
	for _, raw := range bom.Components {
		var meta cdxComponentMeta
		_ = json.Unmarshal(raw, &meta)

		r, ok := byPURL[strings.TrimSpace(meta.PURL)]
		if !ok {
			enrichedComponents = append(enrichedComponents, raw)
			continue
		}

		enriched, err := enrichComponent(raw, meta, r)
		if err != nil {
			enrichedComponents = append(enrichedComponents, raw) // fallback: keep original
		} else {
			enrichedComponents = append(enrichedComponents, enriched)
		}
	}

	// Build vulnerability entries for affected components.
	var cdxVulns []cdxVuln
	vulnSeen := map[string]struct{}{}
	for _, r := range results {
		if r.report.VersionCheck == nil || !r.report.VersionCheck.IsVulnerable {
			continue
		}
		bomRef := bomRefForPURL(r.purl)
		vm := vulnsByID(r.report.Vulnerabilities)
		pkgPURL := packagePURLBase(r.report.Package)

		for _, av := range r.report.VersionCheck.AffectingVulns {
			v, ok := vm[av.ID]
			if !ok {
				continue
			}
			// Use composite key: vuln-id + component-ref to allow same vuln affecting multiple components.
			key := v.ID + "|" + bomRef
			if _, seen := vulnSeen[key]; seen {
				continue
			}
			vulnSeen[key] = struct{}{}

			fixedIn := av.FixedIn
			if fixedIn == "" {
				fixedIn = fixForPURLBase(v, pkgPURL)
			}

			cdxv := cdxVuln{
				BOMRef:      "vuln-" + strings.ToLower(v.ID),
				ID:          v.ID,
				Source:      cdxSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
				Description: clip(v.Summary, 200),
				Affects: []cdxAffects{{
					Ref: bomRef,
					Versions: []cdxVersion{{
						Version: r.version,
						Status:  "affected",
					}},
				}},
			}
			if v.CVSS != nil && v.CVSS.Score > 0 {
				rating := cdxRating{
					Score:    v.CVSS.Score,
					Severity: strings.ToLower(normSev(v)),
					Method:   "CVSSv3",
					Vector:   v.CVSS.Vector,
				}
				cdxv.Ratings = []cdxRating{rating}
			}
			if fixedIn != "" {
				// No standard CycloneDX field for fix; add as advisory note.
				_ = fixedIn // included in description
			}
			for _, ref := range v.References {
				if ref.URL != "" {
					cdxv.Advisories = append(cdxv.Advisories, cdxRef{URL: ref.URL})
					if len(cdxv.Advisories) >= 3 {
						break
					}
				}
			}
			cdxVulns = append(cdxVulns, cdxv)
		}
	}

	return &cdxEnrichedBOM{
		BOMFormat:       bom.BOMFormat,
		SpecVersion:     bom.SpecVersion,
		SerialNumber:    bom.SerialNumber,
		Version:         bom.Version,
		Components:      enrichedComponents,
		Vulnerabilities: cdxVulns,
	}, nil
}

// enrichComponent merges package data into an existing component JSON object.
func enrichComponent(raw json.RawMessage, meta cdxComponentMeta, r scanResult) (json.RawMessage, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	// Ensure bom-ref exists.
	if _, ok := m["bom-ref"]; !ok {
		m["bom-ref"] = bomRefForPURL(meta.PURL)
	}

	p := r.report.Package
	if p == nil {
		return json.Marshal(m)
	}

	// Add description if missing.
	if _, ok := m["description"]; !ok && p.Description != "" {
		m["description"] = p.Description
	}

	// Add licenses if missing.
	if _, ok := m["licenses"]; !ok && len(p.Licenses) > 0 {
		licenses := make([]map[string]interface{}, 0, len(p.Licenses))
		for _, lic := range p.Licenses {
			licenses = append(licenses, map[string]interface{}{
				"license": map[string]string{"id": lic},
			})
		}
		m["licenses"] = licenses
	}

	// Add externalReferences if missing.
	if _, ok := m["externalReferences"]; !ok {
		var refs []map[string]string
		if p.RepoURL != "" {
			refs = append(refs, map[string]string{"type": "vcs", "url": p.RepoURL})
		}
		if p.Homepage != "" && p.Homepage != p.RepoURL {
			refs = append(refs, map[string]string{"type": "website", "url": p.Homepage})
		}
		if len(refs) > 0 {
			m["externalReferences"] = refs
		}
	}

	return json.Marshal(m)
}

func bomRefForPURL(purl string) string {
	// Use PURL as bom-ref, sanitized.
	s := strings.NewReplacer(":", "-", "/", "-", "@", "-", "%", "-").Replace(purl)
	return s
}

// ── Progress bar ─────────────────────────────────────────────────────────────

type progressBar struct {
	prog  progress.Model
	total int
}

func newProgressBar(total int) *progressBar {
	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(36),
		progress.WithoutPercentage(),
	)
	return &progressBar{prog: p, total: total}
}

func (p *progressBar) update(current int, label string) {
	pct := float64(current) / float64(p.total)
	bar := p.prog.ViewAs(pct)
	counter := dimText.Render(fmt.Sprintf("%d/%d", current, p.total))
	fmt.Fprintf(os.Stderr, "\r%s %s  %s", bar, counter, clip(label, 40))
}

func (p *progressBar) done() {
	fmt.Fprintf(os.Stderr, "\r\033[K")
}
