package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"holmes/internal/model"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	criticalSev = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	highSev     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	mediumSev   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	lowSev      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33"))
	unknownSev  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	sectionHdr = lipgloss.NewStyle().Bold(true)
	dimText    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	accentText = lipgloss.NewStyle().Foreground(lipgloss.Color("76"))
	sepColor   = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	fixColor   = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	labelColor = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	spinColor  = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
)


// ── printReport (resolve command) ────────────────────────────────────────────

func printReport(report model.CaseReport) {
	printPackageSection(report.Package)
	printVulnSection(report.Vulnerabilities, report.VersionCheck, packagePURLBase(report.Package))
}

func printPackageSection(p *model.PackageData) {
	if p == nil {
		return
	}
	sep()
	fmt.Println(sectionHdr.Render("PACKAGE"))
	sep()
	field("Name", p.Name)
	field("Ecosystem", p.Ecosystem)
	if p.LatestVersion != "" {
		field("Latest", p.LatestVersion)
	}
	if !p.LastReleasedAt.IsZero() {
		field("Last released", formatTimeAgo(p.LastReleasedAt))
	}
	if p.Description != "" {
		field("Description", clip(p.Description, 80))
	}
	if p.RepoURL != "" {
		field("Repo", p.RepoURL)
	}
	if p.Homepage != "" && p.Homepage != p.RepoURL {
		field("Homepage", p.Homepage)
	}
	if len(p.Licenses) > 0 {
		field("Licenses", strings.Join(p.Licenses, ", "))
	}
	if p.Usage != nil {
		if p.Usage.Stars > 0 {
			field("Stars", humanNum(p.Usage.Stars))
		}
		if p.Usage.Downloads > 0 {
			field("Downloads", humanNum(p.Usage.Downloads))
		}
		if p.Usage.Dependents > 0 {
			field("Dependents", humanNum(p.Usage.Dependents))
		}
	}
}

func printVulnSection(vulns []model.Vulnerability, vc *model.VersionAssessment, pkgPURL string) {
	sep()
	if len(vulns) == 0 {
		fmt.Println(sectionHdr.Render("VULNERABILITIES"))
		sep()
		fmt.Println(accentText.Render("  ✓ No vulnerabilities found."))
		return
	}

	if vc != nil && vc.IsValidSemver {
		if !vc.IsVulnerable {
			fmt.Printf("%s\n", sectionHdr.Render(fmt.Sprintf(
				"VULNERABILITIES  (%d known, none affecting v%s)", len(vulns), vc.RequestedVersion)))
			sep()
			return
		}
		fmt.Printf("%s\n", sectionHdr.Render(fmt.Sprintf(
			"VULNERABILITIES  (%d affecting v%s)", len(vc.AffectingVulns), vc.RequestedVersion)))
		sep()
		affectingIDs := map[string]string{}
		for _, av := range vc.AffectingVulns {
			affectingIDs[av.ID] = av.FixedIn
		}
		vulnByID := vulnsByID(vulns)
		affectingVulns := make([]model.Vulnerability, 0, len(vc.AffectingVulns))
		for _, av := range vc.AffectingVulns {
			if v, ok := vulnByID[av.ID]; ok {
				affectingVulns = append(affectingVulns, v)
			}
		}
		sortBySev(affectingVulns)
		fixes := make(map[string]string, len(affectingVulns))
		for _, v := range affectingVulns {
			fix := affectingIDs[v.ID]
			if fix == "" {
				fix = fixForPURLBase(v, pkgPURL)
			}
			fixes[v.ID] = fix
		}
		printVulnTable(affectingVulns, fixes)
		vuln := criticalSev.Render(fmt.Sprintf("  Version %s is VULNERABLE", vc.RequestedVersion))
		if vc.FixAvailable {
			vuln += accentText.Render(fmt.Sprintf("  →  nearest fix: %s", vc.NearestFix))
		}
		fmt.Println(vuln)
	} else {
		fmt.Printf("%s\n", sectionHdr.Render(fmt.Sprintf("VULNERABILITIES  (%d found)", len(vulns))))
		sep()
		sorted := make([]model.Vulnerability, len(vulns))
		copy(sorted, vulns)
		sortBySev(sorted)
		fixes := make(map[string]string, len(sorted))
		for _, v := range sorted {
			fixes[v.ID] = fixForPURLBase(v, pkgPURL)
		}
		printVulnTable(sorted, fixes)
	}
}

func printVulnTable(vulns []model.Vulnerability, fixes map[string]string) {
	if len(vulns) == 0 {
		return
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(sepColor).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return labelColor.Bold(true)
			}
			if col == 1 {
				return sevStyleFor(normSev(vulns[row]))
			}
			if col == 5 || col == 6 {
				return dimText
			}
			if row%2 == 0 {
				return dimText
			}
			return lipgloss.NewStyle()
		}).
		Headers("ID", "SEVERITY", "CVSS", "FIX", "SUMMARY", "PUBLISHED", "ORIGIN")

	for _, v := range vulns {
		sev := normSev(v)
		cvss := ""
		if v.CVSS != nil && v.CVSS.Score > 0 {
			cvss = fmt.Sprintf("%.1f", v.CVSS.Score)
		}
		fix := fixes[v.ID]
		summary := clip(v.Summary, 60)
		published := ""
		if !v.PublishedAt.IsZero() {
			published = formatTimeAgo(v.PublishedAt)
		}
		t.Row(v.ID, sev, cvss, fix, summary, published, v.Origin)
	}

	fmt.Println(t.Render())
}

func sevStyleFor(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return criticalSev
	case "HIGH":
		return highSev
	case "MEDIUM":
		return mediumSev
	case "LOW":
		return lowSev
	default:
		return unknownSev
	}
}

// ── Scan report (styled stdout) ───────────────────────────────────────────────

func printScanReport(sbomPath string, results []scanResult) {
	vulnerable := filterVulnerable(results)
	sortResultsBySev(vulnerable)
	sevCount := countSeverities(vulnerable)

	fmt.Println(sectionHdr.Render("SBOM Security Scan Report"))
	fmt.Println(sepColor.Render(strings.Repeat("═", 50)))
	fmt.Printf("  %s %s\n", labelColor.Render("SBOM:      "), sbomPath)
	fmt.Printf("  %s %s\n", labelColor.Render("Scanned:   "), fmt.Sprintf("%d packages", len(results)))
	fmt.Printf("  %s %s\n", labelColor.Render("Vulnerable:"), fmt.Sprintf("%d packages", len(vulnerable)))
	if len(vulnerable) > 0 {
		total := sevCount["CRITICAL"] + sevCount["HIGH"] + sevCount["MEDIUM"] + sevCount["LOW"]
		fmt.Printf("  %s %s\n", labelColor.Render("Vulns:     "), fmt.Sprintf("%d unique vulnerabilities", total))
		parts := []string{
			criticalSev.Render(fmt.Sprintf("● CRITICAL: %d", sevCount["CRITICAL"])),
			highSev.Render(fmt.Sprintf("● HIGH: %d", sevCount["HIGH"])),
			mediumSev.Render(fmt.Sprintf("● MEDIUM: %d", sevCount["MEDIUM"])),
			lowSev.Render(fmt.Sprintf("● LOW: %d", sevCount["LOW"])),
		}
		fmt.Printf("  %s %s\n", labelColor.Render("Severity:  "), strings.Join(parts, "  "))
	}

	if len(vulnerable) == 0 {
		fmt.Printf("\n%s\n", accentText.Render("✓ No vulnerable packages found."))
		return
	}

	for _, r := range vulnerable {
		fmt.Println()
		printScanResultBlock(r)
	}

	clean := len(results) - len(vulnerable)
	if clean > 0 {
		fmt.Printf("\n%s\n", dimText.Render(fmt.Sprintf("%d packages not affected.", clean)))
	}
}

func printScanResultBlock(r scanResult) {
	label := r.displayName()
	fmt.Println(sepColor.Render(strings.Repeat("─", 50)))
	fmt.Println(sectionHdr.Render(label))

	if p := r.report.Package; p != nil {
		if p.Description != "" {
			fmt.Printf("  %s\n", dimText.Render(clip(p.Description, 90)))
		}
		var meta []string
		if p.LatestVersion != "" {
			meta = append(meta, "Latest: "+p.LatestVersion)
		}
		if !p.LastReleasedAt.IsZero() {
			meta = append(meta, "Released: "+formatTimeAgo(p.LastReleasedAt))
		}
		if !p.LastUpdatedAt.IsZero() {
			meta = append(meta, "Updated: "+formatTimeAgo(p.LastUpdatedAt))
		}
		if len(p.Licenses) > 0 {
			meta = append(meta, "License: "+strings.Join(p.Licenses, ", "))
		}
		if p.Usage != nil && p.Usage.Stars > 0 {
			meta = append(meta, "Stars: "+humanNum(p.Usage.Stars))
		}
		if len(meta) > 0 {
			fmt.Printf("  %s\n", dimText.Render(strings.Join(meta, "  •  ")))
		}
	}

	vc := r.report.VersionCheck
	vulnMap := vulnsByID(r.report.Vulnerabilities)
	pkgPURL := packagePURLBase(r.report.Package)
	avs := sortedAffecting(vc, vulnMap)

	var ordered []model.Vulnerability
	fixes := map[string]string{}
	for _, av := range avs {
		v, ok := vulnMap[av.ID]
		if !ok {
			continue
		}
		fix := av.FixedIn
		if fix == "" {
			fix = fixForPURLBase(v, pkgPURL)
		}
		fixes[v.ID] = fix
		ordered = append(ordered, v)
	}
	printVulnTable(ordered, fixes)
}

// ── Scan report (plain text for --output file) ────────────────────────────────

func writeScanReport(w *strings.Builder, sbomPath string, results []scanResult) {
	vulnerable := filterVulnerable(results)
	sortResultsBySev(vulnerable)
	sevCount := countSeverities(vulnerable)

	w.WriteString("SBOM Security Scan Report\n")
	w.WriteString("=========================\n")
	w.WriteString(fmt.Sprintf("SBOM:       %s\n", sbomPath))
	w.WriteString(fmt.Sprintf("Scanned:    %d packages\n", len(results)))
	w.WriteString(fmt.Sprintf("Vulnerable: %d packages\n", len(vulnerable)))
	if len(vulnerable) > 0 {
		w.WriteString(fmt.Sprintf("Severity:   CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d\n",
			sevCount["CRITICAL"], sevCount["HIGH"], sevCount["MEDIUM"], sevCount["LOW"]))
	}

	if len(vulnerable) == 0 {
		w.WriteString("\nNo vulnerable packages found.\n")
		return
	}

	w.WriteString("\n")
	for _, r := range vulnerable {
		writeScanResultBlock(w, r)
	}

	clean := len(results) - len(vulnerable)
	if clean > 0 {
		w.WriteString(fmt.Sprintf("%d package", clean))
		if clean > 1 {
			w.WriteString("s")
		}
		w.WriteString(" not affected.\n")
	}
}

func writeScanResultBlock(w *strings.Builder, r scanResult) {
	label := r.displayName()
	w.WriteString(strings.Repeat("─", 50) + "\n")
	w.WriteString(label + "\n")

	if p := r.report.Package; p != nil {
		if p.Description != "" {
			w.WriteString(fmt.Sprintf("  %s\n", clip(p.Description, 90)))
		}
		if p.LatestVersion != "" {
			w.WriteString(fmt.Sprintf("  Latest: %s", p.LatestVersion))
		}
		if len(p.Licenses) > 0 {
			w.WriteString(fmt.Sprintf("  License: %s", strings.Join(p.Licenses, ", ")))
		}
		if p.Usage != nil && p.Usage.Stars > 0 {
			w.WriteString(fmt.Sprintf("  Stars: %s", humanNum(p.Usage.Stars)))
		}
		w.WriteString("\n")
	}

	vc := r.report.VersionCheck
	vulnMap := vulnsByID(r.report.Vulnerabilities)
	pkgPURL := packagePURLBase(r.report.Package)
	avs := sortedAffecting(vc, vulnMap)
	for _, av := range avs {
		v, ok := vulnMap[av.ID]
		if !ok {
			w.WriteString(fmt.Sprintf("  %s\n", av.ID))
			continue
		}
		fixedIn := av.FixedIn
		if fixedIn == "" {
			fixedIn = fixForPURLBase(v, pkgPURL)
		}
		sev := normSev(v)
		line := fmt.Sprintf("  %-22s %-9s", v.ID, sev)
		if v.CVSS != nil && v.CVSS.Score > 0 {
			line += fmt.Sprintf(" CVSS:%-4.1f", v.CVSS.Score)
		} else {
			line += "          "
		}
		if fixedIn != "" {
			line += fmt.Sprintf("  Fix: %s", fixedIn)
		}
		w.WriteString(line + "\n")
		if v.Summary != "" {
			w.WriteString(fmt.Sprintf("  %s\n", clip(v.Summary, 100)))
		}
	}
	w.WriteString("\n")
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func sep() {
	fmt.Fprintln(os.Stdout, sepColor.Render(strings.Repeat("─", 50)))
}

func field(label, value string) {
	if value == "" {
		return
	}
	fmt.Printf("  %s %s\n", labelColor.Render(fmt.Sprintf("%-14s", label+":")), value)
}

func normSev(v model.Vulnerability) string {
	if v.Severity != "" {
		s := strings.ToUpper(strings.TrimSpace(v.Severity))
		switch s {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
			return s
		}
	}
	if v.CVSS != nil {
		switch {
		case v.CVSS.Score >= 9.0:
			return "CRITICAL"
		case v.CVSS.Score >= 7.0:
			return "HIGH"
		case v.CVSS.Score >= 4.0:
			return "MEDIUM"
		case v.CVSS.Score > 0:
			return "LOW"
		}
	}
	return "UNKNOWN"
}

func sevRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func sortBySev(vulns []model.Vulnerability) {
	sort.SliceStable(vulns, func(i, j int) bool {
		ri := sevRank(normSev(vulns[i]))
		rj := sevRank(normSev(vulns[j]))
		if ri != rj {
			return ri > rj
		}
		return vulns[i].ID < vulns[j].ID
	})
}

func vulnsByID(vulns []model.Vulnerability) map[string]model.Vulnerability {
	m := make(map[string]model.Vulnerability, len(vulns))
	for _, v := range vulns {
		m[v.ID] = v
	}
	return m
}

func sortedAffecting(vc *model.VersionAssessment, vulnMap map[string]model.Vulnerability) []model.AffectingVuln {
	if vc == nil {
		return nil
	}
	avs := make([]model.AffectingVuln, len(vc.AffectingVulns))
	copy(avs, vc.AffectingVulns)
	sort.SliceStable(avs, func(i, j int) bool {
		vi, oki := vulnMap[avs[i].ID]
		vj, okj := vulnMap[avs[j].ID]
		if !oki || !okj {
			return avs[i].ID < avs[j].ID
		}
		ri := sevRank(normSev(vi))
		rj := sevRank(normSev(vj))
		if ri != rj {
			return ri > rj
		}
		return avs[i].ID < avs[j].ID
	})
	return avs
}

func filterVulnerable(results []scanResult) []scanResult {
	var out []scanResult
	for _, r := range results {
		if r.report.VersionCheck != nil && r.report.VersionCheck.IsVulnerable {
			out = append(out, r)
		}
	}
	return out
}

func sortResultsBySev(results []scanResult) {
	sort.SliceStable(results, func(i, j int) bool {
		si := maxSevRank(results[i])
		sj := maxSevRank(results[j])
		if si != sj {
			return si > sj
		}
		return results[i].name < results[j].name
	})
}

func maxSevRank(r scanResult) int {
	vm := vulnsByID(r.report.Vulnerabilities)
	max := 0
	if r.report.VersionCheck == nil {
		return max
	}
	for _, av := range r.report.VersionCheck.AffectingVulns {
		v, ok := vm[av.ID]
		if !ok {
			continue
		}
		if rk := sevRank(normSev(v)); rk > max {
			max = rk
		}
	}
	return max
}

func countSeverities(results []scanResult) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	seen := map[string]struct{}{} // deduplicate by vuln ID across packages
	for _, r := range results {
		if r.report.VersionCheck == nil {
			continue
		}
		vm := vulnsByID(r.report.Vulnerabilities)
		for _, av := range r.report.VersionCheck.AffectingVulns {
			if _, ok := seen[av.ID]; ok {
				continue
			}
			seen[av.ID] = struct{}{}
			v, ok := vm[av.ID]
			if !ok {
				continue
			}
			sev := normSev(v)
			if _, ok := counts[sev]; ok {
				counts[sev]++
			}
		}
	}
	return counts
}

func fixForPURLBase(v model.Vulnerability, pkgPURL string) string {
	namePart := purlName(pkgPURL)
	for _, r := range v.AffectedRanges {
		if namePart != "" && r.PURL != "" && purlName(r.PURL) != namePart {
			continue
		}
		if f := firstNonEmpty(r.VersionFixed, r.Fixed); f != "" {
			return f
		}
	}
	if len(v.FixedVersions) > 0 {
		return strings.Join(v.FixedVersions, ",")
	}
	return ""
}

func purlName(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(s, "/"); idx >= 0 {
		name := s[idx+1:]
		name = strings.SplitN(name, "@", 2)[0]
		name = strings.SplitN(name, "?", 2)[0]
		name = strings.SplitN(name, "#", 2)[0]
		name = strings.ReplaceAll(name, "%2F", "/")
		name = strings.ReplaceAll(name, "%2f", "/")
		return strings.ToLower(strings.TrimSpace(name))
	}
	return strings.ToLower(strings.TrimSpace(purl))
}

func packagePURLBase(p *model.PackageData) string {
	if p == nil || len(p.PURLs) == 0 {
		return ""
	}
	return p.PURLs[0]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func humanNum(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func formatTimeAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	days := int(d.Hours() / 24)
	switch {
	case days < 1:
		return t.Format("2006-01-02") + " (today)"
	case days < 30:
		return fmt.Sprintf("%s (%dd ago)", t.Format("2006-01-02"), days)
	case days < 365:
		return fmt.Sprintf("%s (%dmo ago)", t.Format("2006-01-02"), days/30)
	default:
		return fmt.Sprintf("%s (%dyr ago)", t.Format("2006-01-02"), days/365)
	}
}
