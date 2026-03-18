<p align="center">
  <img src="holmes.png" alt="Holmes" width="220"/>
</p>

<h1 align="center">Holmes</h1>

<p align="center">
  A package intelligence tool that investigates open-source dependencies,<br/>
  surfaces known vulnerabilities, and deduces whether your exact version is at risk.
</p>

---

**Alpha software.** Holmes currently supports three ecosystems: npm (JavaScript/Node.js), PyPI (Python), and Go. Other ecosystems may partially work via OSV data but are not officially supported yet.

At the moment, SBOM processing and enrichment are limited to the CycloneDX format.

---

## What it does

Given a package name, repository URL, or PURL, Holmes runs a **detective pipeline** that:

1. Resolves the canonical package identity across ecosystems
2. Fetches rich metadata — licenses, maintainers, download counts, release history
3. Collects vulnerabilities from multiple independent sources and merges them
4. Performs semver range analysis to determine if _your specific version_ is affected, and what the nearest fix is

It ships as two binaries:

- **`holmes`** — a CLI for single-package investigation or full SBOM scanning
- **`holmes_server`** — an HTTP server (`POST /resolve`) that backs the CLI

---

## The Detective Pipeline

Holmes is built around a sequential pipeline of **Detectives**. Each detective receives a shared `Clues` struct, adds what it knows, and passes it forward. Failures are recorded per-detective but never abort the pipeline — the investigation continues with whatever evidence is available.

```
Input (name+eco | URL | PURL)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Clues { RawName, Ecosystem, PURL, Version, ... }   │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────┐
│  Name Detective  │  Resolves fuzzy name → canonical name + ecosystem
│                  │  Sources: npm registry, PyPI, pkg.go.dev
└──────────────────┘
    │  Clues.ResolvedName, Clues.PURLs
    ▼
┌──────────────────────┐
│  Package Detective   │  Fetches metadata: licenses, repo, stars,
│                      │  downloads, version history, maintainers
│                      │  Source: ecosyste.ms
└──────────────────────┘
    │  Clues.PackageData
    ▼
┌──────────────────┐
│  Vuln Detective  │  Collects advisories from two independent sources,
│                  │  deduplicates and merges by advisory ID
│                  │  Sources: OSV API, ecosyste.ms advisories
└──────────────────┘
    │  Clues.Vulnerabilities
    ▼
┌─────────────────────┐
│  Version Detective  │  Pure semver logic — no network calls.
│                     │  Checks if requested version falls inside any
│                     │  affected range; finds the nearest fix version.
└─────────────────────┘
    │  Clues.VersionCheck
    ▼
┌──────────────────────────────────────────────────────────┐
│  CaseReport { Package, Vulnerabilities, VersionCheck }   │
└──────────────────────────────────────────────────────────┘
```

### The Clues struct

`Clues` is the shared evidence bag that flows through every detective. It starts with raw user input and accumulates resolved data at each step:

| Field                                     | Set by            | Purpose                |
| ----------------------------------------- | ----------------- | ---------------------- |
| `RawName`, `Ecosystem`, `PURL`, `RepoURL` | Input             | What the user provided |
| `ResolvedName`, `PURLs`                   | Name Detective    | Canonical identity     |
| `PackageData`                             | Package Detective | Full metadata          |
| `Vulnerabilities`                         | Vuln Detective    | Merged advisory list   |
| `VersionCheck`                            | Version Detective | Semver assessment      |

### Vulnerability sources

The Vuln Detective queries two independent sources and merges results by advisory ID. Each vulnerability records its `origin`: `"osv"`, `"ecosystems"`, or `"both"`.

| Source                                 | What it provides                                                                                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **[OSV](https://osv.dev)**             | Authoritative vulnerability database. Queried by PURL, name+ecosystem, or git repo URL. Provides semver ranges, CVSS scores, fix versions per package. |
| **[ecosyste.ms](https://ecosyste.ms)** | Package registry aggregator. Advisories are embedded in the package metadata response.                                                                 |

### Version assessment

The Version Detective uses only the `Clues` already gathered — no network. Vulnerability range matching follows this priority:

1. Explicit **unaffected** versions list (fast exit if version is listed as safe)
2. Explicit **affected** versions list
3. **ECOSYSTEM** semver range events (`introduced` / `fixed`)
4. **GIT** range events — uses `version_introduced` / `version_fixed` semver equivalents when available; pure commit-hash ranges are skipped to avoid false positives

Each matching vulnerability records its `MatchMethod` so you can audit exactly how the assessment was made.

---

## Data Sources

| Source                                     | Ecosystems           | Data                                   |
| ------------------------------------------ | -------------------- | -------------------------------------- |
| [npm registry](https://registry.npmjs.org) | JavaScript / Node.js | Name resolution                        |
| [PyPI](https://pypi.org)                   | Python               | Name resolution                        |
| [pkg.go.dev](https://pkg.go.dev)           | Go                   | Name resolution                        |
| [ecosyste.ms](https://ecosyste.ms)         | All major            | Package metadata, advisories           |
| [OSV API](https://api.osv.dev)             | All major            | Vulnerability data, CVSS, fix versions |

---

## Installation

**Requirements:** Go 1.24+

```bash
git clone https://github.com/ezequielcamezzana/holmes
cd holmes

# Start the intelligence server (port 8080)
make server

# In another terminal — install the CLI globally
make install
```

After `make install`, `holmes` is available in any terminal session.

To point the CLI at a non-local server:

```bash
HOLMES_API_BASE=http://your-server:8080 holmes scan sbom.json
```

---

## CLI

### `holmes resolve` — investigate a single package

```bash
# By PURL (version triggers vulnerability assessment)
holmes resolve --purl "pkg:npm/axios@0.21.1"

# By name + ecosystem
holmes resolve --name axios --eco npm --version 0.21.1

# By repository URL
holmes resolve --url https://github.com/axios/axios

# Without version (shows all known vulnerabilities, no range check)
holmes resolve --name lodash --eco npm
```

Output includes package metadata, license, usage stats, and a colour-coded vulnerability table:

```
──────────────────────────────────────────────────
PACKAGE
──────────────────────────────────────────────────
  Name:          axios
  Ecosystem:     npm
  Latest:        1.8.0
  Last released: 2024-11-26 (4mo ago)
  Description:   Promise based HTTP client for the browser and node.js
  Repo:          https://github.com/axios/axios
  Licenses:      MIT
  Stars:         107.3K
  Downloads:     53.5M
──────────────────────────────────────────────────
VULNERABILITIES  (2 affecting v0.21.1)
──────────────────────────────────────────────────
╭──────────────────────┬──────────┬──────┬────────┬─────────────────────────┬──────────────────────╮
│ ID                   │ SEVERITY │ CVSS │ FIX    │ SUMMARY                 │ PUBLISHED            │
├──────────────────────┼──────────┼──────┼────────┼─────────────────────────┼──────────────────────┤
│ GHSA-4w2v-q235-vp99  │ HIGH     │ 8.8  │ 0.21.2 │ Server-side request...  │ 2021-01-05 (4yr ago) │
╰──────────────────────┴──────────┴──────┴────────┴─────────────────────────┴──────────────────────╯
  Version 0.21.1 is VULNERABLE  →  nearest fix: 0.21.2
```

### `holmes scan` — scan a CycloneDX SBOM

```bash
# Scan and print report
holmes scan sbom.json

# Save plain-text report to file
holmes scan sbom.json --output report.txt

# Produce an enriched CycloneDX SBOM with vulnerabilities injected
holmes scan sbom.json --enrich enriched.cdx.json
```

The scan command accepts both flat and nested CycloneDX component structures (e.g. SBOMs generated by [syft](https://github.com/anchore/syft)).

Progress is displayed with an animated bar during scanning:

```
████████████████░░░░░░░░  140/208  mongo-driver@v1.11.3
```

Summary output:

```
SBOM Security Scan Report
══════════════════════════════════════════════════
  SBOM:       my-cli-v1.2.3.json
  Scanned:    208 packages
  Vulnerable: 12 packages
  Vulns:      18 unique vulnerabilities
  Severity:   ● CRITICAL: 2  ● HIGH: 8  ● MEDIUM: 6  ● LOW: 2
```

### SBOM enrichment (`--enrich`)

The enriched CycloneDX output adds to each component:

- `description` — from package registry
- `licenses` — SPDX identifiers
- `externalReferences` — VCS and homepage URLs
- `bom-ref` — stable reference for cross-linking

And adds a top-level `vulnerabilities` array with full OSV data, CVSS ratings, and `affects` references linking back to components by `bom-ref`.

---

## Architecture

```
holmes/
├── cmd/
│   ├── cli/        CLI binary (resolve + scan commands)
│   └── server/     HTTP server — POST /resolve
├── internal/
│   ├── detective/
│   │   ├── name/       Canonical name resolution
│   │   ├── package/    Package metadata
│   │   ├── vuln/       Vulnerability collection + merging
│   │   └── version/    Semver range analysis
│   ├── model/          Domain types (Clues, CaseReport, Vulnerability, …)
│   ├── resolver/       Wires and runs the detective pipeline
│   ├── service/        HTTP client with SQLite caching
│   │   └── adapters/   npm, PyPI, Go, ecosyste.ms, OSV adapters
│   └── cache/          SQLite-backed response cache
```

### Caching

All HTTP responses are cached in a local SQLite file (`holmes_cache.db`, created at runtime). The cache stores transformed domain types, not raw HTTP bodies, so a schema version bump automatically invalidates stale entries. Default TTL is 24 hours.

---

## Makefile

| Target           | Description                                    |
| ---------------- | ---------------------------------------------- |
| `make server`    | Build and start the server on `:8080`          |
| `make install`   | Build and install `holmes` to `/usr/local/bin` |
| `make build`     | Build `./holmes` locally                       |
| `make uninstall` | Remove `holmes` from `/usr/local/bin`          |
| `make test`      | Run all tests                                  |
| `make clean`     | Remove built binaries                          |
