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

Given a package name, repository URL, PURL, or CPE, Holmes runs a **detective pipeline** that:

1. Resolves the canonical package identity across ecosystems
2. Fetches rich metadata — licenses, maintainers, download counts, release history
3. Collects vulnerabilities from multiple independent sources (ecosyste.ms, OSV, NVD)
4. Performs semver range analysis to determine if _your specific version_ is affected, and what the nearest fix is

It ships as two binaries:

- **`holmes`** — a CLI for single-package investigation or full SBOM scanning
- **`holmes_server`** — an HTTP server (`POST /resolve`) that backs the CLI

---

## The Detective Pipeline

Holmes is built around a sequential pipeline of **Detectives**. Each detective receives a shared `Clues` struct, adds what it knows, and passes it forward. Failures are recorded per-detective but never abort the pipeline — the investigation continues with whatever evidence is available.

```
Input (name+eco | URL | PURL | CPE)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Clues { RawName, Ecosystem, PURL, CPE, Version, … } │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────┐
│  Name Detective  │  Resolves fuzzy name → canonical name + ecosystem
│                  │  Skipped for URL/PURL/CPE input
│                  │  Sources: npm registry, PyPI, pkg.go.dev
└──────────────────┘
    │  Clues.ResolvedName, Clues.PURLs
    ▼
┌──────────────────────┐
│  Package Detective   │  Fetches metadata: licenses, repo, stars,
│                      │  downloads, version history, maintainers, CPEs
│                      │  Also emits advisory-based vulnerabilities (origin: "ecosystems")
│                      │  Source: ecosyste.ms
└──────────────────────┘
    │  Clues.PackageData, Clues.Vulnerabilities (ecosystems)
    ▼
┌──────────────────┐
│  OSV Detective   │  Queries OSV API by PURL, name+ecosystem, or repo URL
│                  │  Emits vulnerabilities with semver ranges (origin: "osv")
│                  │  Source: OSV API (api.osv.dev)
└──────────────────┘
    │  Clues.Vulnerabilities (+ osv)
    ▼
┌──────────────────┐
│  NVD Detective   │  Queries NVD API by CPE string
│                  │  Uses Clues.CPE (from input or SBOM) and PackageData.CPEs
│                  │  Emits CVEs with version bound ranges (origin: "nvd")
│                  │  Source: NVD CVE API 2.0
└──────────────────┘
    │  Clues.Vulnerabilities (+ nvd)
    ▼
┌─────────────────────┐
│  Version Detective  │  Pure semver logic — no network calls.
│                     │  Checks if requested version falls inside any
│                     │  affected range across all sources; deduplicates
│                     │  by vuln ID and finds the nearest fix version.
└─────────────────────┘
    │  Clues.VersionCheck
    ▼
┌──────────────────────────────────────────────────────────┐
│  CaseReport { Package, Vulnerabilities, VersionCheck }   │
└──────────────────────────────────────────────────────────┘
```

### The Clues struct

`Clues` is the shared evidence bag that flows through every detective. It starts with raw user input and accumulates resolved data at each step:

| Field                                          | Set by            | Purpose                           |
| ---------------------------------------------- | ----------------- | --------------------------------- |
| `RawName`, `Ecosystem`, `PURL`, `RepoURL`      | Input             | What the user provided            |
| `CPE`                                          | Input / SBOM      | CPE 2.3 string for NVD lookup     |
| `Version`                                      | Input / PURL      | Version to assess                 |
| `ResolvedName`, `PURLs`                        | Name Detective    | Canonical identity                |
| `PackageData`                                  | Package Detective | Full metadata (includes CPEs)     |
| `Vulnerabilities`                              | OSV + NVD + Pkg   | Accumulated advisory list         |
| `VersionCheck`                                 | Version Detective | Semver assessment                 |

### Vulnerability sources

Each detective appends to `Clues.Vulnerabilities` independently. The `Origin` field on each vulnerability records its source. The Version Detective deduplicates by ID when the same CVE appears in multiple sources, preferring the entry that provides a fix version.

| Origin          | Detective         | Source                     | What it provides                                                      |
| --------------- | ----------------- | -------------------------- | --------------------------------------------------------------------- |
| `"ecosystems"`  | Package Detective | ecosyste.ms advisories     | Advisory-based vulns embedded in package metadata                     |
| `"osv"`         | OSV Detective     | OSV API (`api.osv.dev`)    | Authoritative semver ranges, CVSS scores, per-package fix versions    |
| `"nvd"`         | NVD Detective     | NVD CVE API 2.0            | CVE records with CPE-based version bounds (requires CPE input)        |

### Version assessment

The Version Detective uses only the `Clues` already gathered — no network. Vulnerability range matching follows this priority:

1. Explicit **unaffected** versions list (fast exit if version is listed as safe)
2. Explicit **affected** versions list
3. **ECOSYSTEM** / **SEMVER** range events (`introduced` / `fixed`)
4. **GIT** range events — uses `version_introduced` / `version_fixed` semver equivalents when available
5. **NVD_CPE** ranges — `versionStartIncluding`, `versionEndExcluding` (exclusive), `versionEndIncluding` (inclusive last affected)

Each matching vulnerability records its `MatchMethod` so you can audit exactly how the assessment was made. When the same CVE ID is found in multiple sources, the best match (preferring one with a known fix version) is kept.

> **Note:** The same CVE can currently appear more than once in the raw vulnerability list when it is independently reported by both OSV and NVD (different `origin` values). The Version Detective already deduplicates by ID when computing the affected set, so the _assessment_ is correct. Deduplication at the display level will be improved in a future release.

---

## NVD Integration

### How it works

The NVD Detective queries the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) using CPE strings. It runs after the OSV Detective so it can also use CPEs discovered from package metadata.

CPE sources (in priority order):
1. `--cpe` flag / `cpe` field in JSON request / `cpe` field in SBOM component
2. CPEs from `PackageData.CPEs` (populated by the Package Detective from ecosyste.ms)

For each CPE, NVD is queried differently depending on the version field:

| CPE version field | NVD parameter        | Behaviour                                       |
| ----------------- | -------------------- | ----------------------------------------------- |
| Specific (`1.2.3`)| `cpeName`            | Returns CVEs matching that exact version        |
| Wildcard (`*`/`-`)| `virtualMatchString` | Returns all CVEs for that vendor/product        |

Results are paginated (up to 2,000 per page) and cached in SQLite for 24 hours by CPE string.

### Rate limiting and retries

NVD enforces rate limits:

| Condition      | Limit                    |
| -------------- | ------------------------ |
| No API key     | 5 requests / 30 seconds  |
| With API key   | 50 requests / 30 seconds |

Holmes automatically retries on HTTP 429, honouring the `Retry-After` response header (default wait: 30 seconds). Up to **10 retries** per request. You will see log lines like:

```
[nvd] rate limited (429) — waiting 30s before retry 1/10
```

### Setting the NVD API key

A free API key increases the rate limit from 5 to 50 requests per 30 seconds. Get one at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

**1. Create a `.env` file** in the project root (already in `.gitignore`):

```bash
NVD_API_KEY="your-api-key-here"
```

**2. Start the server** — it picks up `.env` automatically:

```bash
make server
```

Alternatively, pass the key inline:

```bash
NVD_API_KEY=your-key make server
```

Or export it in your shell session:

```bash
export NVD_API_KEY=your-key
make server
```

The server logs `[nvd]` prefixed lines so you can monitor NVD requests and retries in real time.

---

## Data Sources

| Source                                       | Ecosystems           | Data                                       |
| -------------------------------------------- | -------------------- | ------------------------------------------ |
| [npm registry](https://registry.npmjs.org)   | JavaScript / Node.js | Name resolution                            |
| [PyPI](https://pypi.org)                     | Python               | Name resolution                            |
| [pkg.go.dev](https://pkg.go.dev)             | Go                   | Name resolution                            |
| [ecosyste.ms](https://ecosyste.ms)           | All major            | Package metadata, CPEs, advisories         |
| [OSV API](https://api.osv.dev)               | All major            | Vulnerability data, CVSS, fix versions     |
| [NVD CVE API](https://nvd.nist.gov)          | All (via CPE)        | CVE records, CVSS, CPE-based version bounds|

---

## Installation

**Requirements:** Go 1.24+

```bash
git clone https://github.com/ezequielcamezzana/holmes
cd holmes

# (Optional) set NVD API key for higher rate limits
echo 'NVD_API_KEY="your-key"' > .env

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

# By CPE — queries NVD directly for CVEs affecting this version
holmes resolve --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" --version 2.14.1

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
╭──────────────────────┬──────────┬──────┬────────┬─────────────────────────┬──────────────────────┬────────╮
│ ID                   │ SEVERITY │ CVSS │ FIX    │ SUMMARY                 │ PUBLISHED            │ ORIGIN │
├──────────────────────┼──────────┼──────┼────────┼─────────────────────────┼──────────────────────┼────────┤
│ GHSA-4w2v-q235-vp99  │ HIGH     │ 8.8  │ 0.21.2 │ Server-side request...  │ 2021-01-05 (4yr ago) │ osv    │
╰──────────────────────┴──────────┴──────┴────────┴─────────────────────────┴──────────────────────┴────────╯
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

The scan command:
- Accepts both flat and nested CycloneDX component structures (e.g. SBOMs generated by [syft](https://github.com/anchore/syft))
- Extracts both `purl` and `cpe` fields from each component
- Components with only a `cpe` (no `purl`) are included and resolved via NVD

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

And adds a top-level `vulnerabilities` array with full CVE/advisory data, CVSS ratings, and `affects` references linking back to components by `bom-ref`.

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
│   │   ├── package/    Package metadata + ecosystems advisories
│   │   ├── osv/        OSV vulnerability collection
│   │   ├── nvd/        NVD vulnerability collection (CPE-based)
│   │   └── version/    Semver range analysis
│   ├── model/          Domain types (Clues, CaseReport, Vulnerability, …)
│   ├── resolver/       Wires and runs the detective pipeline
│   ├── service/        HTTP client with SQLite caching
│   │   └── adapters/   npm, PyPI, Go, ecosyste.ms, OSV, NVD adapters
│   └── cache/          SQLite-backed response and domain cache
```

### Self-building knowledge base

Every scan and every resolve query makes Holmes smarter over time. Each package fetched, each vulnerability resolved, and each CPE queried is persisted to the local SQLite database. The next time the same package or CVE is requested, Holmes serves it from cache with zero network calls.

This means:
- **The more you scan, the richer the local database becomes.** Packages seen across multiple SBOMs accumulate metadata, vulnerability records, and CPE mappings without any extra effort.
- **Air-gapped or offline use becomes progressively more viable** — after enough scans the database contains most of your organisation's dependency universe.
- **Subsequent scans of the same SBOM are near-instant** — everything is already cached.

The database is a plain SQLite file (`holmes_cache.db`) sitting next to the server binary. Back it up, copy it between machines, or commit it to a shared volume — it is entirely self-contained.

### Caching

All HTTP responses and resolved domain objects are cached in `holmes_cache.db` (created at runtime). The cache stores transformed domain types, not raw HTTP bodies, so a schema version bump automatically invalidates stale entries. Default TTL is 24 hours.

NVD results are cached separately by CPE string in the `cpe_vuln_queries` table, avoiding redundant NVD API calls for the same CPE across multiple scans.

---

## Makefile

| Target           | Description                                    |
| ---------------- | ---------------------------------------------- |
| `make server`    | Build and start the server on `:8080` (auto-loads `.env`) |
| `make install`   | Build and install `holmes` to `/usr/local/bin` |
| `make build`     | Build `./holmes` locally                       |
| `make uninstall` | Remove `holmes` from `/usr/local/bin`          |
| `make test`      | Run all tests                                  |
| `make clean`     | Remove built binaries                          |
