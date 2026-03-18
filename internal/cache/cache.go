package cache

import (
	"context"
	"time"

	"holmes/internal/model"
)

type Entry struct {
	Value         []byte
	CreatedAt     time.Time
	TTLSeconds    int64
	SchemaVersion int
}

// Store is the generic key-value cache, used for misc HTTP responses
// (npm, PyPI, pkg.go.dev name lookups).
type Store interface {
	Get(ctx context.Context, key string) (*Entry, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration, schemaVersion int) error
}

// LookupTerm maps a search identifier to a package.
// Ecosystem is "" for URL/PURL terms where the ecosystem is not known upfront.
type LookupTerm struct {
	Term      string
	Ecosystem string
}

// DomainStore extends Store with typed caching for packages and vulnerabilities.
type DomainStore interface {
	Store

	// FindPackage looks up a package by any search term (name, URL, PURL).
	// Returns nil, nil when not found or expired.
	FindPackage(ctx context.Context, term, ecosystem string) (*model.PackageData, error)

	// SavePackage persists a package and registers all terms that resolve to it.
	SavePackage(ctx context.Context, pd *model.PackageData, terms []LookupTerm, ttl time.Duration) error

	// GetVuln returns the best cached vuln for id: osv origin preferred,
	// falls back to ecosystems. Returns nil, nil when not found or all expired.
	GetVuln(ctx context.Context, id string) (*model.Vulnerability, error)

	// SaveVulns upserts each vuln keyed by (id, origin).
	SaveVulns(ctx context.Context, vulns []model.Vulnerability, ttl time.Duration) error

	// GetVulnQuery returns the OSV vuln IDs recorded for a package.
	// ok=false means no valid (non-expired) record exists.
	GetVulnQuery(ctx context.Context, packageName, ecosystem string) (ids []string, ok bool, err error)

	// SaveVulnQuery records the OSV query result for a package.
	// vulnIDs may be empty (genuinely no vulns found) — this is still persisted
	// so we don't re-query until the TTL expires.
	SaveVulnQuery(ctx context.Context, packageName, ecosystem string, vulnIDs []string, ttl time.Duration) error
}
