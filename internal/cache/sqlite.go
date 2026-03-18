package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"

	"holmes/internal/model"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &SQLiteStore{db: db}
	if err := store.init(); err != nil {
		return nil, err
	}
	return store, nil
}

// vulnSchemaVersion must be bumped whenever the serialized Vulnerability model
// changes in a way that makes cached records stale (e.g. fields added/removed).
const vulnSchemaVersion = 4

func (s *SQLiteStore) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS cache (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    created_at      DATETIME NOT NULL,
    ttl_seconds     INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS packages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    purl        TEXT,
    repo_url    TEXT,
    data        TEXT NOT NULL,
    fetched_at  DATETIME NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 604800,
    UNIQUE (name, ecosystem)
);

CREATE TABLE IF NOT EXISTS package_lookups (
    term        TEXT NOT NULL,
    ecosystem   TEXT NOT NULL DEFAULT '',
    package_id  INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    PRIMARY KEY (term, ecosystem)
);

CREATE TABLE IF NOT EXISTS vulns (
    id          TEXT NOT NULL,
    origin      TEXT NOT NULL,
    data        TEXT NOT NULL,
    fetched_at  DATETIME NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 86400,
    PRIMARY KEY (id, origin)
);

CREATE TABLE IF NOT EXISTS package_vuln_queries (
    package_id  INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    vuln_ids    TEXT NOT NULL DEFAULT '[]',
    queried_at  DATETIME NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 86400,
    PRIMARY KEY (package_id)
);

CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	return s.migrateVulns()
}

// migrateVulns clears the vulns and package_vuln_queries tables when
// vulnSchemaVersion has changed, forcing a fresh fetch of vulnerability data.
func (s *SQLiteStore) migrateVulns() error {
	var stored int
	row := s.db.QueryRow(`SELECT value FROM db_meta WHERE key = 'vuln_schema_version'`)
	_ = row.Scan(&stored)
	if stored == vulnSchemaVersion {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM package_vuln_queries; DELETE FROM vulns;`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO db_meta (key, value) VALUES ('vuln_schema_version', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		vulnSchemaVersion,
	)
	return err
}

// ── Generic Store ────────────────────────────────────────────────────────────

func (s *SQLiteStore) Get(ctx context.Context, key string) (*Entry, error) {
	var value string
	var createdAt time.Time
	var ttl int64
	var schema int
	err := s.db.QueryRowContext(ctx,
		`SELECT value, created_at, ttl_seconds, schema_version FROM cache WHERE key = ?`, key).
		Scan(&value, &createdAt, &ttl, &schema)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if createdAt.Add(time.Duration(ttl) * time.Second).Before(time.Now().UTC()) {
		return nil, nil
	}
	return &Entry{Value: []byte(value), CreatedAt: createdAt, TTLSeconds: ttl, SchemaVersion: schema}, nil
}

func (s *SQLiteStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration, schemaVersion int) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cache (key, value, created_at, ttl_seconds, schema_version)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    created_at = excluded.created_at,
    ttl_seconds = excluded.ttl_seconds,
    schema_version = excluded.schema_version
`, key, string(value), time.Now().UTC(), int64(ttl.Seconds()), schemaVersion)
	return err
}

// ── Package domain ───────────────────────────────────────────────────────────

func (s *SQLiteStore) FindPackage(ctx context.Context, term, ecosystem string) (*model.PackageData, error) {
	var data string
	var fetchedAt time.Time
	var ttl int64
	err := s.db.QueryRowContext(ctx, `
SELECT p.data, p.fetched_at, p.ttl_seconds
FROM packages p
JOIN package_lookups l ON l.package_id = p.id
WHERE l.term = ? AND l.ecosystem = ?
`, term, ecosystem).Scan(&data, &fetchedAt, &ttl)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if fetchedAt.Add(time.Duration(ttl) * time.Second).Before(time.Now().UTC()) {
		return nil, nil
	}
	var pd model.PackageData
	if err := json.Unmarshal([]byte(data), &pd); err != nil {
		return nil, err
	}
	return &pd, nil
}

func (s *SQLiteStore) SavePackage(ctx context.Context, pd *model.PackageData, terms []LookupTerm, ttl time.Duration) error {
	data, err := json.Marshal(pd)
	if err != nil {
		return err
	}
	purl := ""
	if len(pd.PURLs) > 0 {
		purl = pd.PURLs[0]
	}
	var id int64
	err = s.db.QueryRowContext(ctx, `
INSERT INTO packages (name, ecosystem, purl, repo_url, data, fetched_at, ttl_seconds)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name, ecosystem) DO UPDATE SET
    purl        = excluded.purl,
    repo_url    = excluded.repo_url,
    data        = excluded.data,
    fetched_at  = excluded.fetched_at,
    ttl_seconds = excluded.ttl_seconds
RETURNING id
`, pd.Name, pd.Ecosystem, purl, pd.RepoURL, string(data), time.Now().UTC(), int64(ttl.Seconds())).Scan(&id)
	if err != nil {
		return err
	}
	for _, t := range terms {
		if t.Term == "" {
			continue
		}
		_, err := s.db.ExecContext(ctx, `
INSERT INTO package_lookups (term, ecosystem, package_id)
VALUES (?, ?, ?)
ON CONFLICT(term, ecosystem) DO UPDATE SET package_id = excluded.package_id
`, t.Term, t.Ecosystem, id)
		if err != nil {
			return err
		}
	}
	return nil
}

// ── Vuln domain ──────────────────────────────────────────────────────────────

func (s *SQLiteStore) GetVuln(ctx context.Context, id string) (*model.Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT data, fetched_at, ttl_seconds
FROM vulns
WHERE id = ?
ORDER BY CASE origin WHEN 'osv' THEN 0 ELSE 1 END
`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		var fetchedAt time.Time
		var ttl int64
		if err := rows.Scan(&data, &fetchedAt, &ttl); err != nil {
			continue
		}
		if fetchedAt.Add(time.Duration(ttl) * time.Second).Before(time.Now().UTC()) {
			continue
		}
		var v model.Vulnerability
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			continue
		}
		return &v, nil
	}
	return nil, nil
}

func (s *SQLiteStore) SaveVulns(ctx context.Context, vulns []model.Vulnerability, ttl time.Duration) error {
	now := time.Now().UTC()
	for _, v := range vulns {
		if v.ID == "" || v.Origin == "" {
			continue
		}
		data, err := json.Marshal(v)
		if err != nil {
			continue
		}
		_, err = s.db.ExecContext(ctx, `
INSERT INTO vulns (id, origin, data, fetched_at, ttl_seconds)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id, origin) DO UPDATE SET
    data        = excluded.data,
    fetched_at  = excluded.fetched_at,
    ttl_seconds = excluded.ttl_seconds
`, v.ID, v.Origin, string(data), now, int64(ttl.Seconds()))
		if err != nil {
			return err
		}
	}
	return nil
}

// ── OSV query tracking ───────────────────────────────────────────────────────

func (s *SQLiteStore) GetVulnQuery(ctx context.Context, packageName, ecosystem string) ([]string, bool, error) {
	var idsJSON string
	var queriedAt time.Time
	var ttl int64
	err := s.db.QueryRowContext(ctx, `
SELECT q.vuln_ids, q.queried_at, q.ttl_seconds
FROM package_vuln_queries q
JOIN packages p ON p.id = q.package_id
WHERE p.name = ? AND p.ecosystem = ?
`, packageName, ecosystem).Scan(&idsJSON, &queriedAt, &ttl)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if queriedAt.Add(time.Duration(ttl) * time.Second).Before(time.Now().UTC()) {
		return nil, false, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
		return nil, false, err
	}
	return ids, true, nil
}

func (s *SQLiteStore) SaveVulnQuery(ctx context.Context, packageName, ecosystem string, vulnIDs []string, ttl time.Duration) error {
	var packageID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM packages WHERE name = ? AND ecosystem = ?`, packageName, ecosystem).Scan(&packageID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	ids := vulnIDs
	if ids == nil {
		ids = []string{}
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO package_vuln_queries (package_id, vuln_ids, queried_at, ttl_seconds)
VALUES (?, ?, ?, ?)
ON CONFLICT(package_id) DO UPDATE SET
    vuln_ids    = excluded.vuln_ids,
    queried_at  = excluded.queried_at,
    ttl_seconds = excluded.ttl_seconds
`, packageID, string(idsJSON), time.Now().UTC(), int64(ttl.Seconds()))
	return err
}
