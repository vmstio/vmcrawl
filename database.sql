-- Combined schema + indexes for vmcrawl
-- Generated from creation.sql and indexes.sql

CREATE TABLE IF NOT EXISTS
  error_log (
    event SERIAL PRIMARY KEY,
    timestamp TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      domain TEXT DEFAULT NULL,
      error TEXT DEFAULT NULL
  );

CREATE TABLE IF NOT EXISTS
  mastodon_domains (
    domain TEXT PRIMARY KEY CHECK (domain = LOWER(domain)),
    software_version TEXT DEFAULT NULL,
    active_users_monthly INTEGER DEFAULT NULL,
    timestamp TIMESTAMP DEFAULT NULL,
    full_version TEXT DEFAULT NULL,
    peers BOOLEAN DEFAULT TRUE
  );

CREATE TABLE IF NOT EXISTS
  release_versions (
    branch TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('main', 'release', 'eol')),
    n_level INTEGER PRIMARY KEY CHECK (n_level >= -1),
    latest TEXT NOT NULL
  );

CREATE TABLE IF NOT EXISTS
  raw_domains (
    domain TEXT PRIMARY KEY CHECK (domain = LOWER(domain)),
    errors INTEGER DEFAULT NULL,
    reason TEXT DEFAULT NULL,
    bad_dns BOOLEAN DEFAULT NULL,
    bad_ssl BOOLEAN DEFAULT NULL,
    bad_tcp BOOLEAN DEFAULT NULL,
    bad_type BOOLEAN DEFAULT NULL,
    bad_file BOOLEAN DEFAULT NULL,
    bad_api BOOLEAN DEFAULT NULL,
    bad_json BOOLEAN DEFAULT NULL,
    bad_http2xx BOOLEAN DEFAULT NULL,
    bad_http3xx BOOLEAN DEFAULT NULL,
    bad_http4xx BOOLEAN DEFAULT NULL,
    bad_http5xx BOOLEAN DEFAULT NULL,
    bad_hard BOOLEAN DEFAULT NULL,
    bad_robot BOOLEAN DEFAULT NULL,
    nodeinfo TEXT DEFAULT NULL,
    alias BOOLEAN DEFAULT NULL
  );

CREATE TABLE IF NOT EXISTS statistics (
    date DATE PRIMARY KEY,
    mau INTEGER,
    unique_versions INTEGER,
    main_instances INTEGER,
    latest_instances INTEGER,
    previous_instances INTEGER,
    deprecated_instances INTEGER,
    eol_instances INTEGER,
    main_patched_instances INTEGER,
    latest_patched_instances INTEGER,
    previous_patched_instances INTEGER,
    deprecated_patched_instances INTEGER,
    main_branch_mau INTEGER,
    latest_branch_mau INTEGER,
    previous_branch_mau INTEGER,
    deprecated_branch_mau INTEGER,
    eol_branch_mau INTEGER,
    main_patched_mau INTEGER,
    latest_patched_mau INTEGER,
    previous_patched_mau INTEGER,
    deprecated_patched_mau INTEGER
  );


CREATE TABLE IF NOT EXISTS nightly_versions (
    version VARCHAR(50) PRIMARY KEY,
    start_date DATE,
    end_date DATE
  );

-- Upgrade path for older databases: ensure one row per nightly version
-- before enforcing a primary key on nightly_versions.version.
DELETE FROM nightly_versions nv
USING nightly_versions other
WHERE nv.version = other.version
  AND (
    nv.start_date < other.start_date
    OR (
      nv.start_date = other.start_date
      AND nv.end_date < other.end_date
    )
    OR (
      nv.start_date = other.start_date
      AND nv.end_date = other.end_date
      AND nv.ctid < other.ctid
    )
  );

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'nightly_versions'::regclass
      AND contype = 'p'
  ) THEN
    ALTER TABLE nightly_versions
      ADD CONSTRAINT nightly_versions_pkey PRIMARY KEY (version);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS
  dni (
    domain TEXT PRIMARY KEY,
    comment TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    force TEXT DEFAULT 'soft' CHECK (force IN ('soft', 'hard'))
  );

CREATE TABLE IF NOT EXISTS
  tld_cache (
    tld TEXT PRIMARY KEY,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

CREATE TABLE IF NOT EXISTS
  bad_tld (
    tld TEXT PRIMARY KEY
  );

INSERT INTO
  bad_tld (tld)
VALUES
  ('arpa'),
  ('gov'),
  ('mil'),
  ('su')
ON CONFLICT (tld) DO NOTHING;

INSERT INTO
  release_versions (branch, status, n_level, latest)
VALUES
  ('4.6', 'main', -1, '4.6.0-alpha.4'),
  ('4.5', 'release', 0, '4.5.6'),
  ('4.4', 'release', 1, '4.4.13'),
  ('4.3', 'release', 2, '4.3.19'),
  ('4.2', 'eol', 3, '4.2.29'),
  ('4.1', 'eol', 4, '4.1.22'),
  ('4.0', 'eol', 5, '4.0.15')
ON CONFLICT (n_level) DO UPDATE
SET
  branch = EXCLUDED.branch,
  status = EXCLUDED.status,
  latest = EXCLUDED.latest;

INSERT INTO
  nightly_versions (version, start_date, end_date)
SELECT seed.version, seed.start_date, seed.end_date
FROM (
  VALUES
    ('4.4.0-rc.1', DATE '2025-07-02', DATE '2025-07-02'),
    ('4.4.0-beta.2', DATE '2025-06-18', DATE '2025-07-01'),
    ('4.4.0-beta.1', DATE '2025-06-05', DATE '2025-06-17'),
    ('4.4.0-alpha.5', DATE '2025-05-07', DATE '2025-06-03'),
    ('4.4.0-alpha.4', DATE '2025-03-14', DATE '2025-05-06'),
    ('4.4.0-alpha.3', DATE '2025-02-28', DATE '2025-03-13'),
    ('4.4.0-alpha.2', DATE '2025-01-17', DATE '2025-02-27'),
    ('4.4.0-alpha.1', DATE '2024-10-08', DATE '2025-01-16'),
    ('4.3.0-rc.1', DATE '2024-10-01', DATE '2024-10-07'),
    ('4.3.0-beta.2', DATE '2024-09-18', DATE '2024-09-30'),
    ('4.3.0-beta.1', DATE '2024-08-24', DATE '2024-09-17'),
    ('4.3.0-alpha.5', DATE '2024-07-05', DATE '2024-08-23'),
    ('4.3.0-alpha.4', DATE '2024-05-31', DATE '2024-07-04'),
    ('4.3.0-alpha.3', DATE '2024-02-17', DATE '2024-05-30'),
    ('4.3.0-alpha.2', DATE '2024-02-15', DATE '2024-02-17'),
    ('4.3.0-alpha.1', DATE '2024-01-30', DATE '2024-02-14'),
    ('4.3.0-alpha.0', DATE '2023-09-28', DATE '2024-01-29'),
    ('4.5.0-alpha.1', DATE '2025-07-03', DATE '2029-08-05'),
    ('4.5.0-alpha.2', DATE '2025-08-06', DATE '2025-10-13'),
    ('4.5.0-beta.1', DATE '2025-10-16', DATE '2025-10-21'),
    ('4.5.0-alpha.3', DATE '2025-10-14', DATE '2025-10-15'),
    ('4.5.0-beta.2', DATE '2025-10-22', DATE '2025-10-29'),
    ('4.5.0-rc.1', DATE '2025-10-30', DATE '2025-10-31'),
    ('4.6.0-alpha.1', DATE '2025-11-01', DATE '2026-01-07'),
    ('4.6.0-alpha.2', DATE '2026-01-08', DATE '2026-01-20'),
    ('4.6.0-alpha.3', DATE '2026-01-21', DATE '2099-12-31')
) AS seed(version, start_date, end_date)
WHERE NOT EXISTS (
  SELECT 1
  FROM nightly_versions nv
  WHERE nv.version = seed.version
);
-- Note: 4.2.x and earlier do not have nightly builds


-- ============================================================================
-- Indexes
-- ============================================================================

-- Performance indexes for vmcrawl database
-- Run this file after creation.sql to add indexes for common query patterns
-- These indexes are optional but significantly improve query performance

-- =============================================================================
-- Cleanup: drop indexes for removed columns
-- =============================================================================

DROP INDEX IF EXISTS idx_raw_domains_ignore;
DROP INDEX IF EXISTS idx_raw_domains_failed;
DROP INDEX IF EXISTS idx_raw_domains_nxdomain;
DROP INDEX IF EXISTS idx_raw_domains_norobots;
DROP INDEX IF EXISTS idx_raw_domains_noapi;

-- =============================================================================
-- raw_domains table indexes
-- =============================================================================

-- Partial indexes for bad_* terminal state flags
-- Used by: get_all_bad_domains() bulk query, menu options 60-72, api.py health endpoint
-- Partial indexes only include rows where the flag is TRUE (smaller, faster)
CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_dns
    ON raw_domains (domain) WHERE bad_dns = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_ssl
    ON raw_domains (domain) WHERE bad_ssl = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_tcp
    ON raw_domains (domain) WHERE bad_tcp = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_type
    ON raw_domains (domain) WHERE bad_type = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_file
    ON raw_domains (domain) WHERE bad_file = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_api
    ON raw_domains (domain) WHERE bad_api = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_json
    ON raw_domains (domain) WHERE bad_json = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_http2xx
    ON raw_domains (domain) WHERE bad_http2xx = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_http3xx
    ON raw_domains (domain) WHERE bad_http3xx = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_http4xx
    ON raw_domains (domain) WHERE bad_http4xx = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_http5xx
    ON raw_domains (domain) WHERE bad_http5xx = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_hard
    ON raw_domains (domain) WHERE bad_hard = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_bad_robot
    ON raw_domains (domain) WHERE bad_robot = TRUE;

-- Index for alias domain filtering
-- Used by: alias domain skip logic
CREATE INDEX IF NOT EXISTS idx_raw_domains_alias
    ON raw_domains (domain) WHERE alias = TRUE;

-- Index for non-alias domain scans
-- Used by: most crawler menu queries include (alias IS NULL OR alias = FALSE)
CREATE INDEX IF NOT EXISTS idx_raw_domains_not_alias
    ON raw_domains (domain) WHERE (alias IS NULL OR alias = FALSE);

-- Index for nodeinfo filtering (used to find non-Mastodon platforms and Mastodon instances)
-- Used by: get_not_masto_domains(), menu options 4, 5, 10, 53, api.py health endpoint
CREATE INDEX IF NOT EXISTS idx_raw_domains_nodeinfo
    ON raw_domains (nodeinfo) WHERE nodeinfo IS NOT NULL;

-- Composite index for nodeinfo + domain scans on non-alias rows
-- Used by: option 10/53 style queries with ORDER BY domain
CREATE INDEX IF NOT EXISTS idx_raw_domains_nodeinfo_domain_not_alias
    ON raw_domains (nodeinfo, domain)
    WHERE (alias IS NULL OR alias = FALSE);

-- Index for error reason queries (LIKE 'SSL%', 'DNS%', regex patterns, etc.)
-- Used by: menu options 20-32 (retry errors by type)
-- B-tree indexes support prefix LIKE queries
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason
    ON raw_domains (reason) WHERE reason IS NOT NULL;

-- Composite reason/errors index for non-alias retries
-- Used by: menu options 20-32 (WHERE reason LIKE/regex ... ORDER BY errors)
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason_errors_not_alias
    ON raw_domains (reason text_pattern_ops, errors)
    WHERE reason IS NOT NULL AND (alias IS NULL OR alias = FALSE);

-- Expression index for HTTP class regex filters (^2xx/^3xx/^4xx/^5xx)
-- Used by: menu options 27-30 and health/report style queries
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason_leading_digit_errors_not_alias
    ON raw_domains ((left(reason, 1)), errors)
    WHERE reason IS NOT NULL AND (alias IS NULL OR alias = FALSE);

-- Health/report index for mastodon + reason filters
-- Used by: api.py crawler-health queries (nodeinfo='mastodon' and reason predicates)
CREATE INDEX IF NOT EXISTS idx_raw_domains_mastodon_reason
    ON raw_domains (reason)
    WHERE nodeinfo = 'mastodon' AND reason IS NOT NULL;

-- Index for error count ordering (used in error report queries)
-- Used by: menu options 20-32 ORDER BY errors
CREATE INDEX IF NOT EXISTS idx_raw_domains_errors
    ON raw_domains (errors) WHERE errors IS NOT NULL;

-- Index for uncrawled domain selection (menu option 0)
-- Used by: SELECT domain FROM raw_domains WHERE errors = 0 ORDER BY LENGTH(DOMAIN)
CREATE INDEX IF NOT EXISTS idx_raw_domains_uncrawled
    ON raw_domains ((LENGTH(domain))) WHERE errors = 0 AND (alias IS NULL OR alias = FALSE);

-- =============================================================================
-- mastodon_domains table indexes
-- =============================================================================

-- Index for active_users_monthly ordering (most common sort in API and fetch)
-- Descending order matches the common ORDER BY active_users_monthly DESC pattern
-- Used by: fetch mode domain selection, menu options 50-52, API listing endpoints
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_mau_desc
    ON mastodon_domains (active_users_monthly DESC NULLS LAST);

-- Index for software_version grouping and filtering
-- Used by: API /stats/versions, /stats/branches, branch statistics queries
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_version
    ON mastodon_domains (software_version);

-- Composite index for version queries with MAU ordering
-- Covers: WHERE software_version LIKE 'x.x%' ORDER BY active_users_monthly DESC
-- Used by: menu option 51, API version-specific endpoints
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_version_mau
    ON mastodon_domains (software_version, active_users_monthly DESC NULLS LAST);

-- Pattern index for software_version LIKE 'prefix%' queries
-- Used by: branch/prefix scans in crawler and API endpoints
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_version_pattern
    ON mastodon_domains (software_version text_pattern_ops);

-- Index for timestamp-based cleanup queries
-- Used by: cleanup_old_domains() DELETE WHERE timestamp <= INTERVAL
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_timestamp
    ON mastodon_domains (timestamp DESC NULLS LAST);

-- =============================================================================
-- nightly_versions table indexes
-- =============================================================================

-- Index for date range lookups (used in nightly version resolution)
CREATE INDEX IF NOT EXISTS idx_nightly_versions_dates
    ON nightly_versions (start_date DESC, end_date DESC);

-- Index for version lookups (used in add/update operations)
CREATE INDEX IF NOT EXISTS idx_nightly_versions_version
    ON nightly_versions (version);

-- =============================================================================
-- release_versions table indexes
-- =============================================================================

-- n_level is the PRIMARY KEY, so it already has an index
-- Branch stats subqueries use status + n_level to split release vs EOL buckets,
-- then match mastodon_domains.software_version by branch/latest prefixes.
-- With only a handful of rows, additional indexes provide no benefit

-- =============================================================================
-- error_log table indexes
-- =============================================================================

-- Index for domain-based error lookups
CREATE INDEX IF NOT EXISTS idx_error_log_domain
    ON error_log (domain) WHERE domain IS NOT NULL;

-- Index for timestamp-based log queries
CREATE INDEX IF NOT EXISTS idx_error_log_timestamp
    ON error_log (timestamp DESC);

-- =============================================================================
-- statistics table indexes
-- =============================================================================

-- PRIMARY KEY on date already provides B-tree index
-- No additional indexes needed - table is write-only for historical snapshots

-- =============================================================================
-- Analyze tables after creating indexes
-- =============================================================================

ANALYZE raw_domains;
ANALYZE mastodon_domains;
ANALYZE nightly_versions;
ANALYZE release_versions;
ANALYZE statistics;
ANALYZE error_log;
