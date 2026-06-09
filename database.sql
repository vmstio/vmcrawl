-- Combined schema + indexes for vmcrawl
-- Generated from creation.sql and indexes.sql

CREATE TABLE IF NOT EXISTS
  error_log (
    event SERIAL PRIMARY KEY,
    timestamp TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      domain TEXT DEFAULT NULL,
      error TEXT DEFAULT NULL,
      worker TEXT DEFAULT NULL
  );

ALTER TABLE error_log ADD COLUMN IF NOT EXISTS worker TEXT DEFAULT NULL;
-- Structured classification alongside the free-text error, mirroring the values
-- written to raw_domains.error_type / error_endpoint so the event log and the
-- scheduling classification line up.
ALTER TABLE error_log ADD COLUMN IF NOT EXISTS error_type TEXT DEFAULT NULL;
ALTER TABLE error_log ADD COLUMN IF NOT EXISTS error_endpoint TEXT DEFAULT NULL;

CREATE TABLE IF NOT EXISTS
  mastodon_domains (
    domain TEXT PRIMARY KEY CHECK (domain = LOWER(domain)),
    software_version TEXT DEFAULT NULL,
    active_users_monthly INTEGER DEFAULT NULL,
    timestamp TIMESTAMP DEFAULT NULL,
    full_version TEXT DEFAULT NULL
  );

-- peers column removed: every qualifying instance is queried every time.
ALTER TABLE mastodon_domains DROP COLUMN IF EXISTS peers;
-- Software variant detected from nodeinfo (e.g. 'mastodon', 'glitch', 'hometown').
-- Only populated for Mastodon-compatible instances; replaces raw_domains.nodeinfo.
ALTER TABLE mastodon_domains
  ADD COLUMN IF NOT EXISTS nodeinfo TEXT DEFAULT NULL;

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
    error_type TEXT DEFAULT NULL,
    error_endpoint TEXT DEFAULT NULL,
    last_response_time DOUBLE PRECISION DEFAULT NULL
  );

-- The errors counter was a batch-era diagnostic (consecutive same-type failures
-- before going terminal). With no terminal state it drives nothing, so drop it;
-- the latest failure classification lives in reason and scheduling is derived
-- from it (see reschedule_domain). Idempotent.
ALTER TABLE raw_domains DROP COLUMN IF EXISTS errors;

-- The bad_* terminal flags were a batch-era throttle: a domain that failed
-- ERROR_BUFFER times was marked terminal and excluded from re-scans. The
-- durable queue makes them obsolete — scheduling is derived entirely from
-- reason (see reschedule_domain), so a failing domain is simply rescheduled on
-- a per-type cadence instead of going terminal. Drop them (idempotent); reason
-- already holds each domain's latest classification, so the queue keeps
-- scheduling every row correctly on next claim.
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_dns;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_ssl;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_tcp;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_type;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_file;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_api;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_json;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_http2xx;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_http3xx;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_http4xx;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_http5xx;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_hard;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS bad_robot;

-- nodeinfo moved to mastodon_domains.nodeinfo; only stored for Mastodon-compatible
-- instances now. Non-Mastodon classification uses error_type='OTHER' instead.
ALTER TABLE raw_domains DROP COLUMN IF EXISTS nodeinfo;

-- alias replaced by error_type='ALIAS'; alias domains now back off on the same
-- 90-day flat cadence as HARD errors via the ALIAS entry in _REASON_BASE_HOURS_CASE.
ALTER TABLE raw_domains DROP COLUMN IF EXISTS alias;

-- reason split into error_type + error_endpoint. Migrate existing data by splitting
-- on '+', then drop the old column. Idempotent: ADD COLUMN IF NOT EXISTS is safe on
-- re-run; the UPDATE is a no-op once reason is gone; DROP COLUMN IF EXISTS is safe.
ALTER TABLE raw_domains ADD COLUMN IF NOT EXISTS error_type TEXT DEFAULT NULL;
ALTER TABLE raw_domains ADD COLUMN IF NOT EXISTS error_endpoint TEXT DEFAULT NULL;
UPDATE raw_domains
SET
    error_type = CASE
        WHEN reason LIKE '%+%' THEN split_part(reason, '+', 1)
        ELSE reason
    END,
    error_endpoint = CASE
        WHEN reason LIKE '%+%' THEN split_part(reason, '+', 2)
        ELSE NULL
    END
WHERE reason IS NOT NULL AND error_type IS NULL;
ALTER TABLE raw_domains DROP COLUMN IF EXISTS reason;

-- Durable crawl queue columns (see docs/durable-queue.md).
-- raw_domains doubles as the work ledger; these columns add queue discipline
-- (due time, lease, backoff) so the crawler can run as a crash-safe,
-- self-scheduling daemon without an external broker. Idempotent upgrade path.
ALTER TABLE raw_domains
  ADD COLUMN IF NOT EXISTS next_crawl_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE raw_domains
  ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE raw_domains
  ADD COLUMN IF NOT EXISTS claimed_by TEXT DEFAULT NULL;
ALTER TABLE raw_domains
  ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
-- Wall-clock seconds of the last crawl; drives claim ordering (fastest first).
ALTER TABLE raw_domains
  ADD COLUMN IF NOT EXISTS last_response_time DOUBLE PRECISION DEFAULT NULL;

-- One-time backfill so the first daemon start does not stampede every row at
-- once. Only touches rows that have not yet been scheduled (next_crawl_at IS
-- NULL); re-running this file after the daemon is live is a no-op. The queue
-- reschedules each row precisely on its next claim; this is just initial jitter.
--   * never crawled (error_type IS NULL) -> due now
--   * has a failure (error_type set)     -> spread over ~30d
--   * everything else (healthy)          -> spread over ~1h
UPDATE raw_domains
SET next_crawl_at = now()
WHERE next_crawl_at IS NULL AND error_type IS NULL;

UPDATE raw_domains
SET next_crawl_at = now() + random() * INTERVAL '30 days'
WHERE next_crawl_at IS NULL AND error_type IS NOT NULL;

UPDATE raw_domains
SET next_crawl_at = now() + random() * INTERVAL '1 hour'
WHERE next_crawl_at IS NULL;

CREATE TABLE IF NOT EXISTS statistics (
    date DATE PRIMARY KEY,
    updated_at TIMESTAMPTZ,
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
    deprecated_patched_mau INTEGER,
    invalid BOOLEAN NOT NULL DEFAULT FALSE,
    invalid_reason TEXT
  );

-- Upgrade path: add invalid flag columns to existing statistics tables.
ALTER TABLE statistics
  ADD COLUMN IF NOT EXISTS invalid BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE statistics
  ADD COLUMN IF NOT EXISTS invalid_reason TEXT;

-- Single-row ledger that elects one queue-daemon worker to run periodic
-- maintenance (stats refresh + stale-domain cleanup) per interval. The id CHECK
-- enforces exactly one row; claim_maintenance_slot() flips last_run_at via a
-- conditional UPDATE so the work runs once per interval regardless of how many
-- workers are running. See docs/durable-queue.md.
CREATE TABLE IF NOT EXISTS maintenance_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    last_run_at TIMESTAMPTZ
);
INSERT INTO maintenance_state (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- Single-row ledger for remote crawl-control signals (pause/resume). The id
-- CHECK enforces exactly one row. get_crawler_control() reads it each daemon
-- loop iteration; set_crawler_control() writes it from the CLI or manage menu.
CREATE TABLE IF NOT EXISTS crawler_control (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    reason TEXT,
    set_by TEXT,
    set_at TIMESTAMPTZ DEFAULT now()
);
INSERT INTO crawler_control (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;


CREATE TABLE IF NOT EXISTS nightly_versions (
    version VARCHAR(50),
    start_date DATE,
    end_date DATE,
    -- TRUE rows pin a dedicated "-security" release (start_date = end_date =
    -- the build date) to a specific version, independent of the regular ranges.
    is_security BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (version, is_security)
  );

-- Upgrade path for older databases: add the is_security column if missing.
ALTER TABLE nightly_versions
  ADD COLUMN IF NOT EXISTS is_security BOOLEAN NOT NULL DEFAULT FALSE;

-- Ensure one row per (version, is_security) before (re)enforcing the key.
DELETE FROM nightly_versions nv
USING nightly_versions other
WHERE nv.version = other.version
  AND nv.is_security = other.is_security
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

-- Migrate the primary key to (version, is_security), replacing the older
-- (version)-only key if present.
DO $$
DECLARE
  pk_cols text;
BEGIN
  SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum))
    INTO pk_cols
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
  WHERE c.conrelid = 'nightly_versions'::regclass
    AND c.contype = 'p';

  IF pk_cols IS DISTINCT FROM 'version,is_security' THEN
    IF pk_cols IS NOT NULL THEN
      ALTER TABLE nightly_versions DROP CONSTRAINT nightly_versions_pkey;
    END IF;
    ALTER TABLE nightly_versions
      ADD CONSTRAINT nightly_versions_pkey PRIMARY KEY (version, is_security);
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

-- The bad_* partial indexes are obsolete (columns dropped above). Drop them
-- idempotently; on a fresh DB they never existed, on an upgrade DROP COLUMN
-- already removed them, so these are harmless no-ops kept for explicitness.
DROP INDEX IF EXISTS idx_raw_domains_bad_dns;
DROP INDEX IF EXISTS idx_raw_domains_bad_ssl;
DROP INDEX IF EXISTS idx_raw_domains_bad_tcp;
DROP INDEX IF EXISTS idx_raw_domains_bad_type;
DROP INDEX IF EXISTS idx_raw_domains_bad_file;
DROP INDEX IF EXISTS idx_raw_domains_bad_api;
DROP INDEX IF EXISTS idx_raw_domains_bad_json;
DROP INDEX IF EXISTS idx_raw_domains_bad_http2xx;
DROP INDEX IF EXISTS idx_raw_domains_bad_http3xx;
DROP INDEX IF EXISTS idx_raw_domains_bad_http4xx;
DROP INDEX IF EXISTS idx_raw_domains_bad_http5xx;
DROP INDEX IF EXISTS idx_raw_domains_bad_hard;
DROP INDEX IF EXISTS idx_raw_domains_bad_robot;

-- Obsolete reason-based indexes (reason column dropped above). Drop idempotently.
DROP INDEX IF EXISTS idx_raw_domains_reason;
DROP INDEX IF EXISTS idx_raw_domains_reason_not_alias;
DROP INDEX IF EXISTS idx_raw_domains_reason_leading_digit_not_alias;
DROP INDEX IF EXISTS idx_raw_domains_reason_leading_digit_errors_not_alias;
DROP INDEX IF EXISTS idx_raw_domains_reason_errors_not_alias;

-- Obsolete alias/nodeinfo column indexes (columns dropped above). Drop idempotently.
DROP INDEX IF EXISTS idx_raw_domains_alias;
DROP INDEX IF EXISTS idx_raw_domains_not_alias;
DROP INDEX IF EXISTS idx_raw_domains_nodeinfo;
DROP INDEX IF EXISTS idx_raw_domains_nodeinfo_domain_not_alias;
DROP INDEX IF EXISTS idx_raw_domains_mastodon_reason;

-- Index supporting error_type-based scans: dead-domain counts (error_type IS NOT NULL)
-- and per-type equality queries (error_type = 'DNS' etc.).
CREATE INDEX IF NOT EXISTS idx_raw_domains_error_type
    ON raw_domains (error_type) WHERE error_type IS NOT NULL;

-- Expression index for HTTP class regex filters (^2xx/^3xx/^4xx/^5xx) on error_type.
CREATE INDEX IF NOT EXISTS idx_raw_domains_error_type_leading_digit
    ON raw_domains ((left(error_type, 1)))
    WHERE error_type IS NOT NULL;

-- The errors column was dropped; its ordering index is obsolete.
DROP INDEX IF EXISTS idx_raw_domains_errors;

-- Index for uncrawled domain selection (menu option 0)
-- Used by: SELECT domain WHERE error_type IS NULL ORDER BY LENGTH(domain)
DROP INDEX IF EXISTS idx_raw_domains_uncrawled;
CREATE INDEX IF NOT EXISTS idx_raw_domains_uncrawled
    ON raw_domains ((LENGTH(domain)))
    WHERE error_type IS NULL;

-- Index for the durable queue claim query (see docs/durable-queue.md)
-- Used by: claim_due_domains() -- ORDER BY last_response_time NULLS FIRST,
-- next_crawl_at NULLS FIRST over due rows (fastest-first priority).
-- Failure domains are deliberately NOT excluded: queue mode recrawls them once
-- due, on a per-type cadence derived from error_type, so it actually re-attempts
-- known failures. The hard-DNI exclusion is applied during the scan (it
-- references another table and can't live in the predicate). Drop first so the
-- leading-column change applies on existing deployments; CREATE ... IF NOT
-- EXISTS alone would keep the stale index.
DROP INDEX IF EXISTS idx_raw_domains_due;
CREATE INDEX IF NOT EXISTS idx_raw_domains_due
    ON raw_domains (last_response_time NULLS FIRST, next_crawl_at NULLS FIRST);

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
