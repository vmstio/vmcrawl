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

-- Index for nodeinfo filtering (used to find non-Mastodon platforms and Mastodon instances)
-- Used by: get_not_masto_domains(), menu options 4, 5, 10, 53, api.py health endpoint
CREATE INDEX IF NOT EXISTS idx_raw_domains_nodeinfo
    ON raw_domains (nodeinfo) WHERE nodeinfo IS NOT NULL;

-- Index for error reason queries (LIKE 'SSL%', 'DNS%', regex patterns, etc.)
-- Used by: menu options 20-32 (retry errors by type)
-- B-tree indexes support prefix LIKE queries
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason
    ON raw_domains (reason) WHERE reason IS NOT NULL;

-- Index for error count ordering (used in error report queries)
-- Used by: menu options 20-32 ORDER BY errors
CREATE INDEX IF NOT EXISTS idx_raw_domains_errors
    ON raw_domains (errors) WHERE errors IS NOT NULL;

-- Index for uncrawled domain selection (menu option 0)
-- Used by: SELECT domain FROM raw_domains WHERE errors = 0 ORDER BY LENGTH(DOMAIN)
CREATE INDEX IF NOT EXISTS idx_raw_domains_uncrawled
    ON raw_domains ((LENGTH(domain))) WHERE errors = 0;

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
-- patch_versions table indexes
-- =============================================================================

-- n_level is the PRIMARY KEY, so it already has an index
-- branch is used in subqueries for statistics (SELECT branch || '.%' WHERE n_level = X)
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
ANALYZE patch_versions;
ANALYZE eol_versions;
ANALYZE statistics;
ANALYZE error_log;
