-- Performance indexes for vmcrawl database
-- Run this file after creation.sql to add indexes for common query patterns
-- These indexes are optional but significantly improve query performance

-- =============================================================================
-- raw_domains table indexes
-- =============================================================================

-- Index for filtering by terminal status flags (used in crawl mode domain selection)
-- Partial indexes only include rows where the flag is TRUE (smaller, faster)
CREATE INDEX IF NOT EXISTS idx_raw_domains_ignore
    ON raw_domains (domain) WHERE ignore = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_failed
    ON raw_domains (domain) WHERE failed = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_nxdomain
    ON raw_domains (domain) WHERE nxdomain = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_norobots
    ON raw_domains (domain) WHERE norobots = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_noapi
    ON raw_domains (domain) WHERE noapi = TRUE;

CREATE INDEX IF NOT EXISTS idx_raw_domains_alias
    ON raw_domains (domain) WHERE alias = TRUE;

-- Index for nodeinfo filtering (used to find Mastodon instances in raw_domains)
CREATE INDEX IF NOT EXISTS idx_raw_domains_nodeinfo
    ON raw_domains (nodeinfo) WHERE nodeinfo IS NOT NULL;

-- Composite index for dashboard queries: reason + nodeinfo filtering
-- Used by: WHERE reason LIKE 'SSL%' AND nodeinfo = 'mastodon'
-- Also covers: WHERE reason LIKE 'DNS%' AND nodeinfo = 'mastodon', etc.
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason_nodeinfo
    ON raw_domains (reason, nodeinfo) WHERE reason IS NOT NULL;

-- Index for error reason queries (LIKE 'SSL%', 'DNS%', etc.)
-- B-tree indexes support prefix LIKE queries
CREATE INDEX IF NOT EXISTS idx_raw_domains_reason
    ON raw_domains (reason) WHERE reason IS NOT NULL;

-- Index for error count ordering (used in error report queries)
CREATE INDEX IF NOT EXISTS idx_raw_domains_errors
    ON raw_domains (errors) WHERE errors IS NOT NULL;

-- =============================================================================
-- mastodon_domains table indexes
-- =============================================================================

-- Index for active_users_monthly ordering (most common sort in API and fetch)
-- Descending order matches the common ORDER BY active_users_monthly DESC pattern
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_mau_desc
    ON mastodon_domains (active_users_monthly DESC NULLS LAST);

-- Index for software_version grouping and filtering
-- Used by /stats/versions, /stats/branches, and version-based queries
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_version
    ON mastodon_domains (software_version);

-- Composite index for version queries with MAU ordering
-- Covers: WHERE software_version LIKE 'x.x%' ORDER BY active_users_monthly DESC
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_version_mau
    ON mastodon_domains (software_version, active_users_monthly DESC NULLS LAST);

-- Index for timestamp-based queries (Last Crawled panel, time-based reports)
CREATE INDEX IF NOT EXISTS idx_mastodon_domains_timestamp
    ON mastodon_domains (timestamp DESC NULLS LAST);

-- Index for version prefix matching (dashboard LIKE queries)
-- Supports: WHERE software_version LIKE '4.5%', '4.4%', etc.
-- B-tree naturally supports prefix LIKE queries
-- Note: software_version index above already covers this, but including for documentation

-- =============================================================================
-- nightly_versions table indexes
-- =============================================================================

-- Index for date range lookups (used in nightly version resolution)
CREATE INDEX IF NOT EXISTS idx_nightly_versions_dates
    ON nightly_versions (start_date DESC, end_date DESC);

-- Index for version lookups
CREATE INDEX IF NOT EXISTS idx_nightly_versions_version
    ON nightly_versions (version);

-- =============================================================================
-- patch_versions table indexes
-- =============================================================================

-- Index for n_level lookups (frequent in branch statistics)
CREATE INDEX IF NOT EXISTS idx_patch_versions_nlevel
    ON patch_versions (n_level);

-- Index for branch lookups (used in dashboard version matching queries)
-- Supports: SELECT branch || '.%' FROM patch_versions WHERE n_level = X
CREATE INDEX IF NOT EXISTS idx_patch_versions_branch
    ON patch_versions (branch);

-- =============================================================================
-- eol_versions table indexes
-- =============================================================================

-- eol_versions already has PRIMARY KEY on software_version
-- No additional indexes needed - PK provides fast lookups for EXISTS subqueries

-- =============================================================================
-- dni table indexes
-- =============================================================================

-- Index for domain lookups in DNI checks (already has PK, but explicit for clarity)
-- Note: PRIMARY KEY already creates an index, this is redundant but documents intent

-- =============================================================================
-- error_log table indexes
-- =============================================================================

-- Index for timestamp-based log queries
CREATE INDEX IF NOT EXISTS idx_error_log_timestamp
    ON error_log (timestamp DESC);

-- Index for domain-based error lookups
CREATE INDEX IF NOT EXISTS idx_error_log_domain
    ON error_log (domain) WHERE domain IS NOT NULL;

-- =============================================================================
-- statistics table indexes
-- =============================================================================

-- Index for date-based statistics queries (ORDER BY date DESC LIMIT 1)
-- Note: PRIMARY KEY on date already provides B-tree index
-- For DESC ordering, an explicit DESC index can help:
CREATE INDEX IF NOT EXISTS idx_statistics_date_desc
    ON statistics (date DESC);

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
