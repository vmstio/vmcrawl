#!/usr/bin/env python3

"""
FastAPI service for exposing vmcrawl Mastodon instance data.

This API provides read-only access to collected Mastodon instance statistics,
version information, and domain data.
"""

import os
from contextlib import asynccontextmanager

import toml
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader
from psycopg import sql
from psycopg_pool import ConnectionPool

# Load environment variables
_ = load_dotenv()

# Load application metadata
toml_file_path = os.path.join(os.path.dirname(__file__), "pyproject.toml")
try:
    project_info = toml.load(toml_file_path)
    appname: str = project_info["project"]["name"]
    appversion: str = project_info["project"]["version"]
except (FileNotFoundError, toml.TomlDecodeError, KeyError):
    appname = "vmcrawl-api"
    appversion = "0.1.0"

# Database connection
conn_string = (
    f"postgresql://{os.getenv('VMCRAWL_POSTGRES_USER')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PASS')}@"
    f"{os.getenv('VMCRAWL_POSTGRES_HOST', 'localhost')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PORT', '5432')}/"
    f"{os.getenv('VMCRAWL_POSTGRES_DATA')}"
)

# Create connection pool
db_pool = ConnectionPool(
    conn_string,
    min_size=2,
    max_size=10,
    timeout=30,
)


# Lifespan context manager for cleanup
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application lifespan events."""
    yield
    # Cleanup on shutdown
    try:
        db_pool.close()
    except Exception:
        pass


# Initialize FastAPI app
app = FastAPI(
    title=f"{appname} API",
    version=appversion,
    description="API for accessing Mastodon instance statistics and version data",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# =============================================================================
# AUTHENTICATION
# =============================================================================

# API Key Authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(api_key: str | None = Security(api_key_header)):
    """Validate API key from X-API-Key header.

    If VMCRAWL_API_KEY is not set in environment, authentication is disabled.
    """
    valid_key = os.getenv("VMCRAWL_API_KEY")

    # If no key is configured, allow access (authentication disabled)
    if not valid_key:
        return None

    # Key is configured, so require it
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key. Include X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != valid_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key",
        )

    return api_key


# =============================================================================
# HEALTH CHECK
# =============================================================================


@app.get("/", tags=["Health"])
async def root():
    """API root endpoint with basic information."""
    return {
        "name": f"{appname} API",
        "version": appversion,
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify database connectivity."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute("SELECT 1")
            _ = cur.fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")


# =============================================================================
# STATISTICS ENDPOINTS
# =============================================================================


@app.get("/stats/summary", tags=["Statistics"])
async def get_summary_stats(_api_key: str | None = Depends(get_api_key)):
    """Get summary statistics for all known Mastodon instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Total instances
            _ = cur.execute("SELECT COUNT(*) FROM mastodon_domains")
            result = cur.fetchone()
            total_instances = result[0] if result else 0

            # Total MAU
            _ = cur.execute("SELECT SUM(active_users_monthly) FROM mastodon_domains")
            result = cur.fetchone()
            total_mau = result[0] if result and result[0] else 0

            # Unique versions
            _ = cur.execute(
                "SELECT COUNT(DISTINCT software_version) FROM mastodon_domains"
            )
            result = cur.fetchone()
            unique_versions = result[0] if result else 0

            # Latest timestamp
            _ = cur.execute("SELECT MAX(timestamp) FROM mastodon_domains")
            result = cur.fetchone()
            last_updated = result[0] if result else None

        return {
            "total_instances": total_instances,
            "monthly_active_users": total_mau,
            "unique_versions": unique_versions,
            "last_updated": last_updated.isoformat() if last_updated else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/versions", tags=["Statistics"])
async def get_version_stats(_api_key: str | None = Depends(get_api_key)):
    """Get instance count and user count by Mastodon version."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT
                    software_version,
                    COUNT(*) as instance_count,
                    SUM(active_users_monthly) as total_mau
                FROM mastodon_domains
                GROUP BY software_version
                ORDER BY instance_count DESC
            """
            )
            results = cur.fetchall()

        return {
            "versions": [
                {
                    "version": row[0],
                    "instances": row[1],
                    "monthly_active_users": row[2] or 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/branches", tags=["Statistics"])
async def get_branch_stats(_api_key: str | None = Depends(get_api_key)):
    """Get statistics organized by Mastodon release branches."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Main branch
            _ = cur.execute(
                """
                SELECT
                    COUNT(*) as instances,
                    SUM(active_users_monthly) as mau
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%' FROM patch_versions WHERE n_level = -1
                )
            """
            )
            main_result = cur.fetchone()

            # Latest release branch
            _ = cur.execute(
                """
                SELECT
                    COUNT(*) as instances,
                    SUM(active_users_monthly) as mau
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%' FROM patch_versions WHERE n_level = 0
                )
            """
            )
            latest_result = cur.fetchone()

            # Previous release branch
            _ = cur.execute(
                """
                SELECT
                    COUNT(*) as instances,
                    SUM(active_users_monthly) as mau
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%' FROM patch_versions WHERE n_level = 1
                )
            """
            )
            previous_result = cur.fetchone()

            # Deprecated branches
            _ = cur.execute(
                """
                SELECT
                    COUNT(*) as instances,
                    SUM(active_users_monthly) as mau
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM patch_versions
                    WHERE n_level >= 2
                      AND mastodon_domains.software_version LIKE patch_versions.branch || '.%'
                )
            """
            )
            deprecated_result = cur.fetchone()

            # EOL versions
            _ = cur.execute(
                """
                SELECT
                    COUNT(*) as instances,
                    SUM(active_users_monthly) as mau
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM eol_versions
                    WHERE mastodon_domains.software_version LIKE eol_versions.software_version || '%'
                )
            """
            )
            eol_result = cur.fetchone()

        return {
            "main": {
                "instances": main_result[0] if main_result else 0,
                "monthly_active_users": main_result[1] if main_result else 0,
            },
            "latest": {
                "instances": latest_result[0] if latest_result else 0,
                "monthly_active_users": latest_result[1] if latest_result else 0,
            },
            "previous": {
                "instances": previous_result[0] if previous_result else 0,
                "monthly_active_users": previous_result[1] if previous_result else 0,
            },
            "deprecated": {
                "instances": deprecated_result[0] if deprecated_result else 0,
                "monthly_active_users": deprecated_result[1]
                if deprecated_result
                else 0,
            },
            "eol": {
                "instances": eol_result[0] if eol_result else 0,
                "monthly_active_users": eol_result[1] if eol_result else 0,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/patch-adoption", tags=["Statistics"])
async def get_patch_adoption(_api_key: str | None = Depends(get_api_key)):
    """Get patch adoption statistics (percentage of instances and MAU that are patched)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Calculate patched instances percentage
            _ = cur.execute(
                """
                WITH version_cases AS (
                  SELECT software_version
                  FROM patch_versions
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM eol_versions ev
                    WHERE md.software_version LIKE ev.software_version || '.%'
                       OR md.software_version LIKE ev.software_version || '%'
                  )
                ),
                unpatched_or_eol AS (
                  SELECT COUNT(*) AS cnt
                  FROM mastodon_domains md
                  WHERE md.software_version IN (SELECT software_version FROM eol_check)
                     OR md.software_version NOT IN (SELECT software_version FROM version_cases)
                ),
                totals AS (
                  SELECT COUNT(DISTINCT domain) AS total_domains
                  FROM mastodon_domains
                )
                SELECT
                  ((t.total_domains - u.cnt) * 100.0 / t.total_domains) AS patched_percent
                FROM totals t
                CROSS JOIN unpatched_or_eol u
            """
            )
            instances_result = cur.fetchone()
            patched_instances_percent = (
                round(instances_result[0], 2) if instances_result else 0
            )

            # Calculate patched MAU percentage
            _ = cur.execute(
                """
                WITH version_cases AS (
                  SELECT software_version
                  FROM patch_versions
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM eol_versions ev
                    WHERE md.software_version LIKE ev.software_version || '.%'
                       OR md.software_version LIKE ev.software_version || '%'
                  )
                ),
                totals AS (
                  SELECT SUM(active_users_monthly) AS total_users
                  FROM mastodon_domains
                ),
                unpatched_or_eol AS (
                  SELECT SUM(active_users_monthly) AS cnt
                  FROM mastodon_domains md
                  WHERE md.software_version IN (SELECT software_version FROM eol_check)
                     OR md.software_version NOT IN (SELECT software_version FROM version_cases)
                )
                SELECT
                  ((t.total_users - u.cnt) * 100.0 / t.total_users) AS patched_users_percent
                FROM totals t
                CROSS JOIN unpatched_or_eol u
            """
            )
            mau_result = cur.fetchone()
            patched_mau_percent = round(mau_result[0], 2) if mau_result else 0

        return {
            "instances_patched_percent": patched_instances_percent,
            "mau_patched_percent": patched_mau_percent,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/crawler-health", tags=["Statistics"])
async def get_crawler_health(_api_key: str | None = Depends(get_api_key)):
    """Get crawler health statistics (error counts by type)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # TCP Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND rd.reason LIKE 'TCP%'
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            tcp_issues = result[0] if result else 0

            # SSL Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND rd.reason LIKE 'SSL%'
                  AND ALIAS IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            ssl_issues = result[0] if result else 0

            # DNS Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND rd.reason LIKE 'DNS%'
                  AND ALIAS IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            dns_issues = result[0] if result else 0

            # 5xx Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND rd.reason ~ '^5[0-9]{2}'
                  AND ALIAS IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            http_5xx_issues = result[0] if result else 0

            # 4xx Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND rd.reason ~ '^4[0-9]{2}'
                  AND ALIAS IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            http_4xx_issues = result[0] if result else 0

            # File Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE rd.nodeinfo = 'mastodon'
                  AND (rd.reason LIKE 'FILE%' or rd.reason LIKE 'TYPE%' or rd.reason LIKE 'JSON%')
                  AND ALIAS IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """
            )
            result = cur.fetchone()
            file_issues = result[0] if result else 0

            # MAU Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE nodeinfo = 'mastodon' AND reason LIKE 'MAU%'
            """
            )
            result = cur.fetchone()
            mau_issues = result[0] if result else 0

        return {
            "tcp_issues": tcp_issues,
            "ssl_issues": ssl_issues,
            "dns_issues": dns_issues,
            "http_5xx_issues": http_5xx_issues,
            "http_4xx_issues": http_4xx_issues,
            "file_issues": file_issues,
            "mau_issues": mau_issues,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/domains", tags=["Statistics"])
async def get_domain_stats(_api_key: str | None = Depends(get_api_key)):
    """Get domain statistics (known, dead, blocked, non-Mastodon)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Known Domains
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
            """
            )
            result = cur.fetchone()
            known_domains = result[0] if result else 0

            # Dead Domains
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE (bad_dns IS NOT NULL OR bad_ssl IS NOT NULL
                       OR bad_tcp IS NOT NULL OR bad_type IS NOT NULL
                       OR bad_file IS NOT NULL OR bad_api IS NOT NULL
                       OR bad_json IS NOT NULL OR bad_http2xx IS NOT NULL
                       OR bad_http3xx IS NOT NULL OR bad_http4xx IS NOT NULL
                       OR bad_http5xx IS NOT NULL
                       OR bad_hard IS NOT NULL OR bad_robot IS NOT NULL)
            """
            )
            result = cur.fetchone()
            dead_domains = result[0] if result else 0

            # Blocked Domains
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE (baddata IS NOT NULL)
            """
            )
            result = cur.fetchone()
            blocked_domains = result[0] if result else 0

            # Non-Mastodon Instances
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE "nodeinfo"::TEXT NOT ILIKE '%mastodon%'
            """
            )
            result = cur.fetchone()
            non_mastodon_instances = result[0] if result else 0

        return {
            "known_domains": known_domains,
            "dead_domains": dead_domains,
            "blocked_domains": blocked_domains,
            "non_mastodon_instances": non_mastodon_instances,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/raw-versions", tags=["Statistics"])
async def get_raw_versions(_api_key: str | None = Depends(get_api_key)):
    """Get count of unique raw versions (before normalization/cleaning)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT full_version) AS unique_software_versions
                FROM mastodon_domains
            """
            )
            result = cur.fetchone()
            raw_versions = result[0] if result else 0

        return {"raw_versions": raw_versions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/most-deployed", tags=["Statistics"])
async def get_most_deployed(_api_key: str | None = Depends(get_api_key)):
    """Get the most deployed Mastodon version by instance count and by MAU."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Most deployed by instance count
            _ = cur.execute(
                """
                SELECT
                    software_version,
                    COUNT(*) as instance_count,
                    SUM(active_users_monthly) as total_mau
                FROM mastodon_domains
                GROUP BY software_version
                ORDER BY instance_count DESC
                LIMIT 1
            """
            )
            instance_result = cur.fetchone()

            # Most deployed by MAU
            _ = cur.execute(
                """
                SELECT
                    software_version,
                    COUNT(*) as instance_count,
                    SUM(active_users_monthly) as total_mau
                FROM mastodon_domains
                GROUP BY software_version
                ORDER BY total_mau DESC
                LIMIT 1
            """
            )
            mau_result = cur.fetchone()

        return {
            "by_instance_count": {
                "version": instance_result[0] if instance_result else None,
                "instance_count": instance_result[1] if instance_result else 0,
                "total_mau": instance_result[2] if instance_result else 0,
            },
            "by_mau": {
                "version": mau_result[0] if mau_result else None,
                "instance_count": mau_result[1] if mau_result else 0,
                "total_mau": mau_result[2] if mau_result else 0,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# =============================================================================
# INSTANCE ENDPOINTS
# =============================================================================


@app.get("/instances", tags=["Instances"])
async def get_instances(
    _api_key: str | None = Depends(get_api_key),
    limit: int = Query(100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    sort_by: str = Query("mau", description="Sort field: mau, domain, version"),
    order: str = Query("desc", description="Sort order: asc or desc"),
):
    """Get a list of Mastodon instances with pagination."""
    # Validate sort_by
    valid_sort_fields = {
        "mau": "active_users_monthly",
        "domain": "domain",
        "version": "software_version",
    }
    if sort_by not in valid_sort_fields:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by field. Must be one of: {', '.join(valid_sort_fields.keys())}",
        )

    # Validate order
    if order not in ["asc", "desc"]:
        raise HTTPException(status_code=400, detail="Order must be 'asc' or 'desc'")

    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Use the validated order value directly as a SQL keyword
            sort_order_sql = (
                sql.SQL("ASC") if order.lower() == "asc" else sql.SQL("DESC")
            )
            query = sql.SQL(
                """
                SELECT
                    domain,
                    software_version,
                    full_version,
                    active_users_monthly,
                    timestamp
                FROM mastodon_domains
                ORDER BY {sort_field} {sort_order}
                LIMIT %s OFFSET %s
            """
            ).format(
                sort_field=sql.Identifier(valid_sort_fields[sort_by]),
                sort_order=sort_order_sql,
            )
            _ = cur.execute(query, (limit, offset))
            results = cur.fetchall()

            # Get total count for pagination info
            _ = cur.execute("SELECT COUNT(*) FROM mastodon_domains")
            result = cur.fetchone()
            total_count = result[0] if result else 0

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "instances": [
                {
                    "domain": row[0],
                    "version": row[1],
                    "full_version": row[2],
                    "monthly_active_users": row[3],
                    "last_updated": row[4].isoformat() if row[4] else None,
                }
                for row in results
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/instances/{domain}", tags=["Instances"])
async def get_instance(domain: str, _api_key: str | None = Depends(get_api_key)):
    """Get detailed information about a specific Mastodon instance."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT
                    domain,
                    software_version,
                    full_version,
                    active_users_monthly,
                    timestamp
                FROM mastodon_domains
                WHERE domain = %s
            """,
                (domain,),
            )
            result = cur.fetchone()

            if not result:
                raise HTTPException(
                    status_code=404, detail=f"Instance '{domain}' not found"
                )

        return {
            "domain": result[0],
            "version": result[1],
            "full_version": result[2],
            "monthly_active_users": result[3],
            "last_updated": result[4].isoformat() if result[4] else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/instances/version/{version}", tags=["Instances"])
async def get_instances_by_version(
    version: str,
    _api_key: str | None = Depends(get_api_key),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Get all instances running a specific Mastodon version."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Get instances
            _ = cur.execute(
                """
                SELECT
                    domain,
                    software_version,
                    full_version,
                    active_users_monthly,
                    timestamp
                FROM mastodon_domains
                WHERE software_version LIKE %s
                ORDER BY active_users_monthly DESC
                LIMIT %s OFFSET %s
            """,
                (f"{version}%", limit, offset),
            )
            results = cur.fetchall()

            # Get total count
            _ = cur.execute(
                "SELECT COUNT(*) FROM mastodon_domains WHERE software_version LIKE %s",
                (f"{version}%",),
            )
            result = cur.fetchone()
            total_count = result[0] if result else 0

        return {
            "version": version,
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "instances": [
                {
                    "domain": row[0],
                    "version": row[1],
                    "full_version": row[2],
                    "monthly_active_users": row[3],
                    "last_updated": row[4].isoformat() if row[4] else None,
                }
                for row in results
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# =============================================================================
# SEARCH ENDPOINTS
# =============================================================================


@app.get("/search", tags=["Search"])
async def search_instances(
    _api_key: str | None = Depends(get_api_key),
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(50, ge=1, le=500),
):
    """Search for instances by domain name."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT
                    domain,
                    software_version,
                    full_version,
                    active_users_monthly,
                    timestamp
                FROM mastodon_domains
                WHERE domain ILIKE %s
                ORDER BY active_users_monthly DESC
                LIMIT %s
            """,
                (f"%{q}%", limit),
            )
            results = cur.fetchall()

        return {
            "query": q,
            "count": len(results),
            "instances": [
                {
                    "domain": row[0],
                    "version": row[1],
                    "full_version": row[2],
                    "monthly_active_users": row[3],
                    "last_updated": row[4].isoformat() if row[4] else None,
                }
                for row in results
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# =============================================================================
# MAIN
# =============================================================================


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
