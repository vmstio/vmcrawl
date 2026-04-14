#!/usr/bin/env python3

"""
FastAPI service for exposing vmcrawl Mastodon instance data.

This API provides read-only access to collected Mastodon instance statistics,
version information, and domain data.
"""

import getpass
import json
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import paramiko
import toml
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Path,
    Query,
    Response,
    Security,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from psycopg import sql
from psycopg_pool import ConnectionPool

# Mastodon-compatible software names shared with crawler logic.
MASTODON_COMPATIBLE_SOFTWARE = ("mastodon", "hometown", "kmyblue")
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

# Optional SSH tunnel for remote database access
_ssh_transport: paramiko.Transport | None = None
_ssh_tunnel_port: int | None = None
_ssh_host = os.getenv("VMCRAWL_SSH_HOST")

if _ssh_host:
    import sys

    _db_host = os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
    _db_port = int(os.getenv("VMCRAWL_POSTGRES_PORT", "5432"))
    _ssh_port = int(os.getenv("VMCRAWL_SSH_PORT", "22"))
    _ssh_user = os.getenv("VMCRAWL_SSH_USER") or getpass.getuser()
    _ssh_key_path = os.path.expanduser(os.getenv("VMCRAWL_SSH_KEY", "~/.ssh/id_rsa"))
    _ssh_key_pass = os.getenv("VMCRAWL_SSH_KEY_PASS")

    # Load the SSH key once at startup
    _ssh_pkey: paramiko.PKey | None = None
    for _key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            _ssh_pkey = _key_class.from_private_key_file(
                _ssh_key_path, password=_ssh_key_pass
            )
            break
        except (paramiko.SSHException, ValueError):
            continue
    if _ssh_pkey is None:
        print(f"Error establishing SSH tunnel: Unable to load SSH key: {_ssh_key_path}")
        sys.exit(1)

    _ssh_host_str: str = _ssh_host  # narrowed: we're inside `if _ssh_host:`

    def _connect_ssh_transport() -> paramiko.Transport:
        """Open and authenticate a new SSH transport."""
        transport = paramiko.Transport((_ssh_host_str, _ssh_port))
        transport.connect(username=_ssh_user, pkey=_ssh_pkey)
        return transport

    try:
        _ssh_transport = _connect_ssh_transport()

        # Bind a local listening socket for the tunnel (port stays fixed for lifetime)
        _tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tunnel_sock.bind(("127.0.0.1", 0))
        _ssh_tunnel_port = _tunnel_sock.getsockname()[1]
        _tunnel_sock.listen(15)

        def _ssh_tunnel_accept_loop() -> None:
            """Accept local connections and forward them through the SSH tunnel.

            Reconnects automatically if the SSH transport drops.
            """
            global _ssh_transport
            _reconnect_delay = 5  # seconds between reconnect attempts

            while True:
                # Reconnect if the transport has gone away
                if _ssh_transport is None or not _ssh_transport.is_active():
                    print("SSH tunnel lost, attempting to reconnect…")
                    try:
                        _ssh_transport = _connect_ssh_transport()
                        print(
                            f"SSH tunnel reconnected: 127.0.0.1:{_ssh_tunnel_port}"
                            f" -> {_db_host}:{_db_port} via {_ssh_host}"
                        )
                    except Exception as exc:
                        print(
                            f"SSH reconnect failed: {exc}, retrying in {_reconnect_delay}s"
                        )
                        time.sleep(_reconnect_delay)
                        continue

                try:
                    _tunnel_sock.settimeout(1.0)
                    client_sock, _ = _tunnel_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    channel = _ssh_transport.open_channel(
                        "direct-tcpip",
                        (_db_host, _db_port),
                        client_sock.getpeername(),
                    )
                except Exception:
                    client_sock.close()
                    continue

                def _forward(src: Any, dst: Any) -> None:
                    try:
                        while True:
                            data = src.recv(65536)
                            if not data:
                                break
                            dst.sendall(data)
                    except Exception:
                        pass
                    finally:
                        try:
                            src.close()
                        except Exception:
                            pass
                        try:
                            dst.close()
                        except Exception:
                            pass

                threading.Thread(
                    target=_forward, args=(client_sock, channel), daemon=True
                ).start()
                threading.Thread(
                    target=_forward, args=(channel, client_sock), daemon=True
                ).start()

        _tunnel_thread = threading.Thread(target=_ssh_tunnel_accept_loop, daemon=True)
        _tunnel_thread.start()

        print(
            f"SSH tunnel established: 127.0.0.1:{_ssh_tunnel_port}"
            f" -> {_db_host}:{_db_port} via {_ssh_host}"
        )
    except Exception as exception:
        print(f"Error establishing SSH tunnel: {exception}")
        sys.exit(1)

_db_connect_host = (
    "127.0.0.1" if _ssh_tunnel_port else os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
)
_db_connect_port = (
    str(_ssh_tunnel_port)
    if _ssh_tunnel_port
    else os.getenv("VMCRAWL_POSTGRES_PORT", "5432")
)

# Database connection
conn_string = (
    f"postgresql://{os.getenv('VMCRAWL_POSTGRES_USER')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PASS')}@"
    f"{_db_connect_host}:"
    f"{_db_connect_port}/"
    f"{os.getenv('VMCRAWL_POSTGRES_DATA')}"
    f"?sslmode={os.getenv('VMCRAWL_POSTGRES_SSLMODE', 'require')}"
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
    if _ssh_transport is not None:
        try:
            _ssh_transport.close()
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

# CORS middleware for dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
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


@app.get("/api", tags=["Health"])
async def root():
    """API information endpoint."""
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
                    SELECT branch || '.%' FROM release_versions WHERE n_level = -1
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
                    SELECT branch || '.%' FROM release_versions WHERE n_level = 0
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
                    SELECT branch || '.%' FROM release_versions WHERE n_level = 1
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
                    FROM release_versions
                    WHERE status = 'release'
                      AND n_level >= 2
                      AND mastodon_domains.software_version LIKE release_versions.branch || '.%'
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
                    FROM release_versions
                    WHERE status = 'eol'
                      AND mastodon_domains.software_version LIKE release_versions.branch || '.%'
                )
            """
            )
            eol_result = cur.fetchone()

        return {
            "main": {
                "instances": main_result[0] if main_result else 0,
                "monthly_active_users": (main_result[1] or 0) if main_result else 0,
            },
            "latest": {
                "instances": latest_result[0] if latest_result else 0,
                "monthly_active_users": (latest_result[1] or 0) if latest_result else 0,
            },
            "previous": {
                "instances": previous_result[0] if previous_result else 0,
                "monthly_active_users": (previous_result[1] or 0)
                if previous_result
                else 0,
            },
            "deprecated": {
                "instances": deprecated_result[0] if deprecated_result else 0,
                "monthly_active_users": (deprecated_result[1] or 0)
                if deprecated_result
                else 0,
            },
            "eol": {
                "instances": eol_result[0] if eol_result else 0,
                "monthly_active_users": (eol_result[1] or 0) if eol_result else 0,
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
                  SELECT latest AS software_version
                  FROM release_versions
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM release_versions rv
                    WHERE rv.status = 'eol'
                      AND md.software_version LIKE rv.branch || '.%'
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
                  (
                    (t.total_domains - COALESCE(u.cnt, 0)) * 100.0
                    / NULLIF(t.total_domains, 0)
                  ) AS patched_percent
                FROM totals t
                CROSS JOIN unpatched_or_eol u
            """
            )
            instances_result = cur.fetchone()
            patched_instances_percent = (
                round(instances_result[0], 2)
                if instances_result and instances_result[0] is not None
                else 0
            )

            # Calculate patched MAU percentage
            _ = cur.execute(
                """
                WITH version_cases AS (
                  SELECT latest AS software_version
                  FROM release_versions
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM release_versions rv
                    WHERE rv.status = 'eol'
                      AND md.software_version LIKE rv.branch || '.%'
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
                  (
                    (COALESCE(t.total_users, 0) - COALESCE(u.cnt, 0)) * 100.0
                    / NULLIF(COALESCE(t.total_users, 0), 0)
                  ) AS patched_users_percent
                FROM totals t
                CROSS JOIN unpatched_or_eol u
            """
            )
            mau_result = cur.fetchone()
            patched_mau_percent = (
                round(mau_result[0], 2)
                if mau_result and mau_result[0] is not None
                else 0
            )

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
            compatible_software = list(MASTODON_COMPATIBLE_SOFTWARE)

            # TCP Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND rd.reason LIKE 'TCP%%'
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            tcp_issues = result[0] if result else 0

            # SSL Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND rd.reason LIKE 'SSL%%'
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            ssl_issues = result[0] if result else 0

            # DNS Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND rd.reason LIKE 'DNS%%'
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            dns_issues = result[0] if result else 0

            # 5xx Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND rd.reason ~ '^5[0-9]{2}'
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            http_5xx_issues = result[0] if result else 0

            # 4xx Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND rd.reason ~ '^4[0-9]{2}'
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            http_4xx_issues = result[0] if result else 0

            # File Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT rd.domain) AS unique_domain_count
                FROM raw_domains rd
                WHERE LOWER(rd.nodeinfo) = ANY(%s::text[])
                  AND (rd.reason LIKE 'FILE%%' or rd.reason LIKE 'TYPE%%' or rd.reason LIKE 'JSON%%')
                  AND (rd.alias IS NULL OR rd.alias = FALSE)
                  AND EXISTS (
                    SELECT 1
                    FROM mastodon_domains md
                    WHERE md.domain = rd.domain
                  )
            """,
                (compatible_software,),
            )
            result = cur.fetchone()
            file_issues = result[0] if result else 0

            # MAU Issues
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE LOWER(nodeinfo) = ANY(%s::text[])
                  AND reason LIKE 'MAU%%'
                  AND (alias IS NULL OR alias = FALSE)
            """,
                (compatible_software,),
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

            # Non-Mastodon Instances
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain) AS unique_domain_count
                FROM raw_domains
                WHERE nodeinfo IS NOT NULL
                  AND LOWER(nodeinfo) != ALL(%s::text[])
            """,
                (list(MASTODON_COMPATIBLE_SOFTWARE),),
            )
            result = cur.fetchone()
            non_mastodon_instances = result[0] if result else 0

        return {
            "known_domains": known_domains,
            "dead_domains": dead_domains,
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
                ORDER BY total_mau DESC NULLS LAST
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
    order = order.lower()
    if order not in ["asc", "desc"]:
        raise HTTPException(status_code=400, detail="Order must be 'asc' or 'desc'")

    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            # Use the validated order value directly as a SQL keyword
            sort_order_sql = (
                sql.SQL("ASC") if order.lower() == "asc" else sql.SQL("DESC")
            )
            nulls_sql = (
                sql.SQL(" NULLS LAST")
                if valid_sort_fields[sort_by] == "active_users_monthly"
                else sql.SQL("")
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
                ORDER BY {sort_field} {sort_order}{nulls}
                LIMIT %s OFFSET %s
            """
            ).format(
                sort_field=sql.Identifier(valid_sort_fields[sort_by]),
                sort_order=sort_order_sql,
                nulls=nulls_sql,
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


@app.get("/instances/table", tags=["Dashboard"])
async def get_instances_table(
    _api_key: str | None = Depends(get_api_key),
    limit: int = Query(100, ge=1, le=5000, description="Number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    sort_by: str = Query("mau", description="Sort: mau, domain, version"),
    order: str = Query("desc", description="Sort order: asc or desc"),
    q: str = Query("", description="Search query for domain"),
):
    """Get instances table with DNI filtering (for public dashboard)."""
    valid_sort_cols = {
        "mau": ("md", "active_users_monthly"),
        "domain": ("md", "domain"),
        "version": ("md", "software_version"),
        "raw_version": ("md", "full_version"),
        "software": ("rd", "nodeinfo"),
        "last_crawled": ("md", "timestamp"),
    }
    if sort_by not in valid_sort_cols:
        raise HTTPException(status_code=400, detail="Invalid sort_by field")

    order = order.lower()
    if order not in ["asc", "desc"]:
        raise HTTPException(status_code=400, detail="Order must be 'asc' or 'desc'")

    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            sort_table, sort_col = valid_sort_cols[sort_by]
            sort_field_sql = sql.SQL("{}.{}").format(
                sql.Identifier(sort_table),
                sql.Identifier(sort_col),
            )
            sort_order_sql = sql.SQL("ASC") if order == "asc" else sql.SQL("DESC")
            nulls_sql = sql.SQL(" NULLS LAST") if sort_by == "mau" else sql.SQL("")

            where_clause = sql.SQL("")
            params: list[Any] = []
            if q:
                where_clause = sql.SQL(" AND md.domain ILIKE %s")
                params.append(f"%{q}%")

            query = sql.SQL(
                """
                SELECT
                    md.domain,
                    md.software_version,
                    md.full_version,
                    rd.nodeinfo,
                    md.active_users_monthly,
                    md.timestamp
                FROM mastodon_domains md
                LEFT JOIN raw_domains rd ON rd.domain = md.domain
                WHERE NOT EXISTS (
                    SELECT 1 FROM dni WHERE md.domain LIKE '%%' || dni.domain
                )
                {where}
                ORDER BY {sort} {order}{nulls}
                LIMIT %s OFFSET %s
            """
            ).format(
                where=where_clause,
                sort=sort_field_sql,
                order=sort_order_sql,
                nulls=nulls_sql,
            )
            params.extend([limit, offset])
            _ = cur.execute(query, params)
            results = cur.fetchall()

            # Total count with DNI filter
            count_query = sql.SQL(
                """
                SELECT COUNT(*)
                FROM mastodon_domains md
                WHERE NOT EXISTS (
                    SELECT 1 FROM dni WHERE md.domain LIKE '%%' || dni.domain
                )
                {where}
            """
            ).format(where=where_clause)
            count_params = [f"%{q}%"] if q else []
            _ = cur.execute(count_query, count_params)
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
                    "software": row[3],
                    "monthly_active_users": row[4],
                    "last_updated": row[5].isoformat() if row[5] else None,
                }
                for row in results
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/instances/{domain}", tags=["Instances"])
async def get_instance(
    domain: str = Path(..., pattern=r"^[a-zA-Z0-9.-]{1,253}$"),
    _api_key: str | None = Depends(get_api_key),
):
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
    version: str = Path(..., pattern=r"^[a-zA-Z0-9.+-]{1,64}$"),
    _api_key: str | None = Depends(get_api_key),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Get all instances running an exact Mastodon version."""
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
                WHERE software_version = %s
                ORDER BY active_users_monthly DESC
                LIMIT %s OFFSET %s
            """,
                (version, limit, offset),
            )
            results = cur.fetchall()

            # Get total count
            _ = cur.execute(
                "SELECT COUNT(*) FROM mastodon_domains WHERE software_version = %s",
                (version,),
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
# DASHBOARD ENDPOINTS
# =============================================================================


@app.get("/stats/history", tags=["Dashboard"])
async def get_history_stats(
    _api_key: str | None = Depends(get_api_key),
    days: int = Query(30, ge=1, le=365, description="Number of days of history"),
):
    """Get historical statistics from the statistics table."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT
                    date,
                    updated_at,
                    mau,
                    unique_versions,
                    main_instances,
                    latest_instances,
                    previous_instances,
                    deprecated_instances,
                    eol_instances,
                    main_patched_instances,
                    latest_patched_instances,
                    previous_patched_instances,
                    deprecated_patched_instances,
                    main_branch_mau,
                    latest_branch_mau,
                    previous_branch_mau,
                    deprecated_branch_mau,
                    eol_branch_mau,
                    main_patched_mau,
                    latest_patched_mau,
                    previous_patched_mau,
                    deprecated_patched_mau
                FROM statistics
                ORDER BY date DESC
                LIMIT %s
            """,
                (days,),
            )
            results = cur.fetchall()

        return {
            "history": [
                {
                    "date": str(row[0]),
                    "updated_at": row[1].isoformat() if row[1] else None,
                    "mau": row[2] or 0,
                    "unique_versions": row[3] or 0,
                    "main_instances": row[4] or 0,
                    "latest_instances": row[5] or 0,
                    "previous_instances": row[6] or 0,
                    "deprecated_instances": row[7] or 0,
                    "eol_instances": row[8] or 0,
                    "main_patched_instances": row[9] or 0,
                    "latest_patched_instances": row[10] or 0,
                    "previous_patched_instances": row[11] or 0,
                    "deprecated_patched_instances": row[12] or 0,
                    "main_branch_mau": row[13] or 0,
                    "latest_branch_mau": row[14] or 0,
                    "previous_branch_mau": row[15] or 0,
                    "deprecated_branch_mau": row[16] or 0,
                    "eol_branch_mau": row[17] or 0,
                    "main_patched_mau": row[18] or 0,
                    "latest_patched_mau": row[19] or 0,
                    "previous_patched_mau": row[20] or 0,
                    "deprecated_patched_mau": row[21] or 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/patch-detail", tags=["Dashboard"])
async def get_patch_detail(_api_key: str | None = Depends(get_api_key)):
    """Get per-branch patched vs total counts for instances and MAU."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            branches: dict[str, dict[str, Any]] = {}
            for label, n_level in [
                ("main", -1),
                ("latest", 0),
                ("previous", 1),
            ]:
                if label == "main":
                    # Main uses LIKE with '%' suffix for patched
                    _ = cur.execute(
                        """
                        SELECT COUNT(DISTINCT domain)
                        FROM mastodon_domains
                        WHERE software_version LIKE (
                            SELECT latest || '%%' FROM release_versions WHERE n_level = %s
                        )
                    """,
                        (n_level,),
                    )
                else:
                    _ = cur.execute(
                        """
                        SELECT COUNT(DISTINCT domain)
                        FROM mastodon_domains
                        WHERE software_version = (
                            SELECT latest FROM release_versions WHERE n_level = %s
                        )
                    """,
                        (n_level,),
                    )
                result = cur.fetchone()
                patched = result[0] if result else 0

                _ = cur.execute(
                    """
                    SELECT COUNT(DISTINCT domain)
                    FROM mastodon_domains
                    WHERE software_version LIKE (
                        SELECT branch || '.%%' FROM release_versions WHERE n_level = %s
                    )
                """,
                    (n_level,),
                )
                result = cur.fetchone()
                total = result[0] if result else 0

                # MAU patched
                if label == "main":
                    _ = cur.execute(
                        """
                        SELECT COALESCE(SUM(active_users_monthly), 0)
                        FROM mastodon_domains
                        WHERE software_version LIKE ANY (
                            SELECT latest || '%%' FROM release_versions WHERE n_level = %s
                        )
                    """,
                        (n_level,),
                    )
                else:
                    _ = cur.execute(
                        """
                        SELECT COALESCE(SUM(active_users_monthly), 0)
                        FROM mastodon_domains
                        WHERE software_version = (
                            SELECT latest FROM release_versions WHERE n_level = %s
                        )
                    """,
                        (n_level,),
                    )
                result = cur.fetchone()
                mau_patched = result[0] if result else 0

                _ = cur.execute(
                    """
                    SELECT COALESCE(SUM(active_users_monthly), 0)
                    FROM mastodon_domains
                    WHERE software_version LIKE (
                        SELECT branch || '.%%' FROM release_versions WHERE n_level = %s
                    )
                """,
                    (n_level,),
                )
                result = cur.fetchone()
                mau_total = result[0] if result else 0

                _ = cur.execute(
                    "SELECT latest FROM release_versions WHERE n_level = %s",
                    (n_level,),
                )
                version_result = cur.fetchone()
                version = version_result[0] if version_result else None

                branches[label] = {
                    "patched": patched,
                    "total": total,
                    "mau_patched": mau_patched,
                    "mau_total": mau_total,
                    "version": version,
                }

            # Deprecated branches (n_level >= 2, not eol)
            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain)
                FROM mastodon_domains md
                WHERE md.software_version LIKE ANY (
                    SELECT latest || '%%' FROM release_versions
                    WHERE n_level >= 2 AND status != 'eol'
                )
            """
            )
            result = cur.fetchone()
            dep_patched = result[0] if result else 0

            _ = cur.execute(
                """
                SELECT COUNT(DISTINCT domain)
                FROM mastodon_domains
                WHERE software_version LIKE ANY (
                    SELECT branch || '.%%' FROM release_versions
                    WHERE n_level >= 2 AND status != 'eol'
                )
            """
            )
            result = cur.fetchone()
            dep_total = result[0] if result else 0

            _ = cur.execute(
                """
                SELECT COALESCE(SUM(active_users_monthly), 0)
                FROM mastodon_domains md
                WHERE md.software_version LIKE ANY (
                    SELECT latest || '%%' FROM release_versions
                    WHERE n_level >= 2 AND status != 'eol'
                )
            """
            )
            result = cur.fetchone()
            dep_mau_patched = result[0] if result else 0

            _ = cur.execute(
                """
                SELECT COALESCE(SUM(active_users_monthly), 0)
                FROM mastodon_domains
                WHERE software_version LIKE ANY (
                    SELECT branch || '.%%' FROM release_versions
                    WHERE n_level >= 2 AND status != 'eol'
                )
            """
            )
            result = cur.fetchone()
            dep_mau_total = result[0] if result else 0

            _ = cur.execute(
                """
                SELECT latest FROM release_versions
                WHERE n_level >= 2 AND status != 'eol'
                ORDER BY n_level ASC
            """
            )
            dep_ver_rows = cur.fetchall()
            dep_version = ", ".join(r[0] for r in dep_ver_rows) if dep_ver_rows else None

            branches["deprecated"] = {
                "patched": dep_patched,
                "total": dep_total,
                "mau_patched": dep_mau_patched,
                "mau_total": dep_mau_total,
                "version": dep_version,
            }

        return {"branches": branches}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/patch-distribution", tags=["Dashboard"])
async def get_patch_distribution(_api_key: str | None = Depends(get_api_key)):
    """Get patch distribution data for pie charts (by instances and MAU)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH version_cases AS (
                  SELECT latest AS software_version
                  FROM release_versions
                  WHERE status IN ('release', 'main')
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM release_versions rv
                    WHERE rv.status = 'eol'
                      AND md.software_version LIKE rv.branch || '.%'
                  )
                )
                SELECT
                  CASE
                    WHEN software_version IN (SELECT software_version FROM version_cases)
                      THEN software_version
                    WHEN software_version IN (SELECT software_version FROM eol_check)
                      THEN 'EOL'
                    ELSE 'Unpatched'
                  END as version,
                  COUNT(*) as instance_count,
                  COALESCE(SUM(active_users_monthly), 0) as mau_count
                FROM mastodon_domains
                GROUP BY CASE
                    WHEN software_version IN (SELECT software_version FROM version_cases)
                      THEN software_version
                    WHEN software_version IN (SELECT software_version FROM eol_check)
                      THEN 'EOL'
                    ELSE 'Unpatched'
                  END
            """
            )
            results = cur.fetchall()

        return {
            "distribution": [
                {
                    "version": row[0],
                    "instances": row[1],
                    "mau": row[2] or 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/branch-distribution", tags=["Dashboard"])
async def get_branch_distribution(_api_key: str | None = Depends(get_api_key)):
    """Get branch distribution data for pie charts (by instances and MAU)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH prefixes AS (
                    SELECT branch
                    FROM release_versions
                    WHERE status IN ('release', 'main')
                ),
                matched AS (
                    SELECT
                        pv.branch AS prefix,
                        COUNT(md.software_version) AS instances,
                        COALESCE(SUM(md.active_users_monthly), 0) AS mau
                    FROM prefixes pv
                    LEFT JOIN mastodon_domains md
                      ON md.software_version LIKE pv.branch || '%%'
                    GROUP BY pv.branch
                ),
                eol AS (
                    SELECT
                        'EOL' AS prefix,
                        COUNT(*) AS instances,
                        COALESCE(SUM(active_users_monthly), 0) AS mau
                    FROM mastodon_domains md
                    WHERE EXISTS (
                        SELECT 1
                        FROM release_versions rv
                        WHERE rv.status = 'eol'
                          AND md.software_version LIKE rv.branch || '%%'
                    )
                )
                SELECT * FROM matched
                UNION ALL
                SELECT * FROM eol
                ORDER BY prefix
            """
            )
            results = cur.fetchall()

        return {
            "distribution": [
                {
                    "branch": row[0],
                    "instances": row[1],
                    "mau": row[2] or 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/eol-distribution", tags=["Dashboard"])
async def get_eol_distribution(_api_key: str | None = Depends(get_api_key)):
    """Get EOL branch breakdown for pie charts."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH prefixes AS (
                  SELECT DISTINCT branch AS prefix
                  FROM release_versions
                  WHERE branch IS NOT NULL AND status = 'eol'
                ),
                matched AS (
                  SELECT
                    p.prefix,
                    COUNT(md.software_version) AS instances,
                    COALESCE(SUM(md.active_users_monthly), 0) AS mau
                  FROM prefixes p
                  LEFT JOIN mastodon_domains md
                    ON md.software_version LIKE p.prefix || '%%'
                  GROUP BY p.prefix
                )
                SELECT prefix, instances, mau
                FROM matched
                ORDER BY prefix
            """
            )
            results = cur.fetchall()

        return {
            "distribution": [
                {
                    "branch": row[0],
                    "instances": row[1],
                    "mau": row[2] or 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/branch-adoption", tags=["Dashboard"])
async def get_branch_adoption(_api_key: str | None = Depends(get_api_key)):
    """Get cumulative branch adoption percentages."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH recent_releases AS (
                    SELECT branch, n_level
                    FROM release_versions
                    WHERE status IN ('release', 'eol')
                    ORDER BY n_level
                    LIMIT 7
                ),
                total_count AS (
                    SELECT COUNT(*) as total
                    FROM mastodon_domains
                    WHERE software_version IS NOT NULL
                ),
                total_mau AS (
                    SELECT SUM(active_users_monthly) as total
                    FROM mastodon_domains
                    WHERE software_version IS NOT NULL
                      AND active_users_monthly IS NOT NULL
                ),
                adoption_instances AS (
                    SELECT
                        rr.branch || '+' as version_label,
                        rr.n_level,
                        COUNT(CASE WHEN EXISTS (
                            SELECT 1 FROM release_versions rv
                            WHERE rv.n_level <= rr.n_level
                            AND md.software_version LIKE rv.branch || '%%'
                        ) THEN 1 END) * 100.0 / NULLIF(tc.total, 0) AS adoption_percent
                    FROM recent_releases rr
                    CROSS JOIN mastodon_domains md
                    CROSS JOIN total_count tc
                    WHERE md.software_version IS NOT NULL
                    GROUP BY rr.branch, rr.n_level, tc.total
                ),
                adoption_mau AS (
                    SELECT
                        rr.branch || '+' as version_label,
                        rr.n_level,
                        SUM(CASE WHEN EXISTS (
                            SELECT 1 FROM release_versions rv
                            WHERE rv.n_level <= rr.n_level
                            AND md.software_version LIKE rv.branch || '%%'
                        ) THEN md.active_users_monthly ELSE 0 END) * 100.0 / NULLIF(tm.total, 0) AS adoption_percent
                    FROM recent_releases rr
                    CROSS JOIN mastodon_domains md
                    CROSS JOIN total_mau tm
                    WHERE md.software_version IS NOT NULL
                      AND md.active_users_monthly IS NOT NULL
                    GROUP BY rr.branch, rr.n_level, tm.total
                )
                SELECT
                    ai.version_label,
                    ai.adoption_percent AS instances_percent,
                    COALESCE(am.adoption_percent, 0) AS mau_percent
                FROM adoption_instances ai
                LEFT JOIN adoption_mau am
                  ON ai.version_label = am.version_label
                ORDER BY ai.n_level
            """
            )
            results = cur.fetchall()

        return {
            "adoption": [
                {
                    "branch": row[0],
                    "instances_percent": round(float(row[1]), 2) if row[1] else 0,
                    "mau_percent": round(float(row[2]), 2) if row[2] else 0,
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/stats/supported-branches", tags=["Dashboard"])
async def get_supported_branches_coverage(
    _api_key: str | None = Depends(get_api_key),
):
    """Get percentage of instances and MAU on supported branches."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH supported_branches AS (
                  SELECT DISTINCT branch
                  FROM release_versions
                  WHERE status IN ('release', 'main')
                ),
                eol_branches AS (
                  SELECT DISTINCT branch
                  FROM release_versions
                  WHERE status = 'eol'
                ),
                agg AS (
                  SELECT
                    COUNT(DISTINCT md.domain) AS total_domains,
                    COALESCE(SUM(md.active_users_monthly), 0) AS total_users,
                    COUNT(DISTINCT md.domain) FILTER (
                      WHERE EXISTS (
                              SELECT 1 FROM eol_branches eb
                              WHERE md.software_version LIKE eb.branch || '.%%'
                            )
                         OR NOT EXISTS (
                              SELECT 1 FROM supported_branches sb
                              WHERE md.software_version LIKE sb.branch || '.%%'
                            )
                    ) AS unsupported_or_eol_domains,
                    COALESCE(SUM(md.active_users_monthly) FILTER (
                      WHERE EXISTS (
                              SELECT 1 FROM eol_branches eb
                              WHERE md.software_version LIKE eb.branch || '.%%'
                            )
                         OR NOT EXISTS (
                              SELECT 1 FROM supported_branches sb
                              WHERE md.software_version LIKE sb.branch || '.%%'
                            )
                    ), 0) AS unsupported_or_eol_users
                  FROM mastodon_domains md
                )
                SELECT
                  ((total_domains - unsupported_or_eol_domains) * 100.0
                    / NULLIF(total_domains, 0)) AS instances_percent,
                  ((total_users - unsupported_or_eol_users) * 100.0
                    / NULLIF(total_users, 0)) AS mau_percent
                FROM agg
            """
            )
            result = cur.fetchone()

        return {
            "instances_percent": (
                round(float(result[0]), 1) if result and result[0] else 0
            ),
            "mau_percent": (round(float(result[1]), 1) if result and result[1] else 0),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# =============================================================================
# CHART IMAGE ENDPOINTS
# =============================================================================

QUICKCHART_URL = "https://quickchart.io/chart"
CHART_COLORS = [
    "#9b59b6",
    "#3498db",
    "#2ecc71",
    "#f39c12",
    "#1abc9c",
    "#e67e22",
    "#95a5a6",
]
BRANCH_COLORS = ["#2ecc71", "#3498db", "#9b59b6", "#f39c12", "#1abc9c", "#e67e22"]
RED = "#e74c3c"
ORANGE = "#f39c12"
PURPLE = "#9b59b6"
GREEN = "#2ecc71"


async def _fetch_chart_png(chart_config: dict) -> bytes:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    plugins = chart_config.setdefault("options", {}).setdefault("plugins", {})
    plugins["subtitle"] = {
        "display": True,
        "text": f"Generated {now}",
        "color": "#8888a0",
        "font": {"size": 11},
        "padding": {"bottom": 8},
    }
    params = {
        "c": json.dumps(chart_config),
        "w": 600,
        "h": 400,
        "bkg": "#1a1a24",
        "v": "4",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(QUICKCHART_URL, params=params)
        resp.raise_for_status()
        return resp.content


@app.get("/charts/patch-distribution.png", tags=["Charts"], response_class=Response)
async def chart_patch_distribution(
    metric: str = Query("instances", pattern="^(instances|mau)$"),
    _api_key: str | None = Depends(get_api_key),
):
    """Render patch distribution as a PNG doughnut chart (patched / unpatched / EOL)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH version_cases AS (
                  SELECT latest AS software_version
                  FROM release_versions
                  WHERE status IN ('release', 'main')
                ),
                eol_check AS (
                  SELECT DISTINCT md.software_version
                  FROM mastodon_domains md
                  WHERE EXISTS (
                    SELECT 1
                    FROM release_versions rv
                    WHERE rv.status = 'eol'
                      AND md.software_version LIKE rv.branch || '.%'
                  )
                )
                SELECT
                  CASE
                    WHEN software_version IN (SELECT software_version FROM version_cases)
                      THEN software_version
                    WHEN software_version IN (SELECT software_version FROM eol_check)
                      THEN 'EOL'
                    ELSE 'Unpatched'
                  END as version,
                  COUNT(*) as instance_count,
                  COALESCE(SUM(active_users_monthly), 0) as mau_count
                FROM mastodon_domains
                GROUP BY CASE
                    WHEN software_version IN (SELECT software_version FROM version_cases)
                      THEN software_version
                    WHEN software_version IN (SELECT software_version FROM eol_check)
                      THEN 'EOL'
                    ELSE 'Unpatched'
                  END
                ORDER BY instance_count DESC
                """
            )
            rows = cur.fetchall()

        distribution = [
            {"version": r[0], "instances": r[1], "mau": r[2] or 0} for r in rows
        ]
        distribution.sort(key=lambda d: d["instances"], reverse=True)

        raw_labels = [d["version"] for d in distribution]
        values = [d[metric] for d in distribution]
        colors = [
            RED if lbl == "EOL" else ORANGE if lbl == "Unpatched" else PURPLE
            for lbl in raw_labels
        ]
        metric_label = "Instances" if metric == "instances" else "Monthly Active Users"
        labels = [f"{lbl} ({v:,})" for lbl, v in zip(raw_labels, values)]

        chart_config = {
            "type": "doughnut",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "data": values,
                        "backgroundColor": colors,
                        "borderWidth": 1,
                        "borderColor": "#1a1a24",
                    }
                ],
            },
            "options": {
                "plugins": {
                    "title": {
                        "display": True,
                        "text": f"Patch Distribution ({metric_label})",
                        "color": "#ffffff",
                        "font": {"size": 16},
                    },
                    "legend": {
                        "position": "bottom",
                        "labels": {
                            "color": "#8888a0",
                            "usePointStyle": True,
                            "font": {"size": 11},
                        },
                    },
                    "datalabels": {"display": False},
                }
            },
        }

        png = await _fetch_chart_png(chart_config)
        return Response(content=png, media_type="image/png")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Chart rendering error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/charts/branch-distribution.png", tags=["Charts"], response_class=Response)
async def chart_branch_distribution(
    metric: str = Query("instances", pattern="^(instances|mau)$"),
    _api_key: str | None = Depends(get_api_key),
):
    """Render branch distribution as a PNG doughnut chart."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH prefixes AS (
                    SELECT branch
                    FROM release_versions
                    WHERE status IN ('release', 'main')
                ),
                matched AS (
                    SELECT
                        pv.branch AS prefix,
                        COUNT(md.software_version) AS instances,
                        COALESCE(SUM(md.active_users_monthly), 0) AS mau
                    FROM prefixes pv
                    LEFT JOIN mastodon_domains md
                      ON md.software_version LIKE pv.branch || '%%'
                    GROUP BY pv.branch
                ),
                eol AS (
                    SELECT
                        'EOL' AS prefix,
                        COUNT(*) AS instances,
                        COALESCE(SUM(active_users_monthly), 0) AS mau
                    FROM mastodon_domains md
                    WHERE EXISTS (
                        SELECT 1
                        FROM release_versions rv
                        WHERE rv.status = 'eol'
                          AND md.software_version LIKE rv.branch || '%%'
                    )
                )
                SELECT * FROM matched
                UNION ALL
                SELECT * FROM eol
                ORDER BY prefix
                """
            )
            rows = cur.fetchall()

        distribution = [
            {"branch": r[0], "instances": r[1], "mau": r[2] or 0} for r in rows
        ]

        raw_labels = [d["branch"] for d in distribution]
        values = [d[metric] for d in distribution]
        colors = [RED if lbl == "EOL" else GREEN for lbl in raw_labels]
        metric_label = "Instances" if metric == "instances" else "Monthly Active Users"
        labels = [f"{lbl} ({v:,})" for lbl, v in zip(raw_labels, values)]

        chart_config = {
            "type": "doughnut",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "data": values,
                        "backgroundColor": colors,
                        "borderWidth": 1,
                        "borderColor": "#1a1a24",
                    }
                ],
            },
            "options": {
                "plugins": {
                    "title": {
                        "display": True,
                        "text": f"Branch Distribution ({metric_label})",
                        "color": "#ffffff",
                        "font": {"size": 16},
                    },
                    "legend": {
                        "position": "bottom",
                        "labels": {
                            "color": "#8888a0",
                            "usePointStyle": True,
                            "font": {"size": 11},
                        },
                    },
                    "datalabels": {"display": False},
                }
            },
        }

        png = await _fetch_chart_png(chart_config)
        return Response(content=png, media_type="image/png")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Chart rendering error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/charts/branch-adoption.png", tags=["Charts"], response_class=Response)
async def chart_branch_adoption(
    metric: str = Query("instances", pattern="^(instances|mau)$"),
    _api_key: str | None = Depends(get_api_key),
):
    """Render cumulative branch adoption as a PNG horizontal bar chart."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                WITH recent_releases AS (
                    SELECT branch, n_level
                    FROM release_versions
                    WHERE status IN ('release', 'eol')
                    ORDER BY n_level
                    LIMIT 7
                ),
                total_count AS (
                    SELECT COUNT(*) as total
                    FROM mastodon_domains
                    WHERE software_version IS NOT NULL
                ),
                total_mau AS (
                    SELECT SUM(active_users_monthly) as total
                    FROM mastodon_domains
                    WHERE software_version IS NOT NULL
                      AND active_users_monthly IS NOT NULL
                ),
                adoption_instances AS (
                    SELECT
                        rr.branch || '+' as version_label,
                        rr.n_level,
                        COUNT(CASE WHEN EXISTS (
                            SELECT 1 FROM release_versions rv
                            WHERE rv.n_level <= rr.n_level
                            AND md.software_version LIKE rv.branch || '%%'
                        ) THEN 1 END) * 100.0 / NULLIF(tc.total, 0) AS adoption_percent
                    FROM recent_releases rr
                    CROSS JOIN mastodon_domains md
                    CROSS JOIN total_count tc
                    WHERE md.software_version IS NOT NULL
                    GROUP BY rr.branch, rr.n_level, tc.total
                ),
                adoption_mau AS (
                    SELECT
                        rr.branch || '+' as version_label,
                        rr.n_level,
                        SUM(CASE WHEN EXISTS (
                            SELECT 1 FROM release_versions rv
                            WHERE rv.n_level <= rr.n_level
                            AND md.software_version LIKE rv.branch || '%%'
                        ) THEN md.active_users_monthly ELSE 0 END) * 100.0 / NULLIF(tm.total, 0) AS adoption_percent
                    FROM recent_releases rr
                    CROSS JOIN mastodon_domains md
                    CROSS JOIN total_mau tm
                    WHERE md.software_version IS NOT NULL
                      AND md.active_users_monthly IS NOT NULL
                    GROUP BY rr.branch, rr.n_level, tm.total
                )
                SELECT
                    ai.version_label,
                    ai.adoption_percent AS instances_percent,
                    COALESCE(am.adoption_percent, 0) AS mau_percent
                FROM adoption_instances ai
                LEFT JOIN adoption_mau am
                  ON ai.version_label = am.version_label
                ORDER BY ai.n_level
                """
            )
            rows = cur.fetchall()

        adoption = [
            {
                "branch": r[0],
                "instances_percent": round(float(r[1]), 2) if r[1] else 0,
                "mau_percent": round(float(r[2]), 2) if r[2] else 0,
            }
            for r in rows
        ]

        labels = [d["branch"] for d in adoption]
        values = [d[f"{metric}_percent"] for d in adoption]
        metric_label = "Instances" if metric == "instances" else "Monthly Active Users"

        chart_config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "data": values,
                        "backgroundColor": PURPLE,
                        "borderRadius": 4,
                        "label": "% on branch or newer",
                    }
                ],
            },
            "options": {
                "indexAxis": "y",
                "scales": {
                    "x": {
                        "min": 0,
                        "max": 100,
                        "ticks": {
                            "color": "#8888a0",
                            "callback": "function(v){ return v + '%' }",
                        },
                        "grid": {"color": "#2a2a3a"},
                    },
                    "y": {"ticks": {"color": "#8888a0"}, "grid": {"display": False}},
                },
                "plugins": {
                    "title": {
                        "display": True,
                        "text": f"Cumulative Branch Adoption ({metric_label})",
                        "color": "#ffffff",
                        "font": {"size": 16},
                    },
                    "legend": {"display": False},
                },
            },
        }

        png = await _fetch_chart_png(chart_config)
        return Response(content=png, media_type="image/png")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Chart rendering error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/charts/patch-history.png", tags=["Charts"], response_class=Response)
async def chart_patch_history(
    metric: str = Query("instances", pattern="^(instances|mau)$"),
    days: int = Query(30, ge=7, le=365, description="Days of history to pull"),
    _api_key: str | None = Depends(get_api_key),
):
    """Render patched-instance historical trends as a PNG stacked bar chart."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT date,
                       main_patched_instances, latest_patched_instances,
                       previous_patched_instances, deprecated_patched_instances,
                       main_patched_mau, latest_patched_mau,
                       previous_patched_mau, deprecated_patched_mau
                FROM statistics
                ORDER BY date DESC
                LIMIT %s
                """,
                (days,),
            )
            rows = cur.fetchall()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    # Reverse so oldest → newest left-to-right; take last 10 for readability
    hist = list(reversed(rows))[-10:]
    labels = [
        row[0].strftime("%d %b") if hasattr(row[0], "strftime") else str(row[0])
        for row in hist
    ]

    if metric == "instances":
        datasets = [
            {
                "label": "Main Branch",
                "data": [r[1] for r in hist],
                "backgroundColor": "#3498db",
            },
            {
                "label": "Latest Branch",
                "data": [r[2] for r in hist],
                "backgroundColor": "#2ecc71",
            },
            {
                "label": "Previous Branch",
                "data": [r[3] for r in hist],
                "backgroundColor": "#9b59b6",
            },
            {
                "label": "Deprecated Branch",
                "data": [r[4] for r in hist],
                "backgroundColor": "#f39c12",
            },
        ]
    else:
        datasets = [
            {
                "label": "Main Branch",
                "data": [r[5] for r in hist],
                "backgroundColor": "#3498db",
            },
            {
                "label": "Latest Branch",
                "data": [r[6] for r in hist],
                "backgroundColor": "#2ecc71",
            },
            {
                "label": "Previous Branch",
                "data": [r[7] for r in hist],
                "backgroundColor": "#9b59b6",
            },
            {
                "label": "Deprecated Branch",
                "data": [r[8] for r in hist],
                "backgroundColor": "#f39c12",
            },
        ]

    metric_label = "Instances" if metric == "instances" else "Monthly Active Users"
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": datasets},
        "options": {
            "indexAxis": "y",
            "scales": {
                "x": {
                    "stacked": True,
                    "ticks": {"color": "#8888a0"},
                    "grid": {"color": "#2a2a3a"},
                },
                "y": {
                    "stacked": True,
                    "ticks": {"color": "#8888a0"},
                    "grid": {"display": False},
                },
            },
            "plugins": {
                "title": {
                    "display": True,
                    "text": f"Patched Instance Trend ({metric_label})",
                    "color": "#ffffff",
                    "font": {"size": 16},
                },
                "legend": {
                    "position": "bottom",
                    "labels": {
                        "color": "#8888a0",
                        "usePointStyle": True,
                        "font": {"size": 11},
                    },
                },
            },
        },
    }

    try:
        png = await _fetch_chart_png(chart_config)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Chart rendering error: {str(e)}")
    return Response(content=png, media_type="image/png")


@app.get("/charts/branch-history.png", tags=["Charts"], response_class=Response)
async def chart_branch_history(
    metric: str = Query("instances", pattern="^(instances|mau)$"),
    days: int = Query(30, ge=7, le=365, description="Days of history to pull"),
    _api_key: str | None = Depends(get_api_key),
):
    """Render total branch deployment historical trends as a PNG stacked bar chart."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT date,
                       main_instances, latest_instances,
                       previous_instances, deprecated_instances, eol_instances,
                       main_branch_mau, latest_branch_mau,
                       previous_branch_mau, deprecated_branch_mau, eol_branch_mau
                FROM statistics
                ORDER BY date DESC
                LIMIT %s
                """,
                (days,),
            )
            rows = cur.fetchall()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    hist = list(reversed(rows))[-10:]
    labels = [
        row[0].strftime("%d %b") if hasattr(row[0], "strftime") else str(row[0])
        for row in hist
    ]

    if metric == "instances":
        datasets = [
            {
                "label": "Main Branch",
                "data": [r[1] for r in hist],
                "backgroundColor": "#3498db",
            },
            {
                "label": "Latest Branch",
                "data": [r[2] for r in hist],
                "backgroundColor": "#2ecc71",
            },
            {
                "label": "Previous Branch",
                "data": [r[3] for r in hist],
                "backgroundColor": "#9b59b6",
            },
            {
                "label": "Deprecated Branch",
                "data": [r[4] for r in hist],
                "backgroundColor": "#f39c12",
            },
            {
                "label": "EOL Branches",
                "data": [r[5] for r in hist],
                "backgroundColor": "#e74c3c",
            },
        ]
    else:
        datasets = [
            {
                "label": "Main Branch",
                "data": [r[6] for r in hist],
                "backgroundColor": "#3498db",
            },
            {
                "label": "Latest Branch",
                "data": [r[7] for r in hist],
                "backgroundColor": "#2ecc71",
            },
            {
                "label": "Previous Branch",
                "data": [r[8] for r in hist],
                "backgroundColor": "#9b59b6",
            },
            {
                "label": "Deprecated Branch",
                "data": [r[9] for r in hist],
                "backgroundColor": "#f39c12",
            },
            {
                "label": "EOL Branches",
                "data": [r[10] for r in hist],
                "backgroundColor": "#e74c3c",
            },
        ]

    metric_label = "Instances" if metric == "instances" else "Monthly Active Users"
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": datasets},
        "options": {
            "indexAxis": "y",
            "scales": {
                "x": {
                    "stacked": True,
                    "ticks": {"color": "#8888a0"},
                    "grid": {"color": "#2a2a3a"},
                },
                "y": {
                    "stacked": True,
                    "ticks": {"color": "#8888a0"},
                    "grid": {"display": False},
                },
            },
            "plugins": {
                "title": {
                    "display": True,
                    "text": f"Branch Deployment Trend ({metric_label})",
                    "color": "#ffffff",
                    "font": {"size": 16},
                },
                "legend": {
                    "position": "bottom",
                    "labels": {
                        "color": "#8888a0",
                        "usePointStyle": True,
                        "font": {"size": 11},
                    },
                },
            },
        },
    }

    try:
        png = await _fetch_chart_png(chart_config)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Chart rendering error: {str(e)}")
    return Response(content=png, media_type="image/png")


# =============================================================================
# STATIC FILES & MAIN
# =============================================================================

# Mount static files for dashboard (must be after all API routes)
_web_dir = os.path.join(os.path.dirname(__file__), "web")
if os.path.isdir(_web_dir):
    app.mount("/", StaticFiles(directory=_web_dir, html=True), name="web")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
