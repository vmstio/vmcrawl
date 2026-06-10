ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-slim

# Pinned uv for reproducible dependency resolution.
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/uv

WORKDIR /opt/vmcrawl

# Install locked dependencies first so this layer is cached unless the
# dependency set actually changes. --frozen fails loudly on a stale lock
# instead of silently re-resolving; --no-dev skips the dev dependency group.
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --frozen

# Application source. crawler.py reads pyproject.toml at runtime to derive its
# name/version for the User-Agent, so pyproject.toml (copied above) must stay.
COPY crawler.py ./

# Drop privileges: unprivileged user owning the app tree. Home is /opt/vmcrawl
# so the crawler's ~/.cache/vmcrawl directory resolves to a writable path.
RUN useradd --system --home-dir /opt/vmcrawl --shell /usr/sbin/nologin vmcrawl \
    && chown -R vmcrawl:vmcrawl /opt/vmcrawl
USER vmcrawl

# Flush stdout/stderr promptly to the container log; don't write .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run the interpreter from the venv uv created (mirrors Dockerfile.api) so
# startup does no dependency resolution and needs no network or uv cache.
# Arguments passed to `docker run` are forwarded to crawler.py.
ENTRYPOINT [".venv/bin/python", "crawler.py"]
