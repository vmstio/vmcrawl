ARG DEBIAN_VERSION=trixie
ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-${DEBIAN_VERSION}

RUN apt-get update && apt-get upgrade -y

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Clone repository and set up application
RUN git clone https://github.com/vmstio/vmcrawl.git /opt/vmcrawl

# Create vmcrawl system user and set ownership
RUN useradd -r -s /bin/bash -d /opt/vmcrawl vmcrawl \
    && chown -R vmcrawl:vmcrawl /opt/vmcrawl

# Switch to vmcrawl user
USER vmcrawl
WORKDIR /opt/vmcrawl

# Set up virtual environment and install dependencies
RUN uv sync

# Make the startup script executable
RUN chmod +x /opt/vmcrawl/vmcrawl.sh

ENTRYPOINT ["/opt/vmcrawl/vmcrawl.sh"]
