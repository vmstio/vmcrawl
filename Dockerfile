ARG DEBIAN_VERSION=trixie
ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-${DEBIAN_VERSION}

RUN apt-get update && apt-get upgrade -y

# Clone repository and set up application
RUN git clone https://github.com/vmstio/vmcrawl.git /opt/vmcrawl

# Create vmcrawl system user and set ownership
RUN useradd -r -s /bin/bash -d /opt/vmcrawl vmcrawl \
    && chown -R vmcrawl:vmcrawl /opt/vmcrawl

# Switch to vmcrawl user
USER vmcrawl
WORKDIR /opt/vmcrawl

# Set up virtual environment and install dependencies
RUN python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install --upgrade pip \
    && pip install -r requirements.txt

# Make the startup script executable
RUN chmod +x /opt/vmcrawl/vmcrawl.sh

ENTRYPOINT ["/opt/vmcrawl/vmcrawl.sh"]
