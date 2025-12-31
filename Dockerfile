ARG DEBIAN_VERSION=trixie
ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-${DEBIAN_VERSION}

RUN apt update && apt upgrade -y && apt install -y curl lsb-release vim

RUN git clone https://github.com/vmstio/vmcrawl.git \
    && cd vmcrawl \
    && python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install --upgrade pip \
    && pip install .
WORKDIR /vmcrawl

ENTRYPOINT [ "sh", "-c", ". .venv/bin/activate && python3 crawler.py" ]