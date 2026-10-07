# syntax=docker/dockerfile:1.27

FROM python:3.14-slim AS base

# uv install
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

# Dependency layer (cached unless lockfile changes)
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

# Source + project install
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Drop the base image's pip: its vendored urllib3/msgpack/setuptools trip trivy and
# nothing at runtime needs pip (deps live in /opt/venv, installed by uv).
RUN pip uninstall -y pip

# Runtime
ENV WAZUH_MCP_CONFIG_DIR=/config \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user
RUN groupadd -g 10001 wazuhmcp && useradd -u 10001 -g 10001 -m -s /sbin/nologin wazuhmcp
RUN mkdir -p /config && chown -R wazuhmcp:wazuhmcp /config /app /opt/venv
USER 10001:10001

EXPOSE 8080

# Default command — transport (stdio|http) + bind chosen by /config/server.yaml.
# The helm chart mounts a ConfigMap+Secret at /config and renders server.yaml
# with `transport: http` + `http.bind: 0.0.0.0:8080` to match probe paths.
ENTRYPOINT ["wazuh-mcp"]
