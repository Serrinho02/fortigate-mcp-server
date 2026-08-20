# FortiGate MCP Server Dockerfile
#
# NOTE: CredentialManager (fortinet-mcp-cred) uses the OS `keyring` library.
# A bare Linux container has no Secret Service daemon for it to talk to --
# provisioning credentials via `fortinet-mcp-cred` will fail as shipped. See
# docs/INSTALLATION.md#docker for the keyrings.cryptfile workaround. Either
# provision credentials on a host with a working keyring backend, or run the
# server natively (not in Docker) if you need that CLI to work.
FROM python:3.12-slim

# Metadata
LABEL maintainer="Nicola Serra"
LABEL description="FortiGate MCP Server - FastMCP based FortiGate management server"
LABEL version="1.0.0"

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8814

# Create app user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Set working directory
WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        netcat-traditional \
        git \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Copy project files needed for installation
COPY pyproject.toml README.md ./
COPY src/ src/

# Install Python dependencies with uv
RUN uv pip install --system --no-cache-dir -e .

# Copy remaining application code
COPY config/ config/
COPY tests/ tests/
COPY pytest.ini .

# Create logs directory
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check - Sadece port kontrolü yap
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost ${MCP_SERVER_PORT} || exit 1

# Expose port
EXPOSE ${MCP_SERVER_PORT}

# Default command
CMD ["python", "-m", "src.fortigate_mcp.server_http", "--host", "0.0.0.0", "--port", "8814", "--path", "/fortigate-mcp", "--config", "/app/config/config.json"]
