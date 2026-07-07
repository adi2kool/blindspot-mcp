# Airlock - the instruction and data trust boundary for MCP.
# A small image that installs the package and exposes the `airlock` CLI. Note the proxy's
# stdio launcher runs `python <target>`, so in a container Airlock fronts an HTTP upstream
# (`airlock proxy --http <url>`) or scans an endpoint; stdio-launched upstreams are better
# run via pip/uvx on the host (see docs/deploy.md).
FROM python:3.12-slim

LABEL org.opencontainers.image.title="airlock"
LABEL org.opencontainers.image.description="Airlock - the instruction and data trust boundary for MCP"
LABEL org.opencontainers.image.source="https://github.com/adi2kool/airlock-mcp"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy only what the build backend needs (dynamic version reads src/airlock/__init__.py;
# license-files and readme are declared in pyproject), then install and drop the source.
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && rm -rf /src

# Run as a non-root user.
RUN useradd --create-home airlock
USER airlock
WORKDIR /home/airlock

ENTRYPOINT ["airlock"]
CMD ["--help"]
