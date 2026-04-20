FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22 (needed for nuclei)
ENV GO_VERSION=1.22.5
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install ffuf — used by the content_discovery_worker for path + parameter
# brute-forcing. Pinned to v2 (stable major); any bump should be verified
# against the worker's JSON output parsing since ffuf has changed field
# names between majors.
RUN go install github.com/ffuf/ffuf/v2@latest \
    && ln -sf /root/go/bin/ffuf /usr/local/bin/ffuf

# Download default templates
RUN nuclei -update-templates || true

# Clean Go module cache
RUN go clean -modcache

# Python deps
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# App code
COPY scanner/ /app/scanner/
COPY templates/ /app/templates/

# Default command (overridden per service in docker-compose)
CMD ["uvicorn", "scanner.vm.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8002"]
