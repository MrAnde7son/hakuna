# ───────── Builder stage ─────────
# Go toolchain + nuclei template fetch live here. Runtime stage copies
# only the compiled binaries + downloaded templates, so /usr/local/go
# never reaches the published image.
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION=1.22.5
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ffuf — used by the content_discovery_worker for path + parameter
# brute-forcing. Pinned to v2 (stable major); any bump should be verified
# against the worker's JSON output parsing since ffuf has changed field
# names between majors.
RUN go install github.com/ffuf/ffuf/v2@latest

# Default templates — fetched at build time so the runtime image is
# offline-capable for the standard template set.
RUN /root/go/bin/nuclei -update-templates || true


# ───────── Runtime stage ─────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Compiled Go binaries
COPY --from=builder /root/go/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /root/go/bin/ffuf   /usr/local/bin/ffuf

# Nuclei template store — default location is $HOME/nuclei-templates
COPY --from=builder /root/nuclei-templates /root/nuclei-templates

# Python deps
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Chromium for the agent's render_page tool (SPA rendering). Playwright's
# own installer pulls the browser + every shared library it needs;
# ``--with-deps`` adds the apt-level fonts/codecs/gtk bits that plain
# `apt-get install chromium` would also need. Adds ~400MB to the image.
# Skip with --build-arg SKIP_PLAYWRIGHT=1 on minimal builds where only
# the static specialists are needed.
ARG SKIP_PLAYWRIGHT=0
RUN if [ "$SKIP_PLAYWRIGHT" = "0" ]; then \
        playwright install --with-deps chromium; \
    else \
        echo "skipping playwright chromium install"; \
    fi

COPY scanner/ /app/scanner/
COPY templates/ /app/templates/

CMD ["uvicorn", "scanner.vm.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8002"]
