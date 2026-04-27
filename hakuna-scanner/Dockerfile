FROM python:3.11-slim

# System deps:
#   gcc + libpcap-dev — naabu CGO build
#   make + gcc        — massdns build (puredns runtime dep)
#   nmap              — fingerprinting (Pipeline A nmap step)
#   chromium + libs   — httpx -screenshot (headless browser)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates unzip gcc make libpcap-dev nmap \
    chromium fonts-liberation libappindicator3-1 libasound2 \
    libatk-bridge2.0-0 libatk1.0-0 libcups2 libdbus-1-3 \
    libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 \
    libxcomposite1 libxdamage1 libxrandr2 xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Tell httpx/rod where to find chromium (no download needed). Note that
# httpx also needs the -system-chrome flag at runtime — without it, rod
# tries to download its own Chromium from storage.googleapis.com on first
# use regardless of these env vars, the download is killed by the per-host
# timeout, and every screenshot ends up as a 0-byte PNG. See HttpxRunner.
ENV CHROMIUM_PATH=/usr/bin/chromium

# Install Go 1.22 (needed for PD tools)
ENV GO_VERSION=1.22.5
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install PD tools that don't need CGO
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    && go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
    && go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
    && go install github.com/projectdiscovery/uncover/cmd/uncover@latest

# Katana (separate layer — heavier build with chromium deps)
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# Naabu needs CGO for libpcap — clone and build
RUN git clone --depth 1 https://github.com/projectdiscovery/naabu.git /tmp/naabu \
    && cd /tmp/naabu/cmd/naabu \
    && CGO_ENABLED=1 go build -o /root/go/bin/naabu . \
    && rm -rf /tmp/naabu

# Massdns — runtime dep for puredns. Build from source (no apt package).
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns \
    && cp /tmp/massdns/bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Puredns (Go binary, wraps massdns + handles wildcard filtering natively)
RUN go install github.com/d3mondev/puredns/v2@latest

# Kiterunner (assetnote) — API endpoint brute-forcing. Built from source
# because there's no `go install` entry point: the binary is named `kr` and
# lives under cmd/kiterunner with a custom build target.
RUN git clone --depth 1 https://github.com/assetnote/kiterunner.git /tmp/kiterunner \
    && cd /tmp/kiterunner \
    && go build -o /root/go/bin/kr ./cmd/kiterunner \
    && rm -rf /tmp/kiterunner

# Clean up Go module cache to save image space
RUN go clean -modcache

# Wordlists live OUTSIDE /app on purpose: docker-compose bind-mounts the
# host repo at /app for live reload, which would otherwise hide anything
# the build put under /app/wordlists/.

# Default subdomain wordlist for brute force
RUN mkdir -p /opt/hakuna/wordlists \
    && (wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/DNS/subdomains-top1million-5000.txt" \
       -O /opt/hakuna/wordlists/subdomains.txt \
    || wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
       -O /opt/hakuna/wordlists/subdomains.txt)

# Public DNS resolvers list for puredns/massdns. Curated by trickest, ~28k
# validated public resolvers, refreshed daily upstream. Snapshot baked into
# the image at build time — re-pulled on every rebuild.
RUN wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
       -O /opt/hakuna/wordlists/resolvers.txt

# Kiterunner routes wordlist (assetnote's compiled `.kite` format, ~34MB).
# Distributed as a gzipped tarball — extract and rename. Path is referenced
# by settings.kiterunner_wordlist in app/config.py; keep them in sync.
RUN wget -q "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz" \
       -O /tmp/kiterunner-routes.tar.gz \
    && tar -xzf /tmp/kiterunner-routes.tar.gz -C /tmp \
    && mv /tmp/routes-large.kite /opt/hakuna/wordlists/kiterunner-routes.kite \
    && rm /tmp/kiterunner-routes.tar.gz

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright uses the system chromium already installed above.
# Skip browser download — we point it at /usr/bin/chromium via CHROMIUM_PATH.
ENV PLAYWRIGHT_BROWSERS_PATH=0

# App code
COPY . .

# Default command (overridden per service in docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
