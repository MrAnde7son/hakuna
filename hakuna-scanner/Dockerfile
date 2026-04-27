# ───────── Builder stage ─────────
# All Go toolchain + build-only libs live here. The runtime stage copies
# just the compiled binaries, so /usr/local/go and the module cache
# never reach the published image.
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates unzip gcc make libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION=1.22.5
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# PD tools that don't need CGO
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    && go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
    && go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
    && go install github.com/projectdiscovery/uncover/cmd/uncover@latest

# Katana — separate layer (heavier build)
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# Naabu needs CGO for libpcap
RUN git clone --depth 1 https://github.com/projectdiscovery/naabu.git /tmp/naabu \
    && cd /tmp/naabu/cmd/naabu \
    && CGO_ENABLED=1 go build -o /root/go/bin/naabu . \
    && rm -rf /tmp/naabu

# Massdns — built from source (no apt package)
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns \
    && cp /tmp/massdns/bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Puredns (Go binary, wraps massdns)
RUN go install github.com/d3mondev/puredns/v2@latest

# Kiterunner — custom build target, binary is `kr`
RUN git clone --depth 1 https://github.com/assetnote/kiterunner.git /tmp/kiterunner \
    && cd /tmp/kiterunner \
    && go build -o /root/go/bin/kr ./cmd/kiterunner \
    && rm -rf /tmp/kiterunner

# Wordlists — small, baked here so the runtime stage doesn't need wget
RUN mkdir -p /opt/hakuna/wordlists \
    && (wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/DNS/subdomains-top1million-5000.txt" \
       -O /opt/hakuna/wordlists/subdomains.txt \
    || wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
       -O /opt/hakuna/wordlists/subdomains.txt) \
    && wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
       -O /opt/hakuna/wordlists/resolvers.txt \
    && wget -q "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz" \
       -O /tmp/kiterunner-routes.tar.gz \
    && tar -xzf /tmp/kiterunner-routes.tar.gz -C /tmp \
    && mv /tmp/routes-large.kite /opt/hakuna/wordlists/kiterunner-routes.kite \
    && rm /tmp/kiterunner-routes.tar.gz


# ───────── Runtime stage ─────────
FROM python:3.11-slim

# Runtime deps:
#   libpcap0.8        — naabu (dynamically linked)
#   nmap              — fingerprinting (Pipeline A nmap step)
#   chromium + libs   — httpx -screenshot (headless browser)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates nmap libpcap0.8 \
    chromium fonts-liberation libappindicator3-1 libasound2 \
    libatk-bridge2.0-0 libatk1.0-0 libcups2 libdbus-1-3 \
    libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 \
    libxcomposite1 libxdamage1 libxrandr2 xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# httpx/rod must be told where chromium lives, otherwise rod tries to
# download its own copy at first use, the download is killed by the
# per-host timeout, and every screenshot ends up as a 0-byte PNG.
# Also requires the -system-chrome flag at runtime — see HttpxRunner.
ENV CHROMIUM_PATH=/usr/bin/chromium

# Compiled Go binaries from the builder stage
COPY --from=builder /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /root/go/bin/dnsx      /usr/local/bin/dnsx
COPY --from=builder /root/go/bin/httpx     /usr/local/bin/httpx
COPY --from=builder /root/go/bin/tlsx      /usr/local/bin/tlsx
COPY --from=builder /root/go/bin/cdncheck  /usr/local/bin/cdncheck
COPY --from=builder /root/go/bin/asnmap    /usr/local/bin/asnmap
COPY --from=builder /root/go/bin/uncover   /usr/local/bin/uncover
COPY --from=builder /root/go/bin/katana    /usr/local/bin/katana
COPY --from=builder /root/go/bin/naabu     /usr/local/bin/naabu
COPY --from=builder /root/go/bin/puredns   /usr/local/bin/puredns
COPY --from=builder /root/go/bin/kr        /usr/local/bin/kr
COPY --from=builder /usr/local/bin/massdns /usr/local/bin/massdns

# Wordlists live OUTSIDE /app on purpose: docker-compose bind-mounts the
# host repo at /app for live reload, which would otherwise hide anything
# the build put under /app/wordlists/.
COPY --from=builder /opt/hakuna/wordlists /opt/hakuna/wordlists

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright uses the system chromium already installed above.
ENV PLAYWRIGHT_BROWSERS_PATH=0

# App code
COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
