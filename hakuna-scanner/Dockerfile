FROM python:3.11-slim

# System deps (gcc + libpcap-dev needed for naabu CGO build, nmap for fingerprinting)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates unzip gcc libpcap-dev nmap \
    && rm -rf /var/lib/apt/lists/*

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
    && go install github.com/projectdiscovery/uncover/cmd/uncover@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest

# Naabu needs CGO for libpcap — clone and build
RUN git clone --depth 1 https://github.com/projectdiscovery/naabu.git /tmp/naabu \
    && cd /tmp/naabu/cmd/naabu \
    && CGO_ENABLED=1 go build -o /root/go/bin/naabu . \
    && rm -rf /tmp/naabu

# Puredns (Go binary, handles wildcard filtering natively)
RUN go install github.com/d3mondev/puredns/v2@latest

# Clean up Go module cache to save image space
RUN go clean -modcache

# Default subdomain wordlist for brute force
RUN mkdir -p /app/wordlists \
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
       -O /app/wordlists/subdomains.txt

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Default command (overridden per service in docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
