FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.21 (needed for pdtm and PD tools)
ENV GO_VERSION=1.21.13
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install pdtm and all ProjectDiscovery tools
RUN go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest \
    && pdtm -install-all -silent

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Default command (overridden per service in docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
