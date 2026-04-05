FROM python:3.11-slim

LABEL org.opencontainers.image.title="Hakuna Relay Agent"
LABEL org.opencontainers.image.description="On-prem relay agent for Hakuna integration builder"

WORKDIR /app

# Install deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ agent/

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "agent.main"]
