FROM python:3.11-slim

WORKDIR /app

# Chromium system libraries for the scheduled-report PDF renderer (Playwright).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libpango-1.0-0 libcairo2 libasound2 libatspi2.0-0 \
    libx11-6 libxcb1 libxext6 fonts-liberation \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium (headless shell) for the PDF renderer.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN python -m playwright install chromium

COPY . .

# DATABASE_URL is required at runtime — supplied by docker-compose / Cloud Run env.
# No default: fail fast if unset rather than silently pointing at the wrong DB.

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
