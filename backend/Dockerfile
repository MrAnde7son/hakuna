FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SQLite DB will be stored in a volume
VOLUME ["/app/data"]

ENV DATABASE_URL=sqlite:////app/data/nessus_remediation.db

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
