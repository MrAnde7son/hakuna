FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir \
        flask==3.0.0 \
        requests==2.32.3 \
        pymongo==4.10.1 \
        PyJWT==2.9.0 \
        PyMySQL==1.1.1
WORKDIR /app
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
