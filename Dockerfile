FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN https_proxy=${HTTPS_PROXY:-$HTTP_PROXY} http_proxy=${HTTP_PROXY:-$HTTPS_PROXY} \
    apt-get update && \
    https_proxy=${HTTPS_PROXY:-$HTTP_PROXY} http_proxy=${HTTP_PROXY:-$HTTPS_PROXY} \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN https_proxy=${HTTPS_PROXY:-$HTTP_PROXY} http_proxy=${HTTP_PROXY:-$HTTPS_PROXY} \
    pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY vt_tools.py init.py ./

EXPOSE 8080

CMD ["python", "vt_tools.py", "--help"]
