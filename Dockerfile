FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

ENV https_proxy=${HTTPS_PROXY:-$HTTP_PROXY}
ENV http_proxy=${HTTP_PROXY:-$HTTPS_PROXY}

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY vt_tools.py init.py ./

EXPOSE 8080

CMD ["python", "vt_tools.py", "--help"]
