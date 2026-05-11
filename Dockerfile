ARG NEXTTRACE_RELEASE_TAG=latest
ARG NEXTTRACE_ASSET_PREFIX=ntr

FROM python:3.14-slim

ARG TARGETOS
ARG TARGETARCH
ARG NEXTTRACE_RELEASE_TAG
ARG NEXTTRACE_ASSET_PREFIX

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends nginx ca-certificates procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY docker/download_nexttrace.py /tmp/download_nexttrace.py
RUN python /tmp/download_nexttrace.py && \
    test -x /usr/local/bin/nexttrace && \
    rm /tmp/download_nexttrace.py

WORKDIR /app
COPY app.py /app/app.py
COPY nexttrace_mtr.py /app/nexttrace_mtr.py
COPY templates /app/templates
COPY assets /app/assets
COPY entrypoint.sh /app/entrypoint.sh
COPY nginx.conf /etc/nginx/nginx.conf.template

RUN chmod +x /app/entrypoint.sh

EXPOSE 30080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys, urllib.request; \
response = urllib.request.urlopen('http://127.0.0.1:30080/healthz', timeout=4); \
sys.exit(0 if response.status == 200 else 1)"

ENTRYPOINT ["/app/entrypoint.sh"]
