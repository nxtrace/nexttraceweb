FROM golang:1.25-alpine3.21 AS builder

RUN apk update && apk add --no-cache git

WORKDIR /build
RUN set -eux; \
    git clone https://github.com/nxtrace/Ntrace-core.git .; \
    go clean -modcache; \
    go mod download; \
    BUILD_VERSION="$(git describe --tags --always 2>/dev/null || true)"; \
    [ -n "$BUILD_VERSION" ] || BUILD_VERSION=dev; \
    BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"; \
    COMMIT_SHA1="$(git rev-parse --short HEAD 2>/dev/null || true)"; \
    [ -n "$COMMIT_SHA1" ] || COMMIT_SHA1=unknown; \
    LD_PKG="$(go list -m)/config"; \
    LD_BASE="-X ${LD_PKG}.Version=${BUILD_VERSION} \
             -X ${LD_PKG}.BuildDate=${BUILD_DATE} \
             -X ${LD_PKG}.CommitID=${COMMIT_SHA1} \
             -w -s -checklinkname=0"; \
    go build -trimpath -ldflags "${LD_BASE}" -o nexttrace .

FROM ubuntu:22.04

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends python3 python3-pip nginx ca-certificates procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

COPY --from=builder /build/nexttrace /usr/local/bin/nexttrace
RUN chmod +x /usr/local/bin/nexttrace

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
    CMD python3 -c "import sys, urllib.request; \
response = urllib.request.urlopen('http://127.0.0.1:30080/healthz', timeout=4); \
sys.exit(0 if response.status == 200 else 1)"

ENTRYPOINT ["/app/entrypoint.sh"]
