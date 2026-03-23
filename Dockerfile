ARG NEXTTRACE_RELEASE_TAG=latest
ARG NEXTTRACE_ASSET_PREFIX=ntr

FROM ubuntu:22.04

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG NEXTTRACE_RELEASE_TAG
ARG NEXTTRACE_ASSET_PREFIX

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends python3 python3-pip nginx ca-certificates procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

RUN python3 - <<'PY'
import os
import stat
import urllib.request

target_os = os.environ["TARGETOS"]
target_arch = os.environ["TARGETARCH"]
asset_prefix = os.environ["NEXTTRACE_ASSET_PREFIX"]
release_tag = os.environ["NEXTTRACE_RELEASE_TAG"]

asset_map = {
    ("linux", "amd64"): f"{asset_prefix}_linux_amd64",
    ("linux", "arm64"): f"{asset_prefix}_linux_arm64",
}

asset_name = asset_map.get((target_os, target_arch))
if not asset_name:
    raise SystemExit(f"Unsupported platform: {target_os}/{target_arch}")

release_path = "latest/download" if release_tag == "latest" else f"download/{release_tag}"
url = f"https://github.com/nxtrace/NTrace-core/releases/{release_path}/{asset_name}"
destination = "/usr/local/bin/nexttrace"

with urllib.request.urlopen(url) as response, open(destination, "wb") as output:
    output.write(response.read())

os.chmod(destination, os.stat(destination).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY

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
