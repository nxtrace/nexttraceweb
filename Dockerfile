ARG NEXTTRACE_RELEASE_TAG=v1.7.6
ARG NEXTTRACE_ASSET_PREFIX=ntr

FROM python:3.14-slim

ARG TARGETOS
ARG TARGETARCH
ARG NEXTTRACE_RELEASE_TAG
ARG NEXTTRACE_ASSET_PREFIX
ARG NEXTTRACE_SHA256

ENV NTWA_NEXTTRACE_FLAVOR=${NEXTTRACE_ASSET_PREFIX} \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends nginx ca-certificates procps libcap2-bin apache2-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt && \
    python -m pip check && \
    python -m pip uninstall -y pip && \
    rm -rf /usr/local/lib/python3.14/ensurepip /tmp/requirements.txt

COPY docker/download_nexttrace.py /tmp/download_nexttrace.py
COPY docker/nexttrace-checksums.json /tmp/nexttrace-checksums.json
RUN python /tmp/download_nexttrace.py && \
    test -x /usr/local/bin/nexttrace && \
    setcap cap_net_raw=ep /usr/local/bin/nexttrace && \
    rm /tmp/download_nexttrace.py /tmp/nexttrace-checksums.json

RUN useradd --system --uid 10001 --no-create-home ntwa && \
    mkdir -p /etc/nexttrace && \
    printf 'ptrPath: /etc/nexttrace/ptr.csv\ngeoFeedPath: /etc/nexttrace/geofeed.csv\n' > /etc/nexttrace/nt_config.yaml

WORKDIR /app
COPY app.py /app/app.py
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY ntwa /app/ntwa
COPY nexttrace_mtr.py /app/nexttrace_mtr.py
COPY templates /app/templates
COPY assets /app/assets
COPY entrypoint.sh /app/entrypoint.sh
COPY docker/configure.py docker/healthcheck.py docker/supervise.sh /app/docker/
COPY nginx.conf /etc/nginx/nginx.conf.template

RUN chmod +x /app/entrypoint.sh

USER ntwa

EXPOSE 30080 30443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "/app/docker/healthcheck.py"]

ENTRYPOINT ["/app/entrypoint.sh"]
