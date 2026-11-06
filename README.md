<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

# NEXTTRACE WEB

A lightweight web API server for NextTrace — run visual traceroutes from your browser.

<div align="center">

[![Docker Pulls](https://img.shields.io/docker/pulls/tsosc/nexttraceweb)](https://hub.docker.com/r/tsosc/nexttraceweb)
[![License](https://img.shields.io/github/license/nxtrace/nexttraceweb)](LICENSE)

[中文](README.zh-CN.md) | **English**

</div>

</div>

---

<img width="1440" alt="NextTrace Web Interface" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/798554e2-190e-4425-9527-3a11708dafd8">

<p align="center">
  <img width="443" alt="IP Selection Dialog" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/1eb4b6ce-3ed9-4728-be85-fbdabc5803bd">
  <img width="721" alt="Traceroute Results" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/a0563bfc-37a8-417a-89bf-3ab87ef44d6d">
</p>

---

## Overview

NextTrace Web is a spin-off of the [NextTrace](https://github.com/nxtrace/NTrace-core) project. It provides a simple web frontend and API server so you can run traceroutes and visualize results — including hop, IP, ASN, geolocation, domain, packet loss, and latency stats — entirely from your browser.

> **Reverse proxy note:** Task control uses HTTP; results use SSE. Disable proxy buffering. The Docker image includes this configuration.

*Inspired by [PING.PE](https://ping.pe) — thanks for years of keeping that service alive and giving the community such a great reference.*

---

## How To Use

### Docker (Recommended)

```bash
docker pull tsosc/nexttraceweb
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# Visit http://127.0.0.1:30080
```

Expose the service to the Internet through your own reverse proxy or gateway. This project does not ship an in-app login flow.

### Custom Address & Port

Pass an address/port argument to `docker run` to override the default:

```bash
# Bind to localhost only
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 127.0.0.1:30080

# Listen on all IPs, port 8080
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 8080

# Listen on IPv6 loopback
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb [::1]:30080
```

## Interface Language

The UI ships English and Simplified Chinese. The selector in the page header defaults to **Auto**, which follows the browser's `Accept-Language` preference; pick `English` or `中文` to pin one. The choice is stored in `localStorage` under `uiLanguage`.

The separate **Geo Data Language** option inside the settings drawer is unrelated — it is passed straight to `nexttrace` and controls the language of geolocation data, not the interface.

## Sub-path Deployment

All assets, the `/api/devices` endpoint, and task HTTP/SSE endpoints are resolved relative to the page's own directory, so the app can be mounted under a sub-path. The outer proxy must **strip the prefix** (note the trailing slash on both `location` and `proxy_pass`) and redirect the prefix without a trailing slash:

```nginx
# In the server block. https://example.com/tools/nexttrace/ maps to the container root:
location = /tools/nexttrace {
    return 301 /tools/nexttrace/$is_args$args;
}

location /tools/nexttrace/ {
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_pass http://127.0.0.1:30080/;
}
```

Both trailing slashes matter. Drop the one on `proxy_pass` and the backend receives `/tools/nexttrace/...`, for which it has no route. The 301 covers visitors who leave the trailing slash out of the address bar: the browser resolves relative references against the parent directory, so the assets would be fetched from `/tools/assets/...` and the page would render unstyled.

## Runtime Notes

- Health endpoint: `GET /healthz`
- The container now exits when `gunicorn` or `nginx` dies, so supervisors can restart it instead of leaving a half-dead process tree behind.
- `nexttrace_error` is now a structured payload with `code` and `message`, plus `retry_after_seconds` on rate-limit and capacity rejections.

## Security Defaults

- Configure `NTWA_SECRET_KEY` in production. If omitted, the app generates a temporary random key and logs a warning.
- Recommended: set `NTWA_TRUSTED_HOSTS=trace.example.com` behind a reverse proxy.
- Set `NTWA_SESSION_COOKIE_SECURE=true` only when the outer proxy serves HTTPS.
- Abuse controls:
  - `NTWA_MIN_START_INTERVAL_SECONDS`
  - `NTWA_MAX_ACTIVE_TRACES`
  - `NTWA_TRACE_IDLE_TIMEOUT_SECONDS`
  - `NTWA_TRACE_MAX_DURATION_SECONDS`

## Public Looking Glass

Set `NTWA_PUBLIC_MODE=true` to enable the server-side public policy (off by default). The page remains unchanged. Normal mode retains existing settings, including saved 40ms intervals. Public mode rejects excessive settings instead of silently changing requests.

| Limit | Public mode |
| --- | --- |
| Targets | Public unicast only; blocks local, private, special and IPv6 transition addresses |
| Tasks | At most 4 globally, 1 per session and per IPv4 / IPv6 `/64` |
| Duration | At most 120 seconds; the existing 30-second orphan lease still applies |
| Probes | At least 1 second per hop, at most 30 hops and 512-byte packets |
| Budget | At most 120 reserved probes/second from TTL span and interval; not egress shaping |
| Creation | One token per client and target every 10 seconds, burst 2; retries remain idempotent |
| SSE | 2 subscriptions per task, 4 per client, 32 globally; reconnects reuse the task |
| Resolution | 1 concurrent request per client, 4 globally; at most 16 candidate addresses |
| Data | 8 KiB request bodies; terminal retention of 5 minutes and at most 256 records; bounded output |

Administrator-only configuration:

- `NTWA_SECRET_KEY`: a random secret of at least 32 characters, e.g. generated by `openssl rand -hex 32`. Public mode refuses startup without it.
- `NTWA_TRUSTED_HOSTS`: comma-separated allowed hostnames, required in public mode.
- `NTWA_SESSION_COOKIE_SECURE`: defaults to `true` in public mode and requires an outer HTTPS proxy. Explicit `false` is for local HTTP tests.
- `NTWA_TRUSTED_PROXIES`: exact outer proxy IPs/CIDRs; no external proxy headers are trusted by default. Use `127.0.0.1/32,::1/128` for a same-host proxy. It must overwrite `X-Forwarded-For` and `X-Forwarded-Proto`, as in the sub-path example above. Never trust arbitrary sources.
- `NTWA_PUBLIC_DENY_CIDRS`: additional blocked management ranges or public addresses. Private intermediate hops remain visible in results.
- `NTWA_PUBLIC_DEVICE`: fixed outbound interface; defaults to system routing. The public devices endpoint no longer enumerates host interfaces.
- `NTWA_PUBLIC_TCP_PORTS`: defaults to `80,443`; `NTWA_PUBLIC_UDP_PORTS`: defaults to `80,443,33494`. The first entry is used when omitted. ICMP ignores the page's port field.

Existing concurrency/duration options can tighten public limits further. Keep one Gunicorn worker; in-memory quotas are not shared across independent instances. Public health responses expose only status, native error details stay private, and children inherit only necessary runtime configuration.

The image runs as a non-root user; only the NextTrace executable has `NET_RAW` file capability. The default v1.7.5 download is checked against committed SHA256 values. Custom releases use GitHub release digests or the `NEXTTRACE_SHA256` build argument; missing/mismatched checksums fail the build.

After preparing an administrator-readable `.env.public`, run on a dedicated probe node:

```bash
docker run -d --name ntwa --network host \
  --cap-drop ALL --cap-add NET_RAW \
  --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m \
  --memory 512m --cpus 1 --pids-limit 128 \
  --ulimit nofile=1024:1024 \
  --log-driver local --log-opt max-size=10m --log-opt max-file=3 \
  --env-file .env.public tsosc/nexttraceweb 127.0.0.1:30080
```

The outer HTTPS proxy must disable SSE buffering and allow at least 25 seconds between reads. Do not use `--privileged`. File capabilities must allow NextTrace to gain `NET_RAW`; a `no-new-privileges` setting that prevents this will break probing. Host networking preserves probe routing; use a dedicated node and administrator-managed IPv4/IPv6 egress rules to block management/local networks while retaining required DNS, GeoIP and ICMP reply traffic. Application quotas do not replace upstream DDoS protection.

## External Auth Example

Minimal Nginx example with Basic Auth in front of the container:

```nginx
server {
    listen 443 ssl http2;
    server_name trace.example.com;

    auth_basic "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:30080;
    }
}
```

## Task transport

NextTrace v1.7.5+ with `--mtr --json` is required. Task creation and stop use HTTP; SSE sends full statistics snapshots. Refresh resumes the task stored in sessionStorage. Pages renew the lease every 10 seconds; tasks stop after 30 seconds without renewal. Finished tasks and request deduplication records expire after 5 minutes. Use one Gunicorn gevent worker; task state is in memory and is lost on service restart. New settings default to a 1-second interval between sends to the same TTL; saved intervals remain unchanged. Browser display and CLI arguments use the same effective settings.

The Docker build records `NEXTTRACE_ASSET_PREFIX` as `NTWA_NEXTTRACE_FLAVOR`: `ntr` uses `--json` because it is MTR-only; `nexttrace` and `nexttrace-tiny` use `--mtr --json`. For a custom native binary outside Docker, set `NTWA_NEXTTRACE_FLAVOR` to its flavor (default: `nexttrace`).
