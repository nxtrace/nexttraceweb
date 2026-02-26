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

> **Reverse proxy note:** This project uses WebSocket as its communication protocol. If you configure a reverse proxy, please refer to the Nginx config included in this repository. The provided Docker image already has Nginx reverse proxy built in.

*Inspired by [PING.PE](https://ping.pe) — thanks for years of keeping that service alive and giving the community such a great reference.*

---

## How To Use

### Docker (Recommended)

```bash
docker pull tsosc/nexttraceweb
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb
# Visit http://your_ip:30080
```

### Custom Address & Port

Pass an address/port argument to `docker run` to override the default:

```bash
# Bind to localhost only
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080

# Listen on all IPs, port 80
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 80

# Listen on IPv6 loopback
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb [::1]:30080
```