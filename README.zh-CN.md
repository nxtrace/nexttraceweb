<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

</div>

# NEXTTRACE WEB

<div align="center">

**中文** | [English](README.md)

</div>

NEXTTRACE项目派生的仓库，用于实现简易的NEXTTRACE WEB API服务端

<img width="1440" alt="截屏2023-06-12 00 24 06" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/798554e2-190e-4425-9527-3a11708dafd8">
<p align="center">
  <img width="443" alt="截屏2023-06-12 00 12 57" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/1eb4b6ce-3ed9-4728-be85-fbdabc5803bd">
  <img width="721" alt="截屏2023-06-12 00 26 22" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/a0563bfc-37a8-417a-89bf-3ab87ef44d6d">
</p>




请注意，本项目使用了websocket作为通信协议，因此请在配置反代时参考仓库内的代码(本仓库提供的Docker Image 已内置 Nginx 反代)。

Inspired by PING.PE

感谢PING.PE这么多年来的坚持，让我们能够在这个时候有一个这么好的项目可以参考

## How To Use

推荐使用Docker安装
```bash
docker pull tsosc/nexttraceweb
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 使用 http://127.0.0.1:30080 访问
```
若要使用其他地址和端口，请在docker run时加入参数
```bash
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 监听127.0.0.1:30080
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 80
# 监听所有IP的80端口
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb [::1]:30080
# 监听[::1]:30080
```

建议不要直接把服务裸露在公网，认证和访问控制请放在外层反代或网关上处理。

## 运行时说明

- 健康检查接口：`GET /healthz`
- 容器现在会在 `gunicorn` 或 `nginx` 任一核心进程退出时整体退出，便于外部 supervisor 正常拉起，而不是留下“容器还活着、服务已经死了”的假活状态。
- `nexttrace_error` 现在是结构化载荷，至少包含 `code` 和 `message`；限流/容量拒绝还会带 `retry_after_seconds`。

## 安全相关环境变量

- `NTWA_SECRET_KEY`
- `NTWA_TRUSTED_HOSTS`
- `NTWA_SESSION_COOKIE_SECURE`
- `NTWA_MIN_START_INTERVAL_SECONDS`
- `NTWA_MAX_ACTIVE_TRACES`
- `NTWA_TRACE_IDLE_TIMEOUT_SECONDS`
- `NTWA_TRACE_MAX_DURATION_SECONDS`

生产环境请显式配置 `NTWA_SECRET_KEY`。如果不配置，应用会生成临时随机值并打印告警。

## 外层鉴权示例

下面是一个最小 Nginx Basic Auth 反代示例：

```nginx
server {
    listen 443 ssl http2;
    server_name trace.example.com;

    auth_basic "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_pass http://127.0.0.1:30080;
    }
}
```
