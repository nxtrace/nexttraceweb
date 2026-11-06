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




任务控制使用 HTTP，结果使用 SSE。反代需关闭缓冲（`proxy_buffering off`）；Docker 镜像已内置该配置。

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

## 界面语言

界面已支持英文和简体中文。页头的语言选择器默认为 **跟随系统**，即按浏览器的 `Accept-Language` 自动选择；也可以固定为 `English` 或 `中文`。选择结果保存在 `localStorage` 的 `uiLanguage` 中。

设置抽屉里的 **地理数据语言** 是另一回事——它会直接传给 `nexttrace`，只影响地理位置数据的语言，不影响界面语言。

## 二级路径部署

静态资源、`/api/devices` 接口以及 Socket.IO 的路径都基于当前页面所在目录做相对解析，因此可以部署在二级路径下。外层反代需要**剥离路径前缀**（注意 `location` 和 `proxy_pass` 都要带结尾斜杠），并为不带结尾斜杠的地址加上跳转：

```nginx
# 放在 http 块中，$connection_upgrade 不是 nginx 内置变量：
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# 放在 server 块中，把 https://example.com/tools/nexttrace/ 映射到容器根路径：
location = /tools/nexttrace {
    return 301 /tools/nexttrace/$is_args$args;
}

location /tools/nexttrace/ {
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_pass http://127.0.0.1:30080/;
}
```

两处结尾斜杠都很关键。漏掉 `proxy_pass` 上的那个，后端就会收到 `/tools/nexttrace/...`，没有对应路由。那条 301 用于兜住地址栏里漏掉结尾斜杠的用户：此时浏览器会把相对引用解析到上一级目录，资源会被请求到 `/tools/assets/...`，页面会失去样式。

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
        proxy_buffering off;
        proxy_pass http://127.0.0.1:30080;
    }
}
```

## 任务通信

要求支持 `--mtr --json` 的 NextTrace v1.7.5 或后续兼容版本。HTTP 创建和停止任务，SSE 发送完整统计快照；刷新后根据 sessionStorage 续接任务。页面每 10 秒续租，连续 30 秒未续租停止任务；终态任务及请求去重记录保留 5 分钟。继续使用单个 Gunicorn gevent worker，任务仅保存在内存中，服务重启后不恢复。新配置默认同一跳两次发送相隔 1 秒，各跳独立推进；已有间隔保持原样。页面显示与执行参数使用同一有效配置。

Docker 构建会将 `NEXTTRACE_ASSET_PREFIX` 记为 `NTWA_NEXTTRACE_FLAVOR`：MTR 专用的 `ntr` 使用 `--json`，`nexttrace` 与 `nexttrace-tiny` 使用 `--mtr --json`。Docker 外自定义二进制时按实际 flavor 设置该变量，默认 `nexttrace`。
