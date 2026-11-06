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
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 使用 http://127.0.0.1:30080 访问
```
若要使用其他地址和端口，请在docker run时加入参数
```bash
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# 监听127.0.0.1:30080
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb 8080
# 监听所有IP的8080端口
docker run --network host -d --cap-drop ALL --cap-add NET_RAW --name ntwa tsosc/nexttraceweb [::1]:30080
# 监听[::1]:30080
```

公开部署请启用下文的公开模式并使用 HTTPS 反代；受限访问可在外层网关配置认证。

## 界面语言

界面已支持英文和简体中文。页头的语言选择器默认为 **跟随系统**，即按浏览器的 `Accept-Language` 自动选择；也可以固定为 `English` 或 `中文`。选择结果保存在 `localStorage` 的 `uiLanguage` 中。

设置抽屉里的 **地理数据语言** 是另一回事——它会直接传给 `nexttrace`，只影响地理位置数据的语言，不影响界面语言。

## 二级路径部署

静态资源、`/api/devices` 接口以及任务 HTTP/SSE 的路径都基于当前页面所在目录做相对解析，因此可以部署在二级路径下。外层反代需要**剥离路径前缀**（注意 `location` 和 `proxy_pass` 都要带结尾斜杠），并为不带结尾斜杠的地址加上跳转：

```nginx
# 放在 server 块中，把 https://example.com/tools/nexttrace/ 映射到容器根路径：
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

## 公开 Looking Glass

设置 `NTWA_PUBLIC_MODE=true` 开启服务端公开策略，默认关闭。页面样式不变；普通模式继续支持原有参数和已保存的 40ms 间隔。公开模式对超限参数明确报错，不会静默修改用户请求。

| 限制 | 公开模式 |
| --- | --- |
| 目标 | 仅公网单播；拒绝本机、内网、特殊及 IPv6 过渡地址 |
| 任务 | 全局最多 4 个，每会话和每 IPv4／IPv6 `/64` 最多 1 个 |
| 时长 | 最长 120 秒；原有 30 秒失联回收继续生效 |
| 探测 | 同一跳间隔至少 1 秒，最多 30 跳，包大小最多 512 字节 |
| 总预算 | 按 TTL 范围与间隔计算，最多预留 120 次探测／秒；不是出口整形 |
| 创建 | 每客户端和每目标每 10 秒补充一次，允许突发 2 次；保留请求去重 |
| SSE | 每任务 2 个、每客户端 4 个、全局 32 个订阅；重连不创建新任务 |
| 解析 | 每客户端 1 个、全局 4 个并发；结果最多 16 个地址 |
| 数据 | 请求最多 8 KiB；终态保留 5 分钟且最多 256 条；输出有长度上限 |

以下变量为管理员配置，客户端不能覆盖：

- `NTWA_SECRET_KEY`：至少 32 字符的随机密钥，例如使用 `openssl rand -hex 32` 生成；公开模式缺失时拒绝启动。
- `NTWA_TRUSTED_HOSTS`：允许的域名，逗号分隔；公开模式必须配置。
- `NTWA_SESSION_COOKIE_SECURE`：公开模式默认 `true`，需由外层代理提供 HTTPS；仅本地 HTTP 测试可显式设为 `false`。
- `NTWA_TRUSTED_PROXIES`：外层反代的准确 IP/CIDR，默认不信任外部代理头。同机反代可设置 `127.0.0.1/32,::1/128`。反代必须覆盖 `X-Forwarded-For`、`X-Forwarded-Proto`，见上面的二级路径示例；不要信任任意来源。
- `NTWA_PUBLIC_DENY_CIDRS`：额外禁止的管理网段或公网地址，逗号分隔。目标限制不影响结果中内网中间跳点的显示。
- `NTWA_PUBLIC_DEVICE`：固定出口网卡，默认使用系统路由；公开接口不再枚举主机网卡。
- `NTWA_PUBLIC_TCP_PORTS`：默认 `80,443`；`NTWA_PUBLIC_UDP_PORTS`：默认 `80,443,33494`。缺省使用列表第一项；ICMP 忽略页面端口字段。

已有全局并发、最大时长配置可以进一步收紧公开限制。保持单 Gunicorn worker；内存配额不适用于多个独立实例共享限额的场景。公开健康检查仅返回健康状态，原生错误详情不向访客披露，子进程只继承必要运行环境。

镜像以非 root 用户运行，只有 NextTrace 文件具备 `NET_RAW` 能力。默认固定 v1.7.5 并校验仓库内的 SHA256；自定义版本使用 GitHub 发布摘要或显式传入构建参数 `NEXTTRACE_SHA256`，缺失或不匹配则构建失败。

准备仅管理员可读的 `.env.public` 后，在专用探测节点运行：

```bash
docker run -d --name ntwa --network host \
  --cap-drop ALL --cap-add NET_RAW \
  --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m \
  --memory 512m --cpus 1 --pids-limit 128 \
  --ulimit nofile=1024:1024 \
  --log-driver local --log-opt max-size=10m --log-opt max-file=3 \
  --env-file .env.public tsosc/nexttraceweb 127.0.0.1:30080
```

外层 HTTPS 代理需关闭 SSE 缓冲，读超时至少 25 秒。不要使用 `--privileged`；文件能力需要允许 NextTrace 获得 `NET_RAW`，不能同时开启会阻止该能力的 `no-new-privileges`。host 网络保留探测路由语义，隔离依赖专用节点及管理员配置的出口防火墙；IPv4/IPv6 均需阻止访问管理和本机网络，并保留 DNS、地理数据查询及 ICMP 回包所需流量。应用配额不能代替上游 DDoS 防护。

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
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:30080;
    }
}
```

## 任务通信

要求支持 `--mtr --json` 的 NextTrace v1.7.5 或后续兼容版本。HTTP 创建和停止任务，SSE 发送完整统计快照；刷新后根据 sessionStorage 续接任务。页面每 10 秒续租，连续 30 秒未续租停止任务；终态任务及请求去重记录保留 5 分钟。继续使用单个 Gunicorn gevent worker，任务仅保存在内存中，服务重启后不恢复。新配置默认同一跳两次发送相隔 1 秒，各跳独立推进；已有间隔保持原样。页面显示与执行参数使用同一有效配置。

Docker 构建会将 `NEXTTRACE_ASSET_PREFIX` 记为 `NTWA_NEXTTRACE_FLAVOR`：MTR 专用的 `ntr` 使用 `--json`，`nexttrace` 与 `nexttrace-tiny` 使用 `--mtr --json`。Docker 外自定义二进制时按实际 flavor 设置该变量，默认 `nexttrace`。
