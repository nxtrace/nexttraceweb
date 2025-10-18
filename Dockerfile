FROM golang:1.25-alpine3.21 AS builder

# 安装所需的软件包
RUN apk update && apk add --no-cache git

# 克隆NEXTTRACE源代码并编译（内联计算版本信息并注入到 -ldflags）
WORKDIR /build
RUN set -eux; \
    git clone https://github.com/nxtrace/Ntrace-core.git . ; \
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

# 安装所需的软件包
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3-pip nginx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 安装Python依赖包
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# 从构建阶段复制NEXTTRACE二进制文件到最终镜像
COPY --from=builder /build/nexttrace /usr/local/bin/nexttrace
RUN chmod +x /usr/local/bin/nexttrace

# 复制应用程序文件
COPY app.py /app/app.py

# 复制templates和assets文件夹
COPY templates /app/templates
COPY assets /app/assets

# 配置Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# 设置工作目录
WORKDIR /app

# Copy start.sh to the container
COPY entrypoint.sh /app/entrypoint.sh

EXPOSE 30080

# 设置脚本作为入口点
ENTRYPOINT ["/app/entrypoint.sh"]
