<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

</div>

# NEXTTRACE WEB

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
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb
# 使用 http://your_ip:30080 访问
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

