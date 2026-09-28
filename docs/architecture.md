# MoonDNS 架构

MoonDNS 将 DNS 协议处理和系统 I/O 分开放置。协议核心可用于 Native 与 Wasm；Native 命令通过 `moonbitlang/async` 访问文件和 socket。

```text
                    ┌────────────────────────────┐
                    │ cmd/moondns (Native only)  │
                    │ CLI / Zone file / UDP+TCP  │
                    └──────────────┬─────────────┘
                                   │ Bytes
                                   ▼
┌────────────────────────────────────────────────────────────────┐
│ src/transport: handle_dns_packet、DnsServer、TCP 长度帧辅助函数 │
└───────────────────────────────┬────────────────────────────────┘
                                │
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
       src/codec           src/resolver          src/zone
     Wire 编解码        权威应答与截断        Zone 解析/查找
             └──────────────────┼──────────────────┘
                                ▼
            src/types / records / compression / domain

cmd/main 保持为 Wasm/WASI 可构建的内存管道演示，不引入 Native socket 包。
```

## 请求路径

1. Native UDP listener 接收一个数据报，Native TCP listener 精确读取两字节长度前缀和对应 DNS payload。
2. CLI 适配层把完整 DNS 字节交给 `DnsServer::process_udp` 或 `DnsServer::process_tcp`。
3. `src/transport` 调用 wire decoder、权威 resolver 与 response truncation，然后返回响应字节。
4. Native adapter 将 UDP 响应发回来源地址，或按 TCP 长度帧写回当前连接。

TCP 连接可连续处理多帧。零长度 TCP 帧会关闭该客户端连接。UDP 单个畸形报文返回解析错误并被丢弃，listener 继续处理后续报文。

## 边界

- `src/` 的协议和 Zone 包不直接执行文件或网络 I/O。
- `cmd/moondns` 使用 `moonbitlang/async@0.22.1` 的 Native fs/socket API；因此整个服务二进制不是 Zero-FFI。
- `cmd/main` 仅演示内存请求管道，不能监听 UDP/TCP。
- Zone parser 支持范围见 [scope.md](scope.md)。
- socket 服务目前不实现递归解析、DNSSEC、动态 Zone 热加载或连接级速率限制。
