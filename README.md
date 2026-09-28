# MoonDNS

MoonDNS 是基于 MoonBit 实现的权威 DNS 协议核心和 Native DNS 服务。协议编解码、Zone 查询与应答构造位于 `src/`，通过 `cmd/moondns` 提供原生 UDP/TCP 服务、UDP 查询和 Zone 检查命令。`cmd/main` 保留为可在 Wasm/WASI 上运行的内存管道演示，不监听网络端口。

## 能力范围

- 权威 DNS 查询：A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、CAA；支持通配符、CNAME 追踪、NXDOMAIN/NODATA、EDNS0 与 UDP 响应截断。
- Native 服务：在同一地址和端口监听 UDP 与 TCP；TCP 使用 RFC 1035 两字节长度帧，单个连接可连续处理多条查询，默认最多 64 个并发连接。
- Zone 检查：解析下述 master-file 子集，检查 apex SOA/NS、owner 是否位于 Zone 内，以及 CNAME 是否与其他类型共存。
- Native UDP 查询：输出响应 ID、RCODE、AA 标志及 Answer、Authority、Additional 记录。
- WebAssembly：协议核心和内存演示可以构建到 Wasm/WASI；Native socket CLI 不支持 Wasm。

`src/` 的协议核心不执行 I/O。Native CLI 通过 MoonBit 官方 `moonbitlang/async` socket 和文件 I/O 包接入系统资源；因此整个可执行程序不宣称 Zero-FFI。

## 环境

- MoonBit 工具链：项目目前使用 `0.1.20260915`。
- Node.js 20 或更高版本：运行 `scripts/verify_wasm.js` 时需要。

## 构建与验证

```bash
moon check --deny-warn
moon check --target native --deny-warn
moon build --target native
moon test --target native --deny-warn
moon test --deny-warn
moon test --target wasm
moon test --target wasm-gc
moon test --target js
moon build --target wasm
node scripts/verify_wasm.js
```

Native 回环测试覆盖坏 UDP 报文后的持续服务、分块写入的 TCP 帧、同连接多帧和零长度帧断开。CI 工作流运行严格检查、Native 构建、跨目标测试和 Wasm/WASI 验证。

## Native CLI

检查示例 Zone：

```bash
moon run --target native cmd/moondns -- check \
  -z examples/example.com.zone -o example.com.
```

启动 UDP/TCP 服务，默认监听 `127.0.0.1:5353`：

```bash
moon run --target native cmd/moondns -- serve \
  -z examples/example.com.zone -o example.com. -p 5353
```

发起 UDP 查询：

```bash
moon run --target native cmd/moondns -- query \
  -s 127.0.0.1 -p 5353 www.example.com A
```

外部 DNS 客户端也可查询 UDP 和 TCP，例如：

```bash
dig @127.0.0.1 -p 5353 www.example.com A
dig +tcp @127.0.0.1 -p 5353 www.example.com A
```

`serve` 参数：`-z/--zone`、`-o/--origin`、`--listen`、`-p/--port`、`--max-connections`。默认监听地址为 `127.0.0.1`、端口为 `5353`、并发 TCP 连接上限为 `64`。需要对外提供服务时，请明确指定监听地址和防火墙策略。

## Zone 文件支持

解析器实现一组明确的 BIND master-file 子集：

- `$ORIGIN`、`$TTL`、`@`、分号注释、双引号 TXT 字符串、括号包裹的多行记录、空 owner 续接前一条记录；
- 相对和绝对域名；相对 `$ORIGIN` 相对于当前 origin 解析，但 Zone apex 始终是命令行提供的 `--origin`；
- 十进制秒及 `w/d/h/m/s` 组合 TTL；省略 class 时默认为 `IN`，显式 class 只接受 `IN`；
- A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、CAA 的类型化 RDATA；固定字段数量和数字范围会校验，解析错误包含源行号。

解析器不实现 `$INCLUDE`、任意转义、宏处理或 RFC 3597 泛型 RDATA；遇到未支持语法或 RR 类型会拒绝该文件。完整 master-file 兼容性不在项目范围内。

## 项目布局

```text
src/                 DNS 类型、wire 编解码、安全解析、Zone 与纯应答逻辑
cmd/main/            Wasm/WASI 内存管道演示
cmd/moondns/         Native check、serve、query 命令和 socket 适配器
examples/            Zone 文件示例
scripts/              Wasm/WASI 验证脚本
docs/                 架构、范围和安全说明
```

## 规范和许可证

协议边界参见 [docs/scope.md](docs/scope.md)，实现结构参见 [docs/architecture.md](docs/architecture.md)，威胁与资源边界参见 [docs/security.md](docs/security.md)。项目按 [Apache-2.0](LICENSE) 授权。

## 项目规模

按仓库内 `.mbt` 文件物理行（包括空行）统计，测试文件按 `_test.mbt` 和 `_wbtest.mbt` 后缀识别；不含依赖缓存和构建产物：实现源码 29 个文件、4,605 行，测试源码 22 个文件、2,796 行，共 51 个文件、7,401 行。
