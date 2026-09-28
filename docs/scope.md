# MoonDNS 范围

本文说明 MoonDNS 当前实现与明确不支持的功能，以便示例、CLI 和测试按同一边界验收。

## DNS 协议能力

- DNS Header、Question 和 Resource Record 的 wire 编解码；
- A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、CAA 记录 RDATA；
- EDNS0 OPT 解析、UDP payload 上限协商及应答截断；
- 权威应答、通配符查找、CNAME 追踪、NXDOMAIN 与 NODATA；
- Native UDP/TCP 服务及 UDP 查询 CLI；
- Wasm/WASI 内存协议演示，不包含 Wasm 网络监听。

## Zone master-file 子集

支持 `$ORIGIN`、`$TTL`、`@`、分号注释、双引号 TXT 字符串、圆括号包裹的多行记录、空 owner 续接前一条记录、相对和绝对域名。TTL 接受十进制秒及 `w`、`d`、`h`、`m`、`s` 单位组合；省略 class 时默认为 `IN`，显式 class 仅支持 `IN`。

相对 `$ORIGIN` 按当前 origin 解析；文件内 `$ORIGIN` 只改变后续相对名称的展开上下文。`parse_zone_text(initial_origin, text)` 的 `Zone.origin` 始终等于规范化后的 `initial_origin`，作为权威 apex。

Zone parser 对 A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、CAA 产生类型化 RDATA。固定字段的数量和整数范围会校验；解析错误包含逻辑记录起始行号。`check` 与 `serve` 进一步要求且仅要求一个 apex SOA、至少一个 apex NS、owner 在 Zone 边界内、CNAME owner 不与其他 RR 类型共存。

未实现 `$INCLUDE`、通用宏、所有字符转义、任意 owner 名称转义和 RFC 3597 泛型 RDATA；此类语法不视作受支持输入。

## 明确不支持

- 递归 resolver、上游转发与缓存；
- DNSSEC 签名或验证；
- 动态 DNS 更新、AXFR/IXFR 和热加载；
- DoH、DoT、QUIC 等加密或新传输协议；
- 多租户、管理 API、持久化记录库或服务发现。

以上项目不属于当前验收范围，不在文档中作为已经实现的特性描述。
