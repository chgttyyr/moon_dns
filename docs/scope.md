# MoonDNS 规范范围与非目标界定 (Specification & Scope)

本文档明确定义 **MoonDNS (`chgttyyr/moon_dns`)** 遵循的 RFC 规范范围与明确界定的非目标。

---

## 1. 遵循的标准规范 (In-Scope RFC Standards)

MoonDNS 聚焦于**权威 DNS 服务端核心标准**，支持以下 RFC 规范子集：

### RFC 1035: Domain Names - Implementation and Specification
* **报文二进制格式**：
  - 12 字节固定 Header（ID, QR, Opcode, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT）；
  - Question Section（QNAME, QTYPE, QCLASS）；
  - Resource Record Section（NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA）。
* **域名与指针压缩**：
  - 长度前缀变长 Label 格式（每个 Label 1 字节长度 + 最长 63 字节内容）；
  - 结尾零长度根 Label；
  - 2 字节压缩指针（高 2 位为 `11`，低 14 位为报文绝对偏移）；
  - 四重恶意指针循环与越界安全拦截。
* **权威语义逻辑**：
  - `AA=1` 权威标志位显式置位；
  - `RA=0`（不支持递归标志）；
  - `NXDOMAIN` (RCODE=3, Name Error)：请求域名在区内不存在，必须在 Authority Section 附带该 Zone 的 SOA 记录；
  - `NODATA` (RCODE=0, ANCOUNT=0)：请求域名存在，但无对应 QTYPE，必须在 Authority Section 附带 SOA 记录；
  - ASCII 大小写不敏感（Case-insensitive）比较；
  - UDP 512 字节截断（`TC=1` 且精准丢弃尾部记录）。
* **核心记录类型 (Resource Records)**：
  - `A` (1)：IPv4 地址；
  - `NS` (2)：权威域名服务器名称；
  - `CNAME` (5)：规范别名；
  - `SOA` (6)：区域起始授权参数；
  - `PTR` (12)：指针记录；
  - `MX` (15)：邮件交换（Preference + 域名）；
  - `TXT` (16)：文本字符串（支持多块连续 character-string 编码）；
  - `AAAA` (28)：IPv6 地址；
  - `SRV` (33)：服务定位记录；
  - `CAA` (257)：证书颁发机构授权。

### RFC 6891: Extension Mechanisms for DNS (EDNS(0))
* `OPT` (41) 伪记录编解码；
* 客户端请求缓冲区大小协商（UDP Payload Size）；
* 扩展 RCODE 高位与版本号处理；
* 避免因 512 字节传统限制造成的非必要截断。

---

## 2. 明确界定的非目标 (Explicit Non-Goals)

为了确保项目的纯粹性、极高完成度与严苛的代码质量，本项目**明确不包含**以下特性：

1. **递归解析服务 (Recursive Resolver)**：
   - 本服务是纯粹的**权威 DNS 服务器**（只对自己托管的 Zone 提供应答，不向上游根域名服务器递归迭代）。
2. **DNSSEC 动态数字签名 (RFC 4033 / 4034 / 4035)**：
   - 不进行实时的 RRSIG 密钥计算与签名验证（可作为后续版本规划）。
3. **动态 DNS 更新 (RFC 2136 Dynamic Update)**：
   - 采用标准静态配置加载与内存热重载，不开放网络动态写接口。
4. **完整 AXFR/IXFR 区传送协议 (Zone Transfer)**：
   - 收到 AXFR/IXFR 请求时，安全返回 REFUSED (RCODE=5) 或 NOTIMP (RCODE=4) 错误码，不执行真实的主从同步流。
5. **DoH / DoT 加密传输终端**：
   - 本项目传输层提供原生的 UDP 53 与 TCP 53；加密传输（TLS/HTTPS）建议由外部专用网关（如 Envoy / Cloudflare / NGINX）或独立的专用 Wasm 适配器完成。
