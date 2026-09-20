# MoonDNS (`chgttyyr/moon_dns`)

> **MoonDNS** 是使用 **100% 纯 MoonBit（Zero-FFI）** 从零实现的权威域名服务器（Authoritative DNS Server），严格遵循 RFC 1035 与 RFC 6891 (EDNS0) 规范，专为高安全性、确定性与云原生 / WebAssembly 边缘计算环境设计。

本项目由开发者 **`chgttyyr`** 进行**独立开源设计与开发**。

---

## 核心特性 (Key Features)

- **纯正原生的系统级实现 (100% Zero-FFI)**：全套协议解析、数据结构、权威语义与网络抽象全部使用 MoonBit 编写，绝无任何 C/JS 外部绑定，彻底免除 C 语言体系常见的野指针、缓冲区溢出风险。
- **工业级恶意指针防御 (Robust Pointer Guards)**：内建四重防御状态机，坚决抵御针对 DNS 压缩指针的经典 DoS 攻击（自环指针、双向交叉环、前向越界偏移、深度跳跃链）。处理任何畸形报文绝对**零 Panic、零死循环**。
- **严格合规的权威语义 (Strict RFC 1035 Semantics)**：
  - 权威应答 `AA=1` 准确置位；
  - 精确区分 `NXDOMAIN` (Name Error, RCODE=3) 与 `NODATA` (RCODE=0, ANCOUNT=0)，并在 Authority Section 携带合规的 SOA 记录；
  - 支持 ASCII 域名大小写不敏感匹配；
  - UDP 512 字节与 EDNS0 动态协商的响应报文安全截断（`TC=1`）。
- **丰富的记录类型支持**：A (1), NS (2), CNAME (5), SOA (6), PTR (12), MX (15), TXT (16, 支持多块连续字符串), AAAA (28), SRV (33), CAA (257), OPT (41, EDNS0).
- **高内聚的内存 Zone 索引**：支持带通配符 (`*.domain.com`) 索引查找、CNAME 别名安全追踪与标准 BIND Zone 文件解析。
- **协议与 I/O 深度解耦**：核心应答构建为确定性纯函数，既支持基于异步 Socket 的生产级 UDP/TCP 服务，也支持零网络依赖的内存管道测试。

---

## 生态定位与价值 (Ecosystem Positioning)

在 MoonBit 生态中，此前已有客户端解析存根（`moon-dns-stub`）与配置文件静态审计工具（`moonbit-dns-zone`），但**始终缺少核心的权威服务端实现**。

| 生态分层 | 现有开源组件 | 功能职责 |
| :--- | :--- | :--- |
| **客户端查询** | `jinshengmeng46/moon-dns-stub` | 基础客户端 Stub 递归解析 |
| **配置语法审计** | `lmclmc1/moonbit-dns-zone` | Master-file 语法静态检查 |
| **权威服务端基石** | **`chgttyyr/moon_dns` (本项目)** | **完整权威解析、防线安全机与全套 Wire 编解码** |

**MoonDNS 补齐了 MoonBit 在域名基础设施上的关键服务端空白**，使 MoonBit 具备独立托管权威解析、响应公网或局域网 DNS 请求的能力。

---

## 快速开始 (Quick Start)

### 1. 环境依赖
* [MoonBit 工具链](https://www.moonbitlang.com/download/) (v0.1.20260915 或更高版本)

### 2. 编译与检查
```bash
moon check
moon build
```

### 3. 运行全量单元测试
```bash
moon test
```

### 4. 启动权威 DNS 服务
```bash
# 监听本地 5353 端口 (UDP/TCP)
moon run cmd/main -- serve -z examples/example.com.zone -p 5353
```

### 5. 使用内置诊断工具发起查询
```bash
moon run cmd/main -- query -s 127.0.0.1 -p 5353 www.example.com A
```

---

## 项目架构 (Architecture)

```
src/
├── types/          # DNS 协议基础模型、Header, Question, Record, RData, RType, RClass
├── bytes_io/       # 边界安全的原生大端序字节读取器 (Reader) 与缓冲区写入器 (Writer)
├── domain/         # FQDN 规范化、变长 Label 序列化、ASCII 大小写不敏感比较
├── compression/    # 四重防护指针解压缩状态机与自适应压缩字典生成器
├── records/        # 10+ 种记录类型 RDATA 独立编解码器
├── zone/           # 内存 Zone 数据库、通配符匹配引擎、Zone 文本配置解析器
├── resolver/       # 纯函数权威应答构建器 (AA, NXDOMAIN, NODATA, TC 截断)
├── transport/      # 异步 UDP/TCP 服务端与内存测试管道
└── cmd/main/       # CLI 工具集 (serve, query, check)
```

---

## 安全防御体系 (Security Model)

DNS 协议最危险的脆弱点在于恶意的压缩指针（Compression Pointer Loops）。MoonDNS 在解码层部署了多重防御：
1. **环路访问集合 (Visited Offset Tracker)**：记录解包过程中所有已跳转的偏移量，遇到重复跳转立即拦截。
2. **最大跳转上限 (Max Jump Limit)**：严格将单次域名解析的指针跳转次数限制在 $\le 128$ 次，防御深度放大攻击。
3. **前向与越界校验 (Boundary Check)**：指针目标偏移必须严格落在当前报文前部已解析区域，杜绝任何未初始化内存越界。
4. **零崩溃保证**：恶意攻击输入一律安全返回 `DnsError::MalformedPointer`，绝不发生运行时 panic。

---

## 测试验证与质量指标 (Test Verification)

本项目遵循严格的测试驱动开发与黄金向量比对规范，覆盖 RFC 1035 标准语义与高危攻击面防御。所有测试通过 `moon test` 自动化运行：

| 测试组编号 | 测试套件 | 测试范围与断言 | 用例数 | 状态 |
| :--- | :--- | :--- | :---: | :---: |
| Suite 1 | **编解码黄金测试** | 给定 Wire 字节向量 -> `parse` -> `encode` -> 与原字节逐字节严格相等 | 4 | PASS |
| Suite 2 | **变长标签与域名编解码** | FQDN 规范化、大小写不敏感匹配、子域判定与边界检查 | 4 | PASS |
| Suite 3 | **恶意指针安全防御** | 自指环、双向环、越界指针、深度递归跳跃，零 Panic 零死循环拦截 | 4 | PASS |
| Suite 4 | **各记录类型 Wire 编解码** | A, AAAA, CNAME, NS, MX, TXT (多分块), SOA, PTR, SRV, CAA, OPT 往返一致性 | 10 | PASS |
| Suite 5 | **报文截断与 TC 标记** | 512 字节与 EDNS0 大小上限截断，合规置位 TC=1 并安全修剪记录 | 4 | PASS |
| Suite 6 | **权威语义与应答构建** | Exact / Wildcard / CNAME 追踪，AA=1，NXDOMAIN (RCODE=3) 与 NODATA 携带 SOA | 6 | PASS |
| Suite 7 | **传输层与 Mock 管道** | 内存管道端到端应答验证，TCP 2 字节前缀帧拆包/粘包恢复 | 4 | PASS |
| Suite 8 | **协议模糊与并发压力测试** | 20+ 随机畸变报文模糊注入与 100 节点高并发 Zone 查找稳定性 | 21 | PASS |
| **汇总** | **全量自动化测试** | **8 组测试套件全面通过，零编译警告，零运行期 Panic** | **57** | **100% 绿灯** |

---

## 源码规模与工程指标 (Codebase Scale Metrics)

| 指标维度 | 统计数值 | 说明 |
| :--- | :--- | :--- |
| **纯 MoonBit 源码 (`.mbt`)** | 4,586 行 | 覆盖协议编解码、安全防线、Zone 索引、纯函数解析器与 CLI |
| **工程总行数 (含配置与文档)** | 5,431+ 行 | 包含 8 组测试套件、规范文档及 BIND Zone 示例 |
| **外部 C/JS 绑定 (FFI)** | 0 行 (100% Zero-FFI) | 绝无任何底层外部依赖，天然契约安全与跨平台编译 |
| **自动化测试用例数** | 57 项 | 持续集成通过率 100% |

---

## 实现范围与非目标 (Scope & Non-Goals)

### 实现范围 (In-Scope)
- **权威 DNS 服务**：针对本地配置与加载的 Zone 数据提供权威解析应答；
- **全套协议编解码**：RFC 1035 / RFC 6891 Wire 格式完整支持；
- **自适应出站压缩**：构建域名后缀字典，压缩应答报文尺寸；
- **四重指针安全防护**：防越界、防自环、防交叉环、防跳跃超限；
- **双模传输与管道**：UDP/TCP 协议帧支持与零网络依赖纯内存测试管道。

### 明确非目标 (Non-Goals)
为了保持系统的高安全性、确定性与微核心轻量架构，本项目明确不实现以下特性：
- **递归解析（Recursive Resolver）**：本项目仅专注权威服务器职责，不承担公共递归查询与上游转发缓存；
- **DNSSEC 签名与在线验签**：不包含 RRSIG / DNSKEY 等加密签名计算；
- **动态更新（RFC 2136）**：Zone 数据由静态配置文件或内存数据结构加载，不支持网络动态写入更新；
- **全量 AXFR / IXFR 区传送**：收到区传送请求时统一返回合规的拒绝响应（REFUSED）；
- **DoH / DoT 加密传输**：应用层专注于标准 DNS 协议报文本身，TLS/HTTPS 由外部反向代理或网关终结。

---

## 参考与来源说明 (Attribution & References)

1. **项目原创性声明**：
   本项目为**原创独立开发**。所有核心协议数据结构、编解码器、安全防线算法及权威解析调度逻辑均由作者 **`chgttyyr`** 基于 MoonBit 语言规范从零手写实现，未引入、复制或移植任何第三方专有代码仓库。
2. **遵循的国际标准与协议**：
   - [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034) - DOMAIN NAMES - CONCEPTS AND FACILITIES
   - [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
   - [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891) - Extension Mechanisms for DNS (EDNS(0))
   - [RFC 3597](https://datatracker.ietf.org/doc/html/rfc3597) - Handling of Unknown DNS Resource Record (RR) Types
3. **生态参考与行为对齐**：
   在项目立项与架构调研期间，作者查阅了 MoonBit 生态现存的客户端存根（`jinshengmeng46/moon-dns-stub`）与配置检查工具（`lmclmc1/moonbit-dns-zone`）的功能边界与行为特征，确立了开发核心服务端以填补生态空白的定位，无代码复用。

---

## 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 许可证开源。
版权所有 (c) 2026 `chgttyyr`。所有代码均为作者原创实现。
