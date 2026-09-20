# MoonDNS (`chgttyyr/moon_dns`)

> **MoonDNS** 是使用 **100% 纯 MoonBit（Zero-FFI）** 从零实现的权威域名服务器（Authoritative DNS Server），严格遵循 RFC 1035 与 RFC 6891 (EDNS0) 规范，专为高安全性、确定性与云原生 / WebAssembly 边缘计算环境设计。

本项目由开发者 **`chgttyyr`** 进行**独立开源设计与开发**。

---

## 🌟 核心特性 (Key Features)

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

## 🧩 生态定位与价值 (Ecosystem Positioning)

在 MoonBit 生态中，此前已有客户端解析存根（`moon-dns-stub`）与配置文件静态审计工具（`moonbit-dns-zone`），但**始终缺少核心的权威服务端实现**。

| 生态分层 | 现有开源组件 | 功能职责 |
| :--- | :--- | :--- |
| **客户端查询** | `jinshengmeng46/moon-dns-stub` | 基础客户端 Stub 递归解析 |
| **配置语法审计** | `lmclmc1/moonbit-dns-zone` | Master-file 语法静态检查 |
| **权威服务端基石** | **`chgttyyr/moon_dns` (本项目)** | **完整权威解析、防线安全机与全套 Wire 编解码** |

**MoonDNS 补齐了 MoonBit 在域名基础设施上的关键服务端空白**，使 MoonBit 具备独立托管权威解析、响应公网或局域网 DNS 请求的能力。

---

## 🚀 快速开始 (Quick Start)

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

## 🏛️ 项目架构 (Architecture)

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

## 🛡️ 安全防御体系 (Security Model)

DNS 协议最危险的脆弱点在于恶意的压缩指针（Compression Pointer Loops）。MoonDNS 在解码层部署了多重防御：
1. **环路访问集合 (Visited Offset Tracker)**：记录解包过程中所有已跳转的偏移量，遇到重复跳转立即拦截。
2. **最大跳转上限 (Max Jump Limit)**：严格将单次域名解析的指针跳转次数限制在 $\le 128$ 次，防御深度放大攻击。
3. **前向与越界校验 (Boundary Check)**：指针目标偏移必须严格落在当前报文前部已解析区域，杜绝任何未初始化内存越界。
4. **零崩溃保证**：恶意攻击输入一律安全返回 `DnsError::MalformedPointer`，绝不发生运行时 panic。

---

## 📜 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 许可证开源。
所有代码均为作者 **`chgttyyr`** 原创实现，无任何外部专有代码借用。
