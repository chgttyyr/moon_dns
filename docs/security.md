# MoonDNS 恶意压缩指针防御与安全威胁模型 (Security Threat Model)

在网络协议栈的历史中，**DNS 压缩指针脆弱性（DNS Compression Pointer Vulnerabilities）** 曾多次导致主流开源 DNS 服务器（包括 BIND9、PowerDNS、Dnsmasq 等）发生严重的拒绝服务（DoS）、CPU 100% 挂死、甚至缓冲区溢出远程执行漏洞（如 CVE-2020-13576, CVE-2015-5477 等）。

本文档详细剖析该攻击原理，并展示 **MoonDNS (`chgttyyr/moon_dns`)** 的四重纵深安全防御实现。

---

## 1. 攻击原理深度剖析

DNS 报文（RFC 1035 Section 4.1.4）引入了域名压缩机制：
当一个域名标签的长度字节前两位为二进制 `11`（即 `0xc0`）时，说明该字节与下一个字节构成了 16-bit 压缩指针，其低 14 位表示指向报文前部已解析域名的绝对字节偏移。

由于许多古老的解析器采用递归函数直接跳转读取，攻击者可以通过构造特异畸形报文实施以下攻击：

### 攻击类型 1：自环死循环 (Self-Referencing Loop)
* **载荷构造**：在偏移量 `12` 处放置 `0xc0 0x0c`。
* **攻击机理**：指针的目标偏移正好等于当前指针自身的起始偏移（$12 \to 12$）。
* **破坏后果**：未受防护的解析器会在同一个内存地址无休止循环读取，瞬间锁死单核 CPU，线程无法退出。

### 攻击类型 2：双向乒乓交叉环 (Ping-Pong Circular Reference)
* **载荷构造**：
  - 偏移 `12` 处：Label `a` 后接指针指向偏移 `18`（`0xc0 0x12`）；
  - 偏移 `18` 处：Label `b` 后接指针指向偏移 `12`（`0xc0 0x0c`）。
* **攻击机理**：$A \to B \to A \to B \dots$
* **破坏后果**：避开简单的单步自指检测，仍然造成无限死循环。

### 攻击类型 3：前向越界利用 (Forward Out-of-Bounds Jump)
* **载荷构造**：在报文最前部放置指针指向报文末尾未初始化或完全超出报文总长度的任意内存区（例如 `0xcf 0xff`）。
* **攻击机理**：迫使解析器读取未分配内存或垃圾数据。
* **破坏后果**：在 C/C++ 语言中极易触发 Segmentation Fault 或越界读取信息泄露（Heartbleed 类模式）。

### 攻击类型 4：指数级深度跳跃放大 (Depth Amplification DoS)
* **载荷构造**：在一个微小合法报文中通过多层指针互相引用跳跃成千上万次，虽然最终能终止，但单包消耗数万次循环计算。
* **攻击机理**：利用极小带宽放大消耗服务端的计算资源。

---

## 2. MoonDNS 的四重纵深防御体系 (The Four-Layer Defense)

MoonDNS 在纯 MoonBit 解码层（`src/compression/decompress.mbt`）部署了无死角的四重守卫状态机：

```
                读取到指针字节 (b & 0xc0 == 0xc0)
                              │
                              ▼
            ┌───────────────────────────────────┐
            │ 【防线一 & 三：前向与越界边界断言】 │
            │ target_offset < current_pos 且   │
            │ target_offset in [0, total_len)   │
            └───────────────────────────────────┘
                              │
                    通过 ───┼─── 违规 ───► 返回 Err(MalformedPointer)
                              │
                              ▼
            ┌───────────────────────────────────┐
            │   【防线四：最大跳转深度计数器】    │
            │      jump_count <= 128            │
            └───────────────────────────────────┘
                              │
                    通过 ───┼─── 超过 ───► 返回 Err(MalformedPointer)
                              │
                              ▼
            ┌───────────────────────────────────┐
            │     【防线二：环路访问集合检测】    │
            │    target_offset in visited?      │
            └───────────────────────────────────┘
                              │
                    未曾访问 ──┼── 命中环路 ─► 返回 Err(MalformedPointer)
                              │
                              ▼
            记录 target_offset 到 visited 集合
            保存初次跳转位置用于恢复主光标
            安全执行重定位跳转
```

### 关键代码实现节选 (`src/compression/decompress.mbt`)

```moonbit
// 防线 1 & 3: 严格要求指针只能向后引用已经出现过的已解析数据，且在报文边界内
if target_offset >= current_pos {
  return Err(MalformedPointer("Pointer target points to self or forward"))
}
if target_offset < 0 || target_offset >= total_len {
  return Err(MalformedPointer("Pointer target is out of packet bounds"))
}

// 防线 4: 累计跳转次数上限约束 (防深度放大)
jump_count = jump_count + 1
if jump_count > MAX_POINTER_JUMPS {
  return Err(MalformedPointer("Pointer chain exceeded maximum allowed jumps"))
}

// 防线 2: 环路历史记录追踪 (防 A -> B -> A 拓扑)
for i = 0; i < visited_offsets.length(); i = i + 1 {
  if visited_offsets[i] == target_offset {
    return Err(MalformedPointer("Circular pointer loop detected"))
  }
}
visited_offsets.push(target_offset)
```

---

## 3. 零崩溃保证 (Zero-Panic Contract)

MoonDNS 对所有可能接触外部不可信输入的数据流设立了严格的**零崩溃契约**：

1. **全面使用 `Result[T, DnsError]`**：协议解析路径上杜绝任何未受捕获的 `panic()`，任何畸形、截断或恶意数据一律优雅转换为清晰的错误枚举。
2. **纯函数确定性**：报文解析状态机完全依赖传入的只读缓冲区与局部数组，不产生全局状态污染或数据竞争。
3. **已受全量模糊测试验证**：在 `tests/malicious_fuzz_test.mbt` 中，构建了包含 0~11 字节极端截断、虚假 QDCOUNT、超长 60 字节未闭合 Label、自环指针、越界指针等各类攻击报文，自动化测试证明 **100% 安全拦截，服务状态稳定无虞**。
