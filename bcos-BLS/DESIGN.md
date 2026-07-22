# 百万节点区块链BLS门限签名方案设计文档

## 一、方案概述

### 1.1 背景与目标

本方案旨在解决大规模分布式节点对区块链区块结果进行高效签名的难题。通过BLS门限签名与签名聚合技术，将百万节点的签名压缩为单个聚合签名，实现链上高效验证。

核心技术路线：BLS门限签名（Threshold BLS） + 分层聚合（Hierarchical Aggregation）。

### 1.2 方案架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                        FISCO-BCOS 区块链 (4节点)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │          BlsVerifier 节点内验证模块 (C++)                   │  │
│  │  · 存储 256 组公钥映射 (groupId → BLS PubKey)             │  │
│  │  · 接收聚合签名 + 组标识位图 (uint256 bitmap)              │  │
│  │  · 内部聚合公钥 + BLS 配对验证 (herumi/bls)               │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
          ▲                                    ▲
          │ 提交聚合签名+bitmap                  │ 注册256组公钥
          │                                    │
┌─────────┴──────────┐              ┌──────────┴──────────────┐
│    Leader 节点      │              │   Leader 节点 (初始化)   │
│  · 收集各组门限签名  │              │  · 收集256组DKG公钥      │
│  · BLS签名聚合      │              │  · 调用 BlsVerifier     │
│  · 生成组标识位图    │              │    setGroupPublicKey()  │
│  · 提交至FISCO-BCOS  │              └─────────────────────────┘
└─────────┬──────────┘
          │ 接收各组门限签名
          │
┌─────────┴──────────────────────────────────────────────────────┐
│                    256 个组 (每个组 ~4000 节点)                  │
│                                                                 │
│  ┌─────────────────────── 组 i ───────────────────────────┐    │
│  │  ┌──────────┐                                           │    │
│  │  │ DKG 节点  │ → 生成BLS密钥对，门限拆分，分发份额        │    │
│  │  │ (初始化)  │ → 将公钥提交给 Leader 节点，删除私钥           │    │
│  │  └──────────┘                                           │    │
│  │       │ 分发私钥份额 (Shamir Secret Sharing)              │    │
│  │       ▼                                                 │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │            4000 个普通节点                         │    │    │
│  │  │  每个节点持有私钥份额 sk_share                     │    │    │
│  │  │  对区块哈希签名: sig_share = Sign(sk_share, H)     │    │    │
│  │  └──────────┬──────────────────────────────────────┘    │    │
│  │             │ 发送签名份额                                │    │
│  │             ▼                                            │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │          10 个聚合器节点 (每组400节点)             │    │    │
│  │  │  · 收集签名份额                                     │    │    │
│  │  │  · 门限签名聚合 (Lagrange插值，t-of-n, t=3400)     │    │    │
│  │  │  · 聚合器间交换聚合结果                             │    │    │
│  │  │  · 达到85%阈值 → 生成组门限签名                     │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  └──────────────────────────────────────────────────────────┘    │
│  ... (共256组)                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3 关键参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 总节点数 | ~1,024,000 | 256组 × 4000节点 |
| 组数 | 256 | 每组独立进行门限签名 |
| 每组节点数 | 4000 | 组内节点规模 |
| 门限阈值 (每组) | 3400 (85%) | 至少需要85%的签名份额 |
| 每组聚合器数 | 10 | 每个聚合器负责400节点 |
| 组间聚合阈值 | 205 (80%) | 至少需要80%的组签名 |
| 椭圆曲线 | BLS12-381 | herumi/bls 库, 128-bit 安全 |
| BLS方案 | 小签名大公钥 (Sig∈G1, PK∈G2) | 符合ETH2.0标准 |
| 验签方式 | 节点内验证 (BlsVerifier) | FISCO-BCOS 节点内置 C++ 模块 |
| 门限签名聚合 | O(n) Lagrange 快速算法 | 连续点 1..N 阶乘预计算优化 |

---

## 二、密码学基础

### 2.1 BLS签名算法

BLS签名基于双线性配对（Bilinear Pairing）$e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$。

**密钥生成:**
- 私钥 $sk \in \mathbb{F}_r$（随机数）
- 公钥 $PK = sk \cdot G_2 \in \mathbb{G}_2$

**签名:**
- $\sigma = sk \cdot H(m) \in \mathbb{G}_1$，其中 $H(m)$ 是消息哈希到 $\mathbb{G}_1$ 的结果

**验证:**
- $e(\sigma, G_2) \stackrel{?}{=} e(H(m), PK)$

### 2.2 门限BLS (Threshold BLS)

使用Shamir秘密共享将组私钥拆分为 $n$ 份，门限为 $t$。

**私钥拆分 (由DKG节点执行，方案验证阶段简化为模拟):**

1. DKG节点生成主私钥 $sk_{group}$ 和对应的公钥 $PK_{group} = sk_{group} \cdot G_2$
2. 使用Shamir秘密共享：随机选择 $t-1$ 次多项式 $f(x)$，其中 $f(0) = sk_{group}$
3. 为节点 $j$ 生成私钥份额 $sk_j = f(j)$

**签名份额生成:**

节点 $j$ 使用私钥份额签名：
$$ \sigma_j = sk_j \cdot H(m) $$

**门限签名聚合 (Lagrange插值):**

收集至少 $t$ 个有效签名份额后，聚合器计算：

$$ \sigma_{group} = \sum_{j \in S} \lambda_j(0) \cdot \sigma_j $$

其中 $S$ 是签名份额的索引集合，$|S| \ge t$，$\lambda_j(0)$ 是Lagrange系数：
$$ \lambda_j(0) = \prod_{k \in S, k \neq j} \frac{0 - k}{j - k} $$

$\sigma_{group}$ 等同于使用 $sk_{group}$ 直接对消息签名的结果。

### 2.3 跨组签名聚合

Leader节点将多个组的门限签名聚合成单个BLS签名：

$$ \sigma_{agg} = \sum_{i \in G_{participating}} \sigma_{group\_i} $$

对应地，聚合公钥为：

$$ PK_{agg} = \sum_{i \in G_{participating}} PK_{group\_i} $$

**安全性质：** 聚合签名 $\sigma_{agg}$ 只有在对所有参与组的公钥聚合 $PK_{agg}$ 下才能通过验证，任何非参与组的公钥不能混入。

### 2.4 BLS12-381 曲线与节点内验证

本方案统一使用 **BLS12-381** 曲线（herumi/bls 默认模式），避免了链上链下跨曲线不兼容问题。

| 参数 | 值 | 说明 |
|------|-----|------|
| 曲线 | BLS12-381 | 128-bit 安全 |
| F_p | 381 bits | 6 个 uint64 |
| F_r | 256 bits | 4 个 uint64 |
| G1 序列化 | 48 bytes (压缩) | 签名 |
| G2 序列化 | 96 bytes (压缩) | 公钥 |

验签不再通过智能合约完成，而是集成到 **FISCO-BCOS 节点内部的 BlsVerifier 模块**中：

- 公钥聚合（G2 加法）和签名聚合（G1 加法）在 Leader 链下完成
- BlsVerifier 使用 herumi/bls 的 C++ API 做 BLS 配对验证
- 验证结果参与 FISCO-BCOS 共识，所有节点独立执行验签

---

## 三、组件详细设计

### 3.1 BlsVerifier 节点内验证模块 (C++)

#### 3.1.1 功能概述

BlsVerifier 是集成到 FISCO-BCOS 节点内部的 C++ 静态库模块，替代智能合约完成验签，直接参与共识过程。每个 FISCO-BCOS 节点启动时初始化该模块。

核心功能：
1. **公钥存储：** 维护 256 组 groupId → BLS 公钥的映射表
2. **聚合验签：** 接收聚合签名 + 组标识位图，内部聚合公钥并验证 BLS 配对

#### 3.1.2 对外接口

```cpp
// 单例访问 (节点内唯一)
BlsVerifier& v = BlsVerifier::instance();

// 初始化 (节点启动时调用)
int v.init();

// 逐组注册公钥 (系统初始化阶段)
int v.setGroupPublicKey(uint32_t groupId, const std::string& pubkeyHex);

// 验签 (共识过程中调用)
bool v.verify(const std::string& aggSigHex,
              const std::string& bitmapHex,
              const std::string& message);

// 查询接口
size_t groupCount();
bool hasGroup(uint32_t groupId);
std::string getGroupPublicKey(uint32_t groupId);
```

#### 3.1.3 内部验签流程

```
verify(aggSigHex, bitmapHex, message):
  1. 同步锁保护 (mutex, 线程安全)
  2. 解析 bitmap → 提取参与组 ID 列表
  3. 查表获取各组公钥, G2 累加 → 聚合公钥 PK_agg
  4. 反序列化聚合签名 → G1 点 σ_agg
  5. BLS 配对验证: e(σ_agg, G2) == e(H(m), PK_agg)
  6. 返回 bool 结果
```

#### 3.1.4 错误码

| 错误码 | 含义 |
|--------|------|
| OK (0) | 验证通过 |
| ERR_NOT_INITIALIZED (-1) | 模块未初始化 |
| ERR_INVALID_GROUP_ID (-3) | 组ID不在 1~256 范围 |
| ERR_INVALID_PUBKEY (-4) | 公钥 hex 格式无效 |
| ERR_INVALID_BITMAP (-6) | 位图格式无效 |
| ERR_PUBKEY_NOT_FOUND (-8) | 位图引用的组公钥未注册 |
| ERR_VERIFY_FAILED (-9) | 签名不匹配 |

#### 3.1.5 FISCO-BCOS 集成方式

将 `libblsverifier.a` 链接到 FISCO-BCOS 节点二进制：

```
// 节点启动时
BlsVerifier::instance().init();

// 初始化阶段：注册公钥
for (auto& [gid, pk] : registeredGroups)
    BlsVerifier::instance().setGroupPublicKey(gid, pk);

// 共识验证区块时
bool valid = BlsVerifier::instance().verify(
    block.aggregatedSignature,
    block.groupBitmap,
    block.blockHash
);
```

---

### 3.2 组模拟程序 (C++)

#### 3.2.1 功能概述

组模拟程序模拟单个组内所有节点的行为，包括：
1. DKG初始化：密钥生成与份额分发
2. 签名生成：4000个节点各自签名
3. 签名聚合：聚合器收集份额并生成门限签名

#### 3.2.2 模块架构 (实际代码)

```
group-simulator/
├── CMakeLists.txt
├── src/
│   ├── main.cpp              # 入口 + 命令行解析
│   ├── common/
│   │   ├── types.h           # 类型定义 (hex 序列化, 零外部依赖)
│   │   ├── config.h          # GroupConfig 结构
│   │   └── config.cpp        # 命令行解析
│   ├── crypto/
│   │   ├── bls_wrapper.h     # BLS 封装 (FrNative/G2Native/G1Native + hex↔native)
│   │   └── bls_wrapper.cpp   # herumi/bls C++ API 适配
│   ├── dkg/
│   │   ├── polynomial.h/cpp  # Shamir 多项式 (Horner 求值)
│   │   └── dkg_node.h/cpp    # DKG 密钥生成 + 份额分发 + 模拟删主私钥
│   ├── node/
│   │   ├── signer_node.h/cpp # 签名节点 (持有 hex 私钥份额)
│   │   └── node_manager.h/cpp# 批量管理 4000 签名节点
│   ├── aggregator/
│   │   ├── threshold.h/cpp   # O(n) Lagrange 快速门限聚合 (阶乘预计算)
│   │   └── aggregator.h/cpp  # 聚合器 (收集+交换+拉格朗日聚合)
│   └── network/
│       ├── simulator.h       # 网络模拟器接口
│       └── simulator.cpp     # 三阶段模拟 (DKG→签名→聚合→内验)
├── config/
│   └── group_config.json
└── scripts/
    ├── quick_test.sh
    └── run_all_groups.sh
```

**类型设计要点：** `types.h` 中所有密码学数据 (私钥份额/公钥/签名) 均使用 `std::string` hex 序列化存储，完全零外部库依赖。BLS 原生类型 (`bls::SecretKey`/`bls::PublicKey`/`bls::Signature`) 仅在 `bls_wrapper` 中使用。
```

#### 3.2.3 核心数据结构 (hex 序列化设计)

```cpp
// 密码学数据全部 hex 存储 (零外部依赖)
using FrHex     = std::string;   // Fr 域元素 (hex)
using PubKeyHex = std::string;   // G2 公钥 (hex)
using SigHex    = std::string;   // G1 签名 (hex)

// BLS 原生类型 (仅在 bls_wrapper 中使用)
using FrNative = bls::SecretKey;
using G2Native = bls::PublicKey;
using G1Native = bls::Signature;

// DKG 密钥份额 (hex 存储)
struct KeyShare {
    NodeId  node_id;          // 节点ID (1..4000)
    FrHex   secret_key_share; // 私钥份额 (Fr, hex)
};

// 签名份额消息
struct SigShareMessage {
    NodeId       node_id;     // 节点ID
    SigHex       signature;   // 签名份额 (G1, hex)
    std::string  block_hash;  // 区块哈希
};

// 组门限签名 (发送给 Leader)
struct GroupThresholdSignature {
    GroupId              group_id;     // 组ID
    SigHex               signature;    // 门限签名 (G1, hex)
    uint32_t             num_signers;  // 参与签名节点数
    std::string          block_hash;
    std::vector<NodeId>  signer_ids;
};
```

#### 3.2.4 执行流程

```
Phase 1: DKG初始化
───────────────────
1. DKG节点生成随机主私钥 sk ∈ F_r
2. 计算组公钥 PK = sk · G2
3. 生成 t-1 次随机多项式 f(x)，满足 f(0) = sk
4. 为节点 j=1..4000 计算私钥份额 sk_j = f(j)
5. 将 (sk_j, PK) 分发给节点 j
6. 删除主私钥 sk（模拟，记录到日志确认删除）
7. 将组公钥 PK 发送给 Leader 节点

Phase 2: 签名生成 (每次新区块触发)
─────────────────────────────────
1. 4000个签名节点获取当前区块哈希 H
2. 每个节点计算签名份额 σ_j = sk_j · hashToG1(H)
3. 节点将签名份额发送给对应的聚合器 (按 node_id 分段分配)
   · 聚合器0: 节点 1-400
   · 聚合器1: 节点 401-800
   · ...
   · 聚合器9: 节点 3601-4000

Phase 3: 门限签名聚合
─────────────────────
1. 每个聚合器收集所负责节点的签名份额
2. 验证每个签名份额的有效性: e(σ_j, G2) == e(H(H), sk_j·G2)
   (实际可简化，仅当收到足够份额后直接聚合)
3. 聚合器间交换累积结果：
   · 聚合器 k 将收集到的份额列表发送给聚合器 0（选一个做牵头聚合器）
4. 牵头聚合器检查是否收集到 ≥3400 个份额
5. 若满足阈值，使用Lagrange插值计算门限签名：
   σ_group = Σ λ_j(0) · σ_j  (j ∈ S, |S| ≥ t)
6. 将门限签名发送给Leader节点
```

#### 3.2.5 关键算法：O(n) Lagrange 快速插值

由于组内节点使用连续 ID (1..N)，Lagrange 系数可通过阶乘预计算优化至 O(N)：

```cpp
// λ_i(0) = (-1)^{N-1} * N! * i^{-1} / [(i-1)! * (N-i)! * (-1)^{N-i}]
std::vector<Fr> lagrangeFast(uint32_t N) {
    std::vector<Fr> fact(N + 1);
    fact[0] = frInt(1);
    for (uint32_t m = 1; m <= N; ++m)
        fact[m] = frMul(fact[m-1], frInt(m));

    Fr total = fact[N];
    Fr neg_one = frInt(-1);
    Fr sign = ((N-1) % 2 == 0) ? frInt(1) : neg_one;

    std::vector<Fr> out(N);
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t id = i + 1;
        Fr num = frMul(sign, frMul(total, frInv(frInt(id))));
        Fr s = ((N-id) % 2 == 0) ? frInt(1) : neg_one;
        Fr den = frMul(s, frMul(fact[id-1], fact[N-id]));
        out[i] = frMul(num, frInv(den));
    }
    return out;
}

// 门限签名聚合: σ_group = Σ λ_i * σ_i
G1 aggregate(const std::vector<G1>& sigs, const std::vector<Fr>& lambdas) {
    G1 result; result.clear();
    for (size_t i = 0; i < sigs.size(); ++i)
        result.add(g1Mul(sigs[i], lambdas[i]));
    return result;
}
```

复杂度对比：O(N²) → O(N)，4000 节点聚合耗时从 ~33s 降至 ~0.7s。

#### 3.2.6 命令行接口

```bash
# 运行单个组模拟
./group_simulator --group-id 1 \
                  --num-nodes 4000 \
                  --threshold 3400 \
                  --num-aggregators 10 \
                  --block-hash 0x... \
                  --leader-address 127.0.0.1:9000

# 批量运行所有256组 (由调度脚本控制)
./run_all_groups.sh --num-groups 256 --block-hash 0x...
```

---

### 3.3 Leader节点 (C++)

#### 3.3.1 功能概述

Leader节点负责：
1. 接收来自256个组的门限签名
2. 聚合各组签名生成最终BLS聚合签名
3. 计算参与组的位图标识符
4. 将聚合签名和位图提交至 FISCO-BCOS 节点（节点内 BlsVerifier 模块验证）

#### 3.3.2 模块架构 (实际代码)

```
leader-node/
├── CMakeLists.txt
├── src/
│   ├── main.cpp                     # 入口 + 命令行解析
│   ├── common/
│   │   ├── types.h                  # 类型定义 (hex序列化)
│   │   ├── config.h                 # LeaderConfig
│   │   └── config.cpp               # 命令行解析
│   ├── crypto/
│   │   ├── bls_wrapper.h            # BLS封装 (hex↔native)
│   │   └── bls_wrapper.cpp          # herumi/bls C++ API
│   ├── aggregation/
│   │   ├── bls_aggregator.h         # 跨组 BLS 聚合器
│   │   └── bls_aggregator.cpp       # G1+G2 聚合 + 位图生成 + 逐组验签
│   ├── leader/
│   │   ├── signature_collector.h    # 签名收集器 + JSON 解析
│   │   ├── signature_collector.cpp  # 文件加载 + 测试数据生成
│   │   ├── leader_core.h            # 核心协调器
│   │   └── leader_core.cpp          # 三阶段流程编排
│   └── contract/
│       ├── contract_client.h/cpp    # 合约调用 (stub, 待接入FISCO-BCOS SDK)
│       └── abi_codec.h/cpp          # ABI 编码器 (stub)
├── config/
│   └── leader_config.json
└── scripts/
    └── run_leader_test.sh
```

#### 3.3.3 核心数据结构 (hex 序列化)

```cpp
struct GroupThresholdSignature {
    GroupId  group_id;
    SigHex   signature;       // 门限签名 (G1, hex)
    uint32_t num_signers;
    std::string block_hash;
};

struct AggregationResult {
    SigHex    aggregated_signature;  // 最终聚合签名 (G1, hex)
    PubKeyHex aggregated_pubkey;     // 最终聚合公钥 (G2, hex)
    Uint256   group_bitmap;          // 参与组位图 (hex "0x...")
    uint32_t  group_count;
    std::string block_hash;
};
```

#### 3.3.4 执行流程

```
Phase 1: 初始化
──────────────
1. 加载配置：256组公钥映射、FISCO-BCOS节点连接信息
2. 连接FISCO-BCOS节点 (通过FISCO-BCOS C++ SDK)
3. 启动签名收集服务，监听各组聚合器发来的门限签名

Phase 2: 签名收集与聚合 (每次新区块)
────────────────────────────────────
1. 等待并接收各组聚合器发来的门限签名消息
2. 验证每组门限签名的有效性:
   e(σ_group_i, G2) == e(hashToG1(H), PK_group_i)
3. 将有效的组签名加入集合
4. 判断是否收集到 ≥205个组 (80%) 的有效签名
5. 若满足，执行签名聚合：
   a. 计算聚合签名: σ_agg = Σ σ_group_i   (G1加法)
   b. 计算聚合公钥: PK_agg = Σ PK_group_i  (G2加法，链下)
   c. 生成组标识位图 bitmap:
      bit(i-1) = 1 表示组i参与签名
      例: 组1,3,5参与 → bitmap = 0b10101 = 21

Phase 3: 提交至 FISCO-BCOS 节点
────────────────────────────────────
1. 构造区块交易参数:
   - aggregatedSignature: 聚合签名 (G1, hex)
   - aggregatedPubKey:    聚合公钥 (G2, hex)
   - groupBitmap:         组标识位图 (uint256, hex)
   - message:             区块哈希 (bytes32)
2. 提交至 FISCO-BCOS 节点, 节点的 BlsVerifier 模块参与共识验证
3. 记录日志
```

#### 3.3.5 BLS 签名聚合 + 位图生成

```cpp
AggregationResult aggregate() {
    // 1. G1 加法: σ_agg = Σ σ_group_i
    G1Native agg_sig; agg_sig.clear();
    for (auto& [gid, sig_hex] : collected_sigs_)
        agg_sig.add(g1FromHex(sig_hex));

    // 2. G2 加法: PK_agg = Σ PK_group_i
    G2Native agg_pub; agg_pub.clear();
    for (auto& [gid, _] : collected_sigs_) {
        auto it = group_pubkeys_.find(gid);
        if (it != group_pubkeys_.end())
            agg_pub.add(g2FromHex(it->second));
    }

    // 3. 生成位图 (bit(i-1)=1 表示组i参与)
    uint8_t buf[32] = {0};
    for (auto& [gid, _] : collected_sigs_) {
        uint32_t bit = gid - 1;
        buf[bit / 8] |= (1u << (7 - (bit % 8))); // MSB-first
    }
    // buf[0..31] → "0x..." hex 字符串

    return {g1ToHex(agg_sig), g2ToHex(agg_pub), bitmap_hex, ...};
}
```

#### 3.3.6 测试模式

Leader 支持 `--generate-test-data` 模式，直接生成 256 组密钥对并签名（跳过组模拟器），用于 Leader 聚合性能验证。

性能数据（256 组, 80% 参与, 单机单线程）:
- 签名生成: 94 ms/轮 (205 次 BLS 签名)
- Leader 聚合: <1 ms/轮 (205 次 G1+G2 加法)
- BLS 验签: 1 ms/轮
```

---

### 3.4 BlsVerifier 验证模块 (C++ 静态库)

详见 **§3.1**，替代智能合约方案。模块输出 `libblsverifier.a`，链接到 FISCO-BCOS 节点中。

### 3.5 集成测试

```
integration-test/
├── CMakeLists.txt
├── src/
│   ├── main.cpp          # 端到端集成测试 (DKG→签名→Leader聚合→验签)
│   ├── bench_single.cpp  # 单组 4000 节点性能基准
│   └── bench_leader.cpp  # Leader 256 组聚合性能基准
└── scripts/
```

---

## 四、BLS密码库选择

### 4.1 C++端：herumi/bls (BLS12-381)

最终选择统一使用 **BLS12-381** 曲线（128-bit 安全）：

- herumi/bls 默认模式 (公钥∈G2, 签名∈G1)
- 安装方式: `git clone --recursive && make -C mcl && make`
- 产出: `libbls384_256.a` + `libmcl.a`
- 编译参数: `MCLBN_FP_UNIT_SIZE=6, MCLBN_FR_UNIT_SIZE=4`, `MCL_BLS12_381=5`

### 4.2 为什么不用 BN254

原设计曾考虑 BN254 以兼容 FISCO-BCOS EVM 预编译, 但最终改为节点内验证后, 无需跨曲线适配:

| 对比项 | BN254 | BLS12-381 (选用) |
|--------|-------|------------------|
| 安全强度 | ~100 bits | 128 bits |
| G1 大小 | 64 bytes | 48 bytes (压缩) |
| 链上支持 | EIP-196/197 | 无需 (节点内验证) |
| 生态成熟度 | Solidity 库较多 | ETH2.0 标准 |

---

## 五、FISCO-BCOS 集成详细设计

### 5.1 总体改造概述

FISCO-BCOS 的 4 节点网络负责接收 Leader 提交的聚合签名，验证签名，并将签名放入区块中参与共识。主要改造分为三个部分：

| 改造项 | 涉及文件 | 说明 |
|--------|---------|------|
| 1. 区块数据结构扩展 | `bcos-tars-protocol/.../Block.tars` + `protocol/BlockHeaderImpl` | 在 BlockHeader 中增加 BLS 聚合签名字段 |
| 2. RPC 接口新增 | `bcos-rpc/bcos-rpc/jsonrpc/JsonRpcInterface` + `JsonRpcImpl_2_0` | 增加两个 JSON-RPC 接口 |
| 3. 共识验签接入 | `bcos-pbft/.../BlockValidator.cpp` | 在 PBFT 区块验证流程中调用 BlsVerifier 验签 |

### 5.2 改造一：区块数据结构扩展 (Block.tars)

#### 5.2.1 新增 BLS 聚合签名结构体

在 `bcos-tars-protocol/bcos-tars-protocol/tars/Block.tars` 中，于 BlockHeader 之前新增一个 struct：

```
// BLS 聚合签名信息
struct BlsAggregatedSignature {
    1 optional vector<byte> aggregatedSignature;   // BLS 聚合签名 (G1点, 48 bytes 压缩)
    2 optional vector<byte> groupBitmap;           // 参与组位图 (32 bytes = 256 bits)
};
```

**字段说明：**
- `aggregatedSignature`：Leader 聚合所有参与组的门限签名后得到的最终 BLS 签名（G1 点，序列化后 48 bytes）
- `groupBitmap`：uint256 位图，第 (i-1) 位 = 1 表示组 i 参与签名。最多支持 256 组

#### 5.2.2 在 BlockHeader 中引用

在 `BlockHeader` struct 中增加新字段：

```
struct BlockHeader {
    1 optional BlockHeaderData data;
    2 optional vector<byte> dataHash;
    3 optional vector<Signature> signatureList;
    4 optional BlsAggregatedSignature blsAggregatedSignature;   // 新增: BLS聚合签名
};
```

**注意：** `blsAggregatedSignature` 不参与 `dataHash` 的计算（signatureList 同样不参与），因为聚合签名是外部 Leader 在对当前区块签名之后才附加上来的。

#### 5.2.3 协议实现层适配

需要在以下文件中增加 `BlsAggregatedSignature` 的 getter/setter 和序列化支持：

- `bcos-tars-protocol/bcos-tars-protocol/protocol/BlockHeaderImpl.h` — 增加：
  - `bcos::bytes aggregatedSignature() const;` （返回 G1 压缩序列化）
  - `bcos::bytes groupBitmap() const;` （返回 32 字节位图）
  - `void setBlsAggregatedSignature(const bcos::bytes& sig, const bcos::bytes& bitmap);`

- `bcos-tars-protocol/bcos-tars-protocol/protocol/BlockHeaderImpl.cpp` — 实现上述方法，读写 `m_inner()->blsAggregatedSignature.aggregatedSignature` 和 `m_inner()->blsAggregatedSignature.groupBitmap`

- `bcos-framework/bcos-framework/protocol/BlockHeader.h` — 在框架层接口中增加对应的纯虚函数声明：

```cpp
// 框架层接口新增
virtual bcos::bytes aggregatedBlsSignature() const = 0;
virtual bcos::bytes groupBitmap() const = 0;
virtual void setBlsAggregatedSignature(bcos::bytes const& _sig, bcos::bytes const& _bitmap) = 0;
```

### 5.3 改造二：新增 RPC 接口

#### 5.3.1 设计原则

4 个 FISCO-BCOS 节点的工作是"被动接收"，因此只需提供两个对外接口。采用现有的 JSON-RPC 2.0 模式（`MethodMap` + `*I` 包装器），与 `getSealerList` 等方法保持一致。

#### 5.3.2 接口一：注册组公钥 — `addGroupPublicKey`

**调用方：** Leader 节点（系统初始化阶段，一次性）

**JSON-RPC 请求格式：**
```json
{
  "jsonrpc": "2.0",
  "method": "addGroupPublicKey",
  "params": ["group0", 1, "0x..."],
  "id": 1
}
```

- `params[0]`: groupId (string) — FISCO-BCOS 群组 ID
- `params[1]`: bLSGroupId (int) — BLS 组 ID (1~256)
- `params[2]`: pubkeyHex (string) — BLS 公钥 hex 字符串 (G2 点序列化)

**返回：**
```json
{
  "jsonrpc": "2.0",
  "result": { "code": 0, "message": "success" },
  "id": 1
}
```

错误码对应 `BlsVerifier::ErrorCode`：`-1` 未初始化、`-3` 无效组ID、`-4` 无效公钥、`-10` 内部错误

**内部实现链路：**
```
JsonRpcInterface::addGroupPublicKey()      // 接口声明
  → JsonRpcImpl_2_0::addGroupPublicKey()   // 实现
    → BlsVerifier::instance().setGroupPublicKey(groupId, pubkeyHex)
```

#### 5.3.3 接口二：提交聚合签名 — `submitBlsAggregatedSignature`

**调用方：** Leader 节点（每次出块时调用）

**JSON-RPC 请求格式：**
```json
{
  "jsonrpc": "2.0",
  "method": "submitBlsAggregatedSignature",
  "params": ["group0", "0x...", "0x..."],
  "id": 2
}
```

- `params[0]`: groupId (string) — FISCO-BCOS 群组 ID
- `params[1]`: aggregatedSignature (string) — BLS 聚合签名 hex (G1 点序列化)
- `params[2]`: groupBitmap (string) — 组标识位图 hex (64 字符 = 32 bytes)

**内部处理流程：**
```
1. 获取当前最新区块的 parentInfo 中第一个 parentHash
   → 这是签名消息 (被签名的内容)
2. 调用 BlsVerifier::instance().verify(aggSig, bitmap, parentHash, result)
   → 内部: 解析位图 → 聚合公钥 → BLS 配对验证
3. 验证通过 → 将聚合签名放入下一区块的 BlockHeader.blsAggregatedSignature
4. 验证失败 → 返回错误，不参与出块
```

**返回（验证通过）：**
```json
{
  "jsonrpc": "2.0",
  "result": { "code": 0, "message": "verify success, txHash=0x..." },
  "id": 2
}
```

**返回（验证失败）：**
```json
{
  "jsonrpc": "2.0",
  "error": { "code": -9, "message": "BLS signature verification failed" },
  "id": 2
}
```

#### 5.3.4 需要修改的文件清单

| 文件 | 改动 |
|------|------|
| `bcos-rpc/bcos-rpc/jsonrpc/JsonRpcInterface.h` | 新增纯虚函数 `addGroupPublicKey`、`submitBlsAggregatedSignature`；新增 `*I` 包装函数 |
| `bcos-rpc/bcos-rpc/jsonrpc/JsonRpcInterface.cpp` | `initMethod()` 中注册两个新方法到 `m_methodToFunc` |
| `bcos-rpc/bcos-rpc/jsonrpc/JsonRpcImpl_2_0.h` | 声明两个新方法 |
| `bcos-rpc/bcos-rpc/jsonrpc/JsonRpcImpl_2_0.cpp` | 实现两个新方法，通过 `getNodeService()` 获取 Ledger 访问最新区块 |

### 5.4 改造三：共识流程中接入 BlsVerifier 验签

#### 5.4.1 节点初始化（一次性）

在 `bcos-ledger/bcos-ledger/Ledger.h` 或 `libinitializer/Initializer.cpp` 的初始化流程中，加入 BlsVerifier 的初始化和公钥注册：

```cpp
// Initializer::init() 中追加（在 Ledger 就绪之后）
BlsVerifier::instance().init();

// 公钥可在节点启动配置文件中指定，或由 Leader 通过 addGroupPublicKey RPC 接口逐组注册
// 在 Initializer 中实现公钥加载，或等待 RPC 调用后完成
```

#### 5.4.2 共识验签时机

**签名消息（被签名内容）** = 当前区块 header 中 `parentInfo` 的第一个父区块的 `blockHash`

在 `bcos-pbft/bcos-pbft/pbft/engine/BlockValidator.cpp` 的区块验证流程中，增加 BLS 验签步骤。

现有验证流程概览：

```cpp
// BlockValidator 中的现有验证函数
bool BlockValidator::checkSignatureList(Block::Ptr _block);   // 验证 sealer 签名列表
```

**新增 BLS 验证逻辑：**

```cpp
/// 验证 BLS 聚合签名（4 节点中均独立执行）
bool BlockValidator::checkBlsAggregatedSignature(Block::Ptr _block) {
    auto header = _block->blockHeader();
    auto& blsSig = header->blsAggregatedSignature();

    // 如果区块中无 BLS 聚合签名，跳过（兼容旧区块）
    if (blsSig.aggregatedSignature.empty() || blsSig.groupBitmap.empty()) {
        return true;
    }

    // 签名消息 = parentInfo 中第一个父区块的 hash
    auto parents = header->parentInfo();
    if (parents.empty()) {
        return false;  // 创世块不应有聚合签名
    }
    auto parentHashHex = toHex(parents[0].blockHash);

    // 调用 BlsVerifier 验签
    auto& verifier = BlsVerifier::instance();
    std::string aggSigHex = "0x" + toHex(blsSig.aggregatedSignature);
    std::string bitmapHex = "0x" + toHex(blsSig.groupBitmap);

    return verifier.verify(aggSigHex, bitmapHex, parentHashHex);
}
```

**调用位置：** 在 `BlockValidator::checkBlock()` 方法中，`checkSignatureList()` 之后追加：

```cpp
if (!checkBlsAggregatedSignature(_block)) {
    BLOCK_VALIDATOR_LOG(ERROR) << LOG_BADGE("checkBlock")
                               << LOG_DESC("BLS aggregated signature verification failed");
    return false;
}
```

#### 5.4.3 数据流：从 Leader 提交到区块共识

```
Leader 节点
  │
  │  调用 RPC: submitBlsAggregatedSignature(aggSig, bitmap)
  ▼
FISCO-BCOS 节点 (接收 RPC 的节点)
  │
  │  1. 取最新区块 parentInfo[0].blockHash 作为签名消息
  │  2. BlsVerifier.verify(aggSig, bitmap, parentHash) → 验证
  │  3. 验证通过 → 将聚合签名打包进新区块:
  │     blockHeader.blsAggregatedSignature = {aggSig, bitmap}
  │  4. 新区块广播至其他 3 个共识节点
  ▼
其他 3 个共识节点 (收到共识区块)
  │
  │  BlockValidator 验证区块:
  │    checkSignatureList()        → 验证 sealer 签名
  │    checkBlsAggregatedSignature() → 验证 BLS 聚合签名
  │         │
  │         ▼
  │    BlsVerifier.verify(aggSig, bitmap, parentInfo[0].blockHash)
  │         │
  │         ├─ 通过 → 区块有效，参与共识
  │         └─ 失败 → 区块无效，拒绝
```

### 5.5 4节点网络搭建

```bash
curl -LO https://github.com/FISCO-BCOS/FISCO-BCOS/releases/download/v3.6.0/build_chain.sh
chmod +x build_chain.sh
./build_chain.sh -l 127.0.0.1:4 -p 30300,20200,8545 -o nodes
cd nodes/127.0.0.1 && ./start_all.sh
```

### 5.6 BlsVerifier 编译与链接

```bash
# 1. 编译 BlsVerifier 静态库
cd bcos-BLS/bls-verifier/build && cmake .. && make
# 产出: libblsverifier.a

# 2. 链接到 FISCO-BCOS 节点
# 在 FISCO-BCOS 节点的 CMakeLists.txt 中添加:
#   target_link_libraries(fisco-bcos-pro STATIC ... ${BLSLIB_PATH}/libblsverifier.a ...)

# 3. 同时需要链接 herumi/bls 依赖库
#   target_link_libraries(fisco-bcos-pro STATIC ...
#       ${BLS_LIB}    # libbls384_256.a
#       ${MCL_LIB}    # libmcl.a
#   )
```

---

## 六、数据流与交互时序

### 6.1 系统初始化流程

```
时间线： 系统启动前 (一次性)

1. 启动FISCO-BCOS 4节点网络 (每个节点集成 BlsVerifier)
2. Leader 初始化节点:
   - 生成/收集 256 组 DKG 公钥
   - 为每个节点调用 BlsVerifier.setGroupPublicKey() 注册公钥
   - (同一套公钥在所有节点上同步注册)
3. 启动256个DKG节点，每组生成密钥:
   ┌─ DKG节点(i) ─┐
   │ 生成 sk_i     │
   │ 计算 PK_i     │
   │ 门限拆分      │
   │ 分发份额      │
   │ 删除sk_i      │
   │ 发送PK_i ──────────────► Leader节点
   └──────────────┘
4. Leader 收集全部 256 个 PK, 注册到 BlsVerifier
5. 启动各组内 4000 个签名节点 + 10 个聚合器
```

### 6.2 区块签名流程 (每次新区块)

```
时间线： 每次FISCO-BCOS出块时

FISCO-BCOS 出块
    │
    │ 区块哈希 H
    ▼
┌─────────────────────────────────────────────────────┐
│ 256个组并行执行:                                     │
│                                                     │
│ 4000个签名节点 ──签名份额──► 10个聚合器               │
│   (并行签名)              (收集+内部交换+聚合)        │
│                                │                    │
│                        组门限签名 σ_group_i           │
│                                │                    │
└────────────────────────────────┼────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
                σ_group_1   σ_group_2   σ_group_256
                    │            │            │
                    └────────────┼────────────┘
                                 ▼
                         ┌──────────────┐
                         │  Leader 节点  │
                         │              │
                         │ 收集 ≥205组  │
                         │ BLS签名聚合   │
                         │ 生成 bitmap   │
                         │              │
                         │ 提交至FISCO-BCOS  │
                         └──────┬───────┘
                                │
                                ▼
                    ┌──────────────────────────┐
                    │  BlsVerifier (节点内)     │
                    │                          │
                    │  1. 解析位图 → 参与组列表  │
                    │  2. 聚合公钥 PK_agg       │
                    │  3. e(σ_agg, G2) ==       │
                    │     e(H(m), PK_agg) ?     │
                    │                          │
                    │ ✓ 通过 → 区块有效          │
                    │ ✗ 失败 → 区块拒绝          │
                    └──────────────────────────┘
```

---

## 七、项目目录结构

```
millions-nodes/
├── DESIGN.md                          # 本文档
├── bls-verifier/                      # C++ 验证模块 (链接到 FISCO-BCOS)
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── BlsVerifier.h              # 公开 API
│   │   └── BlsVerifier.cpp            # 实现 (公钥映射 + 位图解析 + BLS验签)
│   └── test/
│       └── main.cpp                   # 18 项功能测试
├── group-simulator/                   # C++ 组模拟程序
│   ├── CMakeLists.txt
│   ├── src/{common,crypto,dkg,node,aggregator,network}/
│   ├── config/
│   └── scripts/
├── leader-node/                       # C++ Leader 节点
│   ├── CMakeLists.txt
│   ├── src/{common,crypto,aggregation,leader,contract}/
│   ├── config/
│   └── scripts/
├── integration-test/                  # 集成测试
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.cpp                   # 端到端集成测试
│   │   ├── bench_single.cpp          # 单组性能基准
│   │   └── bench_leader.cpp          # Leader 聚合基准
│   └── scripts/
├── deps/                              # 第三方依赖
│   └── bls/                           # herumi/bls (BLS12-381)
└── README.md
```

---

## 八、安全考虑

### 8.1 方案验证阶段的简化与风险

| 简化项 | 影响 | 说明 |
|--------|------|------|
| DKG模拟（非真分布式） | 单点生成密钥 | 验证阶段可接受，生产需真DKG |
| 进程内网络模拟 | 无网络延迟/丢包 | 性能估算需乘以网络系数 |
| 信任Leader提交PK_agg | BlsVerifier 在节点内聚合公钥 | 替代合约方案后, 节点内直接查表聚合, 无信任问题 |
| 简化椭圆曲线参数 | 统一 BLS12-381 | 无跨曲线兼容问题 |

### 8.2 BLS签名安全注意事项

1. **子群检查：** herumi/bls 库内置子群检查
2. **随机数质量：** FrNative::init() 使用系统 CSPRNG
3. **重放保护：** 签名消息包含区块哈希, 天然防重放
4. **线程安全：** BlsVerifier 使用 std::mutex 保护公钥映射

### 8.3 BlsVerifier 节点内验证安全

1. **共识一致性：** 所有节点独立执行验签, 结果不一致会导致分叉
2. **公钥同步：** 初始化阶段公钥必须在所有节点上完全一致
3. **位图完整性：** 位图中每个置位bit对应的公钥必须已注册, 否则返回 ERR_PUBKEY_NOT_FOUND

---

## 九、性能评估

### 9.1 实测性能数据 (MacBook, BLS12-381, 单线程)

#### 单组 4000 节点

| 阶段 | 耗时 | 说明 |
|------|------|------|
| DKG 初始化 | 30.7 s | 一次性 (3399次多项式×4000节点 Horner 求值) |
| 签名生成 (每轮) | 1.88 s | 4000 次 BLS 签名 |
| 门限聚合 (每轮) | 0.70 s | O(n) Lagrange 快速算法 + G1 标量乘 |
| 验签 (每轮) | 1 ms | BLS 配对验证 |
| **签名+聚合/轮** | **~2.6 s** | 10 轮全部通过 |

#### Leader 聚合 (256 组, 80% 参与)

| 阶段 | 耗时 | 说明 |
|------|------|------|
| 密钥初始化 | 88 ms | 256 组密钥对 |
| 签名生成 (每轮) | 94 ms | 205 次 BLS 签名 |
| Leader 聚合 (每轮) | <1 ms | 205 次 G1 + 205 次 G2 加法 |
| 验签 (每轮) | 1 ms | 单次配对 |
| **聚合+验签/轮** | **~1 ms** | Leader 聚合极快 |

### 9.2 瓶颈分析

1. **DKG 初始化：** 30s/组，256组串行约 2 小时 — 生产环境各组并行初始化，一次性完成
2. **组内门限聚合：** 0.7s/轮 (G1 标量乘是瓶颈) — 可多线程优化
3. **Leader 聚合：** <1ms/轮 — 无瓶颈
4. **BLS 验签：** 1ms/次 — FISCO-BCOS 节点内验签极快

---

## 十、开发计划

### ✅ Phase 1: 基础密码学与 C++ 组模拟程序 (已完成)

- [x] 集成 herumi/bls (BLS12-381) 至 C++ 项目
- [x] 实现 DKG 模块 (多项式 + 份额分发)
- [x] 实现签名节点 (SignerNode + NodeManager)
- [x] 实现聚合器 (ThresholdAggregator + O(n) Lagrange)
- [x] 实现进程内网络模拟 (NetworkSimulator, 三阶段流程)
- [x] 单组端到端测试 (20 / 4000 节点)
- [x] 性能基准测试 (DKG + 10 轮签名聚合)

### ✅ Phase 2: Leader 节点 (已完成)

- [x] 实现签名收集器 (文件加载 + 测试数据生成 + JSON 解析)
- [x] 实现跨组 BLS 聚合 (BlsAggregator: 逐组验签 + G1/G2 聚合 + 位图)
- [x] 实现 Leader 核心协调 (三阶段流程编排)
- [x] 合约客户端 stub (待合约完成后填充)

### ✅ Phase 3: BlsVerifier 验证模块 (已完成，替代智能合约)

- [x] 实现 BlsVerifier 单例类 (公钥映射 + 位图解析 + 聚合验签)
- [x] 线程安全 (std::mutex)
- [x] 错误码体系
- [x] 18 项功能测试 (注册/验签/错误路径/128组压力)

### ✅ Phase 4: 集成测试 (已完成)

- [x] 10 组端到端全流程验证通过
- [x] 单组 4000 节点性能基准 (DKG + 10轮)
- [x] Leader 256 组聚合性能基准

### ✅ Phase 5: FISCO-BCOS 节点集成 (已完成)

**5.1 编译集成**

- [x] 在 `libinitializer/Initializer.cpp` 中初始化 `BlsVerifier::instance().init()`
- [x] 在 `bcos-sealer/bcos-sealer/Sealer.cpp` 中出块时将暂存签名写入区块头

**5.2 区块数据结构扩展**

- [x] `bcos-tars-protocol/.../tars/Block.tars` — 新增 `BlsAggregatedSignature` struct
- [x] `BlockHeader` 中增加 `blsAggregatedSignature` 字段
- [x] `BlockHeaderImpl.h/.cpp` — 实现 getter/setter
- [x] `bcos-framework/.../BlockHeader.h` — 新增框架层虚函数声明

**5.3 RPC 接口**

- [x] `JsonRpcInterface.h/.cpp` — 新增 `addGroupPublicKey`、`submitBlsAggregatedSignature`
- [x] `JsonRpcImpl_2_0.h/.cpp` — 实现两个新方法

**5.4 共识验签接入**

- [x] `BlockValidator.cpp` — 新增 `checkBlsAggregatedSignature()` 方法

**5.5 网络通信层 (组模拟器 ↔ Leader ↔ FISCO-BCOS)**

- [x] `common/SimpleHttp.h` — 零依赖 POSIX HTTP 服务端/客户端
- [x] `leader-node/src/network/leader_server.h` — Leader HTTP 服务端（接收签名 + 轮询 FISCO-BCOS）
- [x] `leader-node/src/leader/leader_core.h/.cpp` — 集成网络模式 + `runNetworkMode()`
- [x] `group-simulator/src/network/simulator.h/.cpp` — 网络模式 `runNetworkLoop()` + `sendToLeader()`
- [x] `group-simulator/src/main.cpp` — 支持 `--network-mode` 标志
- [x] `GroupConfig` 新增 `leader_port` 字段

### Phase 6: 全流程网络测试 (待完成)

- [ ] 在 64 台机器上部署 256 个组模拟器进程
- [ ] 启动 FISCO-BCOS 4 节点网络 (集成 `libblsverifier.a`)
- [ ] 启动 Leader 节点 (网络模式: `--network-mode --listen-port 9000 --fisco-rpc ...`)
- [ ] 各组模拟器执行 DKG，公钥注册到各 FISCO-BCOS 节点
- [ ] 全流程: 出块 → hash 分发 → 组签名 → Leader 聚合 → RPC 提交 → 共识验证

---

## 十二、测试部署方案

### 12.1 网络拓扑

```
┌──────────────────────────────────────────────────────────────┐
│  本机 (macOS) — FISCO-BCOS 4 节点共识网络                      │
│                                                                │
│  节点0: 127.0.0.1:20200 (RPC)  30300 (P2P)  8545 (Channel)   │
│  节点1: 127.0.0.1:20201 (RPC)  30301 (P2P)  8546 (Channel)   │
│  节点2: 127.0.0.1:20202 (RPC)  30302 (P2P)  8547 (Channel)   │
│  节点3: 127.0.0.1:20203 (RPC)  30303 (P2P)  8548 (Channel)   │
│                                                                │
│  出块间隔: 10 秒 (保证签名流程足够时间)                          │
└───────────────────────────┬──────────────────────────────────┘
                            │ 公网 IP
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  云服务器 × 1 — Leader 节点                                    │
│                                                                │
│  HTTP Server: 0.0.0.0:9000                                    │
│  · /register_pubkey       (POST, 组模拟器上传公钥)              │
│  · /submit_signature      (POST, 组模拟器提交门限签名)          │
│  · /latest_block_hash     (GET,  组模拟器获取最新区块 hash)      │
│  · /collected_count       (GET,  查询已收集签名数)              │
│  · /pubkey_count          (GET,  查询已注册公钥数)              │
│                                                                │
│  轮询 FISCO-BCOS 节点0:20200 (RPC), 每 2 秒获取最新区块 hash     │
│  聚合达到阈值后向全部 4 个节点 RPC 提交聚合签名                   │
│  部署路径: /opt/bls-leader/                                     │
└──────────┬──────────┬──────────┬─────────────────┬────────────┘
           │          │          │                 │
     ┌─────┘    ┌─────┘    ┌─────┘           ┌─────┘
     ▼          ▼          ▼                 ▼
┌─────────┐┌─────────┐┌─────────┐   ┌──────────────┐
│ 机器 1   ││ 机器 2   ││ 机器 3   │ … │ 机器 64       │
│ 组 1-4  ││ 组 5-8  ││ 组 9-12 │   │ 组 253-256   │
│         ││         ││         │   │              │
│ 4 进程   ││ 4 进程   ││ 4 进程   │   │ 4 进程        │
│ 各 4000 ││ 各 4000 ││ 各 4000 │   │ 各 4000      │
│ 模拟节点 ││ 模拟节点 ││ 模拟节点 │   │ 模拟节点      │
└─────────┘└─────────┘└─────────┘   └──────────────┘
```

### 12.2 机器规格建议

| 部署项 | 数量 | CPU | 内存 | 说明 |
|--------|------|-----|------|------|
| FISCO-BCOS 节点 | 1 台 (4 进程) | 8 核 | 16 GB | 本机 macOS，4 节点共享 |
| Leader 节点 | 1 台 | 4 核 | 8 GB | 云服务器，仅聚合 + HTTP 服务 |
| 组模拟器机器 | 64 台 | 4 核 | 8 GB | 每台 4 进程，各模拟 4000 节点签名 |

### 12.3 分片方案（256 组 → 64 台机器）

每台机器运行 4 个 `group_simulator` 进程：

| 机器编号 | 负责的组 | 进程启动命令 (示例) |
|----------|---------|-------------------|
| 1 | 1, 2, 3, 4 | `--group-id 1` `--group-id 2` `--group-id 3` `--group-id 4` |
| 2 | 5, 6, 7, 8 | `--group-id 5` ... |
| ... | ... | ... |
| 64 | 253, 254, 255, 256 | `--group-id 253` ... |

### 12.4 编译产出物准备

在**本机**上交叉编译三个二进制文件：

```bash
# 1. FISCO-BCOS 节点 (macOS, 已集成 BlsVerifier)
cd /Users/wushichen/FISCO-BCOS
mkdir -p build && cd build
cmake .. -DFULLNODE=ON -DCMAKE_BUILD_TYPE=Release -DTESTS=OFF
make -j4 fisco-bcos
# 产出: build/fisco-bcos-air/fisco-bcos

# 2. Leader 节点 (为云服务器交叉编译 Linux x86_64)
cd /Users/wushichen/FISCO-BCOS/bcos-BLS/leader-node
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
# 产出: build/leader_node

# 3. 组模拟器 (为 64 台 Linux 机器交叉编译)
cd /Users/wushichen/FISCO-BCOS/bcos-BLS/group-simulator
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
# 产出: build/group_simulator
```

> **注意**：如果云服务器和组模拟器机器也是 macOS，则无需交叉编译。Linux 部署需要在 Linux 环境本地编译或使用交叉编译工具链。

### 12.5 FISCO-BCOS 4 节点部署（本机 macOS）

**12.5.1 生成 4 节点配置**

```bash
cd /Users/wushichen/FISCO-BCOS
# 下载 build_chain 脚本
curl -LO https://github.com/FISCO-BCOS/FISCO-BCOS/releases/download/v3.11.0/build_chain.sh
chmod +x build_chain.sh

# 生成 4 节点配置
./build_chain.sh -l 127.0.0.1:4 -p 30300,20200,8545 -o nodes

# 产出: nodes/127.0.0.1/ 下有 4 个节点目录
#   node0/   node1/   node2/   node3/
```

**12.5.2 调整出块间隔（10 秒）**

编辑每个节点的 `config.ini`，在 `[consensus]` 段添加：

```ini
[consensus]
    consensus_timeout = 10000
```

**12.5.3 编译并替换节点二进制**

```bash
# 用集成了 BlsVerifier 的 fisco-bcos 替换默认二进制
cp build/fisco-bcos-air/fisco-bcos nodes/127.0.0.1/node0/
cp build/fisco-bcos-air/fisco-bcos nodes/127.0.0.1/node1/
cp build/fisco-bcos-air/fisco-bcos nodes/127.0.0.1/node2/
cp build/fisco-bcos-air/fisco-bcos nodes/127.0.0.1/node3/
```

**12.5.4 启动 4 节点**

```bash
cd nodes/127.0.0.1
./start_all.sh

# 验证: 检查进程
ps aux | grep fisco-bcos | grep -v grep
# 应该有 4 个进程

# 验证: 查看日志确认创世区块已出
tail -f node0/log/log_2026*.log | grep "number=0"
```

### 12.6 Leader 节点部署（云服务器）

**12.6.1 上传文件**

```bash
# 在本机执行
LEADER_HOST="<云服务器IP>"
scp bcos-BLS/leader-node/build/leader_node $LEADER_HOST:/opt/bls-leader/
scp bcos-BLS/leader-node/config/leader_config.json $LEADER_HOST:/opt/bls-leader/
```

**12.6.2 启动 Leader**

```bash
# 在云服务器上执行
cd /opt/bls-leader
./leader_node \
    --network-mode \
    --listen-port 9000 \
    --total-groups 256 \
    --min-threshold 205 \
    --fisco-rpc <本机公网IP>:20200 \
    --fisco-rpc <本机公网IP>:20201 \
    --fisco-rpc <本机公网IP>:20202 \
    --fisco-rpc <本机公网IP>:20203
```

> 如果本机没有公网 IP，可用 frp/ngrok 等内网穿透工具暴露 20200-20203 端口。

**12.6.3 验证 Leader 启动**

```bash
# 在任意机器上测试接口
curl http://<Leader IP>:9000/collected_count
# 预期返回: {"collected_count":0,"threshold_reached":false}

curl http://<Leader IP>:9000/pubkey_count
# 预期返回: {"pubkey_count":0,"total_groups":256}
```

### 12.7 组模拟器部署（64 台机器）

**12.7.1 上传文件（以机器 1 为例）**

```bash
# 在本机执行（64 台机器需要逐台或批量上传）
MACHINE_IP="<机器1 IP>"
scp bcos-BLS/group-simulator/build/group_simulator $MACHINE_IP:/opt/bls-group/
scp bcos-BLS/group-simulator/config/group_config.json $MACHINE_IP:/opt/bls-group/
```

**12.7.2 创建启动脚本**

每台机器上创建 `/opt/bls-group/start.sh`：

```bash
#!/bin/bash
# 64台机器分片表: 机器 N 负责组 (4N-3) 到 (4N)
# 使用方法: ./start.sh <机器编号: 1-64>

MACHINE_ID=${1:?请指定机器编号 (1-64)}
LEADER_HOST="<Leader云服务器IP>:9000"
BASE_GROUP=$(( (MACHINE_ID - 1) * 4 + 1 ))

# 每台机器 4 个进程, 参数:
#   --group-id          组ID (每组 4000 节点, 门限 3400)
#   --leader-address    Leader HTTP 地址
#   --leader-port       Leader HTTP 端口

for i in 0 1 2 3; do
    GID=$((BASE_GROUP + i))
    nohup ./group_simulator \
        --network-mode \
        --group-id $GID \
        --num-nodes 4000 \
        --threshold 3400 \
        --num-aggregators 10 \
        --leader-address "$(echo $LEADER_HOST | cut -d: -f1)" \
        --leader-port "$(echo $LEADER_HOST | cut -d: -f2)" \
        > logs/group_${GID}.log 2>&1 &
done

echo "机器 $MACHINE_ID 启动完成: 组 $BASE_GROUP 到 $((BASE_GROUP + 3))"
```

**12.7.3 创建 logs 目录并启动**

```bash
# 在每台机器上执行
mkdir -p /opt/bls-group/logs
chmod +x /opt/bls-group/start.sh

# 机器 1:
./start.sh 1   # 启动组 1-4

# 机器 2:
./start.sh 2   # 启动组 5-8
# ... 依次类推 ...

# 机器 64:
./start.sh 64  # 启动组 253-256
```

**12.7.4 DKG 进度监控**

在 Leader 机器上持续查询公钥注册进度：

```bash
# 每 5 秒查询一次，直到全部 256 组注册完毕
watch -n 5 'curl -s http://localhost:9000/pubkey_count'
```

预期输出变化过程：`{"pubkey_count":0}` → `{"pubkey_count":50}` → ... → `{"pubkey_count":256}`。

> DKG 初始化约 30 秒/组（各组并行执行），约 30-40 秒后全部完成。

### 12.8 启动时序

```
时间轴 (T=0 为起点):
──────────────────────────────────────────────────────────────────

T+0s : 启动 FISCO-BCOS 4 节点
         → 每个节点初始化 BlsVerifier
         → 创世区块 (number=0) 生成
         → 等待 Leader 注册公钥后开始正常出块

T+5s : 启动 Leader 节点 (云服务器)
         → HTTP Server 监听 9000 端口
         → 轮询 FISCO-BCOS 获取区块 hash

T+10s: 启动 256 个组模拟器 (64 台机器)
         → 各组并行 DKG (约 30s)
         → DKG 完成后 POST /register_pubkey 上传公钥
         → Leader 转发 RPC addGroupPublicKey 到 4 个节点

T+45s: DKG 全部完成，256 组公钥已注册到全部节点
         → 此时可以触发 FISCO-BCOS 首次正常出块
         → 或等待自动出块 (每 10 秒)

T+50s: 出块 #1，Leader 轮询到新区块 hash
         → 组模拟器获取 hash → 签名 → 门限聚合 → 发给 Leader
         → Leader 聚合 ≥205 组签名 → RPC 提交到 4 个节点

T+60s: 出块 #2，Sealer 将暂存签名写入区块头
         → 其他 3 个节点 BlockValidator 验签通过
         → 共识通过 → 第一个包含 BLS 签名的区块上链
```

### 12.9 关键注意事项

1. **公钥数量检查**：Leader 启动后需确认 `pubkey_count` 达到 256 后再开始出块。否则区块头中不会有 BLS 签名字段。

2. **出块间隔**：至少 10 秒。签名流程（获取 hash → 4000 节点签名 1.88s → 门限聚合 0.7s → Leader 聚合 <1ms → RPC 提交）约需 3 秒。256 组并行执行，但需要各组签名都到达 Leader 才能聚合。考虑到网络延迟，10 秒足够。

3. **Leader 多节点提交**：公钥注册和签名提交都发给全部 4 个节点。因为 sealer 会轮换，下一个出块节点可能是任意一个。

4. **签名覆盖**：`BlsVerifier::setPendingBlsSignature` 无条件覆盖旧签名。只要新签名在新出块前到达即可。

5. **端口放行**：
   - 本机公网 IP: 20200-20203 (FISCO-BCOS RPC)
   - Leader 云服务器: 9000 (HTTP)
   - 确保防火墙/安全组允许这些端口的 TCP 入站连接

### 12.10 验证命令

```bash
# 1. 检查 FISCO-BCOS 节点状态
curl -X POST http://127.0.0.1:20200 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getBlockNumber","params":["group0"],"id":1}'

# 2. 检查 Leader 收集签名情况
curl -s http://<Leader IP>:9000/collected_count

# 3. 检查公钥注册完成
curl -s http://<Leader IP>:9000/pubkey_count

# 4. 查看区块头是否包含 BLS 签名
curl -X POST http://127.0.0.1:20200 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getBlockByNumber","params":["group0","node0",2,true,true],"id":1}'
# 检查返回 JSON 中是否包含 blsAggregatedSignature 字段
```

---

## 十一、参考资料

### BLS密码学

1. [BLS Signatures (Boneh-Lynn-Shacham)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05)
2. [Ethereum 2.0 BLS Spec](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)
3. [Threshold BLS Signatures - jcraige.com](https://jcraige.com/threshold-bls-signatures)

### Solidity BLS库

4. [kevincharm/bls-bn254](https://github.com/kevincharm/bls-bn254) - BN254 BLS Solidity库
5. [randa-mu/bls-solidity](https://github.com/randa-mu/bls-solidity) - BLS Solidity库
6. [warlock-labs/solbls](https://github.com/warlock-labs/solbls) - BN254 BLS Solidity库

### C++ BLS库

7. [herumi/bls](https://github.com/herumi/bls) - BLS12-381门限签名C++库
8. [herumi/mcl](https://github.com/herumi/mcl) - 底层椭圆曲线数学库
9. [skalenetwork/libBLS](https://github.com/skalenetwork/libBLS) - BLS + DKG C++库（BN254）

### FISCO-BCOS

10. [FISCO-BCOS预编译合约](https://fisco-bcos-documentation.readthedocs.io/en/latest/docs/design/virtual_machine/precompiled.html)
11. [FISCO-BCOS 3.0文档](https://fisco-bcos-30-en-document.readthedocs.io/en/latest/)
12. [EIP-197: BN254配对预编译](https://eips.ethereum.org/EIPS/eip-197)

### EVM预编译

13. [EIP-196: BN254 G1加法/标量乘预编译](https://eips.ethereum.org/EIPS/eip-196)
14. [EIP-2537: BLS12-381预编译 (Pectra升级)](https://eips.ethereum.org/EIPS/eip-2537)
15. [RFC 9380: Hash-to-Curve](https://datatracker.ietf.org/doc/html/rfc9380)
