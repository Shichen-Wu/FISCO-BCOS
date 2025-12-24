# RPBFT-MVBA 共识算法文档

## 概述

本文档描述了基于FISCO-BCOS项目实现的新BFT共识算法，该算法结合了**RPBFT (Robust PBFT)** 和 **MVBA (Multi-Valued Byzantine Agreement)** 两种机制，提供了更强的容错能力和动态节点管理能力。

## 1. 算法架构

### 1.1 整体架构

新的共识算法由两个核心组件构成：

1. **RPBFT (Robust PBFT)**: 基于PBFT的增强版本，支持动态sealer轮换机制
2. **MVBA (Multi-Valued Byzantine Agreement)**: 多值拜占庭协议，用于处理恶意节点检测和惩罚

```
┌─────────────────────────────────────────────────┐
│              PBFT Engine (基础层)                 │
│  - 处理区块共识                                  │
│  - 检测恶意行为（双重签名等）                    │
└──────────────┬──────────────────────────────────┘
               │
               ├─────────────────┐
               │                 │
┌──────────────▼──────────┐  ┌───▼──────────────────┐
│   RPBFT Config          │  │   MVBA Processor     │
│   - Sealer轮换管理      │  │   - 处理混淆证明      │
│   - Epoch机制           │  │   - 多值拜占庭共识    │
└─────────────────────────┘  └──────────────────────┘
```

### 1.2 组件关系

- **PBFTEngine** 集成了 **MVBAProcessor**，当检测到恶意节点行为时，会触发MVBA协议
- **RPBFTConfig** 继承自 **PBFTConfig**，扩展了sealer轮换功能
- **MVBAProcessor** 独立运行，通过回调机制与PBFT引擎交互

## 2. RPBFT (Robust PBFT)

### 2.1 核心特性

RPBFT是对传统PBFT的增强，主要创新点包括：

#### 2.1.1 动态Sealer轮换机制

RPBFT引入了**Working Sealer**和**Candidate Sealer**的概念：

- **Working Sealer**: 当前参与共识的节点集合
- **Candidate Sealer**: 候选节点集合，可以轮换进入Working Sealer

#### 2.1.2 Epoch机制

通过Epoch机制管理sealer的轮换：

- **epoch_block_num**: 每个epoch包含的区块数量
- **epoch_sealer_num**: 每个epoch的sealer数量
- 当达到epoch边界或sealer数量不足时，触发sealer轮换

### 2.2 关键实现

#### 2.2.1 RPBFTConfig

```cpp
class RPBFTConfig : public PBFTConfig {
    // 判断是否应该轮换sealer
    bool shouldRotateSealers(protocol::BlockNumber _number) const override;
    
    // RPBFT配置工具
    RPBFTConfigTools::Ptr rpbftConfigTools() const noexcept;
};
```

#### 2.2.2 Sealer轮换触发条件

RPBFT在以下情况下会触发sealer轮换：

1. **定期轮换**: 达到 `epoch_block_num` 的倍数时
2. **数量不足**: Working Sealer数量小于 `epoch_sealer_num` 时
3. **非法交易**: 检测到前一个leader伪造了轮换交易时
4. **配置变更**: `epoch_sealer_num` 配置发生变化时

### 2.3 配置参数

- `epoch_block_num`: 每个epoch的区块数量
- `epoch_sealer_num`: 每个epoch的sealer数量
- `notify_rotate_flag`: 通知轮换标志

## 3. MVBA (Multi-Valued Byzantine Agreement)

### 3.1 核心概念

MVBA是一个多值拜占庭协议，用于在观察节点（Observer Nodes）之间就某个值达成共识。在本实现中，MVBA主要用于：

1. **处理EquivocationProof（混淆证明）**: 当PBFT检测到节点进行双重签名等恶意行为时，生成混淆证明
2. **达成共识**: 观察节点通过MVBA协议就恶意节点列表达成一致

### 3.2 EquivocationProof（混淆证明）

混淆证明是MVBA的输入，包含以下信息：

```protobuf
message RawEquivocationProof {
    int32 version = 1;
    repeated int64 maliciousNodeIndexes = 2;    // 恶意节点索引列表
    repeated bytes mainChainSignatures = 3;      // 主链区块签名集合
    repeated bytes conflictSignatures = 4;       // 矛盾区块签名集合
    int64 conflictBlockNumber = 5;               // 冲突区块高度
    int64 rollbackBlockNumber = 6;               // 回滚区块高度
    int64 sequentialEpoch = 7;                   // 时序epoch
    bytes additionalData = 8;                   // 其他附加数据
}
```

### 3.3 MVBA协议流程

MVBA协议采用三阶段提交机制：

#### 阶段1: Active → ActiveEcho

1. **Active阶段**: 
   - 节点收到第一个Active消息后，保存proposal
   - 创建自己的Active消息并广播给所有观察节点
   - 对收到的每个Active消息，创建ActiveEcho消息并发送给对应的generatedFrom节点

2. **ActiveEcho阶段**:
   - 节点收集ActiveEcho消息
   - 当收集到足够的ActiveEcho（达到quorum）时，进入Lock阶段
   - Quorum计算: `observerNodesNum - (observerNodesNum - 1) / 3`

#### 阶段2: Lock → LockEcho

1. **Lock阶段**:
   - 当ActiveEcho达到quorum后，节点创建Lock消息
   - Lock消息的payloadHash是Active消息的hash值
   - 从ActiveEchoList中收集节点签名，构建Lock消息的证书
   - 广播Lock消息

2. **LockEcho阶段**:
   - 节点收集LockEcho消息
   - 当收集到足够的LockEcho（达到quorum）时，进入Finish阶段

#### 阶段3: Finish

1. **Finish阶段**:
   - 当LockEcho达到quorum后，节点创建Finish消息
   - Finish消息的payloadHash是Lock消息的hash值
   - 从LockEchoList中收集节点签名，构建Finish消息的证书
   - 广播Finish消息
   - 当收集到足够的Finish消息（达到quorum）时，MVBA实例完成

### 3.4 MVBA消息类型

```cpp
enum MVBAPacketType : uint32_t {
    ActivePacket = 0x10,        // Active消息
    ActiveEchoPacket = 0x11,    // ActiveEcho消息
    LockPacket = 0x12,          // Lock消息
    LockEchoPacket = 0x13,      // LockEcho消息
    FinishPacket = 0x14,        // Finish消息
    NotifyFinishedPacket = 0x15, // 完成通知消息
    PrevotePacket = 0x16,       // 预投票消息（预留）
    VotePacket = 0x17,          // 投票消息（预留）
};
```

### 3.5 MVBA状态机

每个MVBA实例维护以下状态：

- `m_actived`: 是否已完成Active阶段
- `m_locked`: 是否已完成Lock阶段
- `m_finished`: 是否已完成Finish阶段

状态转换流程：

```
初始状态
  ↓
收到Active消息 → 创建并广播自己的Active → 发送ActiveEcho
  ↓
收集ActiveEcho (达到quorum) → m_actived = true
  ↓
创建并广播Lock消息 → 发送LockEcho
  ↓
收集LockEcho (达到quorum) → m_locked = true → 触发Lock回调
  ↓
创建并广播Finish消息
  ↓
收集Finish (达到quorum) → m_finished = true → 触发Finish回调
```

### 3.6 关键实现组件

#### 3.6.1 MVBAProcessor

MVBAProcessor是MVBA协议的主要处理器：

```cpp
class MVBAProcessor {
    // 启动MVBA实例
    void startMVBAInstance(EpochIndexType _index, 
                          EquivocationProof::Ptr _input, 
                          HashType _inputHash);
    
    // 处理MVBA消息
    void handleMVBAMessage(MVBAMessageInterface::Ptr _msg);
    
    // 注册回调
    void registerLockNotifyHandler(LockNotifyHandler _handler);
    void registerFinishNotifyHandler(FinishNotifyHandler _handler);
};
```

#### 3.6.2 MVBACache

MVBACache维护单个MVBA实例的状态：

- `m_activeList`: Active消息列表
- `m_activeEchoList`: ActiveEcho消息列表
- `m_lockList`: Lock消息列表
- `m_lockEchoList`: LockEcho消息列表
- `m_finishList`: Finish消息列表

#### 3.6.3 MVBACacheProcessor

MVBACacheProcessor管理多个MVBA实例：

- 为每个epoch index创建独立的MVBACache
- 处理各种类型的MVBA消息
- 检查并推进每个实例的状态

## 4. 集成机制

### 4.1 PBFT与MVBA的集成

PBFTEngine在初始化时创建MVBAProcessor：

```cpp
// 在PBFTEngine构造函数中
m_mvbaProcessor = std::make_shared<MVBAProcessor>(_config);
```

当检测到恶意行为时，PBFT可以触发MVBA协议：

```cpp
// 创建EquivocationProof
auto equivocationProof = std::make_shared<EquivocationProof>();
// ... 填充混淆证明数据 ...

// 启动MVBA实例
m_mvbaProcessor->startMVBAInstance(epochIndex, equivocationProof, inputHash);
```

### 4.2 观察节点机制

MVBA协议主要在观察节点（Observer Nodes）之间运行：

- 观察节点不参与PBFT共识，但参与MVBA协议
- 观察节点通过MVBA就恶意节点列表达成共识
- 共识结果可以用于后续的节点惩罚或轮换

## 5. 安全性分析

### 5.1 容错能力

- **PBFT容错**: 传统PBFT可以容忍 f < n/3 的拜占庭节点
- **MVBA容错**: MVBA在观察节点间运行，quorum为 `n - (n-1)/3`，可以容忍 f < n/3 的拜占庭节点
- **组合容错**: RPBFT-MVBA组合可以处理更复杂的攻击场景

### 5.2 恶意行为检测

RPBFT-MVBA可以检测和处理以下恶意行为：

1. **双重签名**: 节点对不同的区块高度签名，产生冲突
2. **分叉攻击**: 节点尝试创建分叉链
3. **非法轮换**: Leader伪造sealer轮换交易

### 5.3 共识保证

- **安全性**: 所有诚实节点最终会对恶意节点列表达成一致
- **活性**: 在异步网络环境下，只要不超过容错阈值，协议最终会完成
- **有效性**: 只有被检测到的恶意节点才会被包含在共识结果中

## 6. 性能特性

### 6.1 消息复杂度

- **MVBA消息数**: O(n²)，其中n为观察节点数量
- **MVBA轮次**: 固定3轮（Active、Lock、Finish）
- **通信复杂度**: 每轮需要O(n²)消息

### 6.2 延迟特性

- **MVBA完成时间**: 取决于网络延迟和节点响应时间
- **Quorum等待**: 需要等待足够多的节点响应，可能受最慢节点影响

### 6.3 优化机制

- **异步消息处理**: 使用消息队列异步处理MVBA消息
- **批量处理**: 支持批量处理多个提案（预留功能）
- **缓存管理**: 自动清理过期的MVBA实例缓存

## 7. 配置和部署

### 7.1 配置参数

#### RPBFT配置

```toml
[consensus]
consensus_type = "rpbft"
epoch_block_num = 1000        # 每个epoch的区块数
epoch_sealer_num = 4          # 每个epoch的sealer数量
```

#### MVBA配置

```cpp
// 在PBFTConfig中
m_instanceTimeout = 300000;   // MVBA实例超时时间（毫秒）
m_messageTimeout = 100000;    // 消息超时时间（毫秒）
m_maxPendingMessages = 1000000; // 最大pending消息数
```

### 7.2 部署要求

1. **节点类型**: 需要区分共识节点和观察节点
2. **网络要求**: 观察节点之间需要P2P连接
3. **存储要求**: 需要存储MVBA实例状态和消息缓存

## 8. 未来改进方向

### 8.1 性能优化

- [ ] 实现批量MVBA提案处理
- [ ] 优化消息广播机制
- [ ] 实现MVBA消息压缩

### 8.2 功能扩展

- [ ] 实现Prevote和Vote阶段（当前已定义但未实现）
- [ ] 支持动态调整quorum阈值
- [ ] 实现MVBA结果的链上存储和应用

### 8.3 安全性增强

- [ ] 完善消息签名验证
- [ ] 实现时间戳验证机制
- [ ] 增强对网络分区攻击的防护

## 9. 参考文献

1. Castro, M., & Liskov, B. (1999). Practical Byzantine fault tolerance. OSDI.
2. Cachin, C., & Vukolić, M. (2017). Blockchains and consensus protocols: a primer. 
3. FISCO-BCOS官方文档: https://fisco-bcos-documentation.readthedocs.io/

## 10. 附录

### 10.1 关键数据结构

#### EquivocationProof结构
- 版本号
- 恶意节点索引列表
- 主链签名集合
- 冲突签名集合
- 冲突区块高度
- 回滚区块高度
- 时序epoch

#### MVBAProposal结构
- Index: MVBA轮次
- Round: MVBA阶段
- SealerId: 提案发起人
- MvbaInput: EquivocationProof
- PayloadHash: 证书的payload hash
- NodeList: 证明节点列表
- SignatureList: 签名列表

### 10.2 关键接口

#### MVBAProcessor接口
- `startMVBAInstance()`: 启动MVBA实例
- `handleMVBAMessage()`: 处理MVBA消息
- `registerLockNotifyHandler()`: 注册Lock回调
- `registerFinishNotifyHandler()`: 注册Finish回调

#### MVBACache接口
- `addActiveCache()`: 添加Active消息
- `addActiveEchoCache()`: 添加ActiveEcho消息
- `addLockCache()`: 添加Lock消息
- `addLockEchoCache()`: 添加LockEcho消息
- `addFinishCache()`: 添加Finish消息
- `checkAndActived()`: 检查并推进Active阶段
- `checkAndLocked()`: 检查并推进Lock阶段
- `checkAndFinished()`: 检查并推进Finish阶段

---

**文档版本**: 1.0  
**最后更新**: 2024-12-15  
**作者**: FISCO-BCOS开发团队

