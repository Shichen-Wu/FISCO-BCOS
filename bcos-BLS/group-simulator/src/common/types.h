#ifndef GROUP_SIMULATOR_COMMON_TYPES_H_
#define GROUP_SIMULATOR_COMMON_TYPES_H_

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// 基础类型别名 (不依赖任何外部库)
// ============================================================================

/// 组ID类型: 1-256
using GroupId = uint32_t;

/// 节点在组内的ID: 1-4000
using NodeId = uint32_t;

// ============================================================================
// 密码学数据的序列化存储 (hex字符串)
// 所有BLS操作通过 bls_wrapper.h 进行类型转换
// ============================================================================

/// 私钥份额: Fr 域元素 (32 bytes → hex)
using FrHex = std::string;

/// 组公钥: G2 点 (BLS12-381: 96 bytes 压缩 → hex)
using PubKeyHex = std::string;

/// BLS签名: G1 点 (BLS12-381: 48 bytes 压缩 → hex)
using SigHex = std::string;

// ============================================================================
// 数据结构 (全部使用 hex 序列化，无 BLS 库依赖)
// ============================================================================

/// DKG初始化产生的密钥份额
struct KeyShare {
    NodeId  node_id;            ///< 节点在组内的ID (1..n)
    FrHex   secret_key_share;   ///< 私钥份额 (Fr标量, hex编码)
};

/// 签名节点产生的签名份额消息
struct SigShareMessage {
    NodeId       node_id;    ///< 签名节点ID
    SigHex       signature;  ///< BLS签名份额 (G1点, hex编码)
    std::string  block_hash; ///< 被签名的区块哈希 (hex)
};

/// 聚合后的组门限签名 (发送给Leader)
struct GroupThresholdSignature {
    GroupId              group_id;        ///< 组ID
    SigHex               signature;       ///< 门限签名 (G1点, hex编码)
    uint32_t             num_signers;     ///< 实际参与签名的节点数
    std::string          block_hash;      ///< 被签名的区块哈希
    std::vector<NodeId>  signer_ids;      ///< 参与签名的节点ID列表
};

/// 聚合器间交换数据
struct AggregatorExchangeData {
    uint32_t                       aggregator_id;  ///< 聚合器ID (0..9)
    std::vector<SigShareMessage>   shares;         ///< 收集到的签名份额
};

/// 组模拟运行结果
struct SimulationResult {
    GroupId     group_id;
    bool        threshold_reached;       ///< 是否达到门限阈值
    uint32_t    signatures_collected;    ///< 收集的签名数
    uint32_t    threshold_required;      ///< 要求的门限数
    std::string threshold_signature_hex; ///< 门限签名 (hex)
    int64_t     dkg_time_ms;             ///< DKG初始化耗时
    int64_t     sign_time_ms;            ///< 签名耗时
    int64_t     aggregate_time_ms;       ///< 聚合耗时
};

#endif // GROUP_SIMULATOR_COMMON_TYPES_H_
