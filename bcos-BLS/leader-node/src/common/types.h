#ifndef LEADER_NODE_COMMON_TYPES_H_
#define LEADER_NODE_COMMON_TYPES_H_

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// 基础类型
// ============================================================================

using GroupId  = uint32_t;   ///< 组ID (1-256)
using Uint256  = std::string; ///< uint256 通常用 hex string 传递

/// 签名 / 公钥 的 hex 序列化存储
using SigHex    = std::string;
using PubKeyHex = std::string;
using FrHex     = std::string;

// ============================================================================
// 数据结构
// ============================================================================

/// 从组聚合器收到的门限签名消息
struct GroupThresholdSignature {
    GroupId              group_id;        ///< 组ID
    SigHex               signature;       ///< 门限签名 (G1, hex)
    uint32_t             num_signers;     ///< 组内参与签名节点数
    std::string          block_hash;      ///< 被签名的区块哈希
    std::vector<uint32_t> signer_ids;     ///< 参与节点ID列表 (可选)
};

/// 跨组聚合结果
struct AggregationResult {
    SigHex      aggregated_signature;     ///< 最终聚合签名 (G1, hex)
    PubKeyHex   aggregated_pubkey;        ///< 最终聚合公钥 (G2, hex)
    Uint256     group_bitmap;             ///< 参与组位图 (hex)
    uint32_t    group_count;              ///< 参与组数量
    std::string block_hash;               ///< 区块哈希
    int64_t     aggregate_time_ms;        ///< 聚合耗时
};

/// 单组公钥信息 (从 group_pubkeys.json 加载)
struct GroupPubKeyInfo {
    GroupId    group_id;  ///< 组ID
    PubKeyHex  pubkey;    ///< 组BLS公钥 (G2, hex)
};

/// 合约调用结果
struct ContractCallResult {
    bool        success;        ///< 调用是否成功
    std::string tx_hash;        ///< 交易哈希
    std::string return_data;    ///< 返回值
    int64_t     gas_used;       ///< 消耗的gas
    std::string error_msg;      ///< 错误信息
};

#endif // LEADER_NODE_COMMON_TYPES_H_
