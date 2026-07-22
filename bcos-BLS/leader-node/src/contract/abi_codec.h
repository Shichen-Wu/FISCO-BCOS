#ifndef LEADER_NODE_CONTRACT_ABI_CODEC_H_
#define LEADER_NODE_CONTRACT_ABI_CODEC_H_

#include "common/types.h"
#include <string>

/// 简易 ABI 编码器: 编码 verifyAggregatedSignature 调用的 calldata
///
/// 函数签名:
///   verifyAggregatedSignature(
///     uint256[2]  aggregatedSignature,  // G1 点
///     uint256[4]  aggregatedPubKey,     // G2 点
///     uint256     groupBitmap,
///     bytes32     message
///   ) → bool
///
/// 函数选择器: keccak256("verifyAggregatedSignature(uint256[2],uint256[4],uint256,bytes32)")

class AbiCodec {
public:
    /// 计算 keccak256 哈希 (前 4 字节)
    static uint32_t functionSelector(const std::string& signature);

    /// 编码验签交易 calldata
    /// @param agg_sig 聚合签名 (G1 hex)
    /// @param agg_pub 聚合公钥 (G2 hex)
    /// @param bitmap  组标识位图 (hex, 含0x前缀)
    /// @param msg     消息 (32 bytes hex)
    /// @return 完整calldata (hex)
    static std::string encodeVerifyCall(
        const SigHex&    agg_sig,
        const PubKeyHex& agg_pub,
        const Uint256&   bitmap,
        const std::string& msg);

    // TODO: 合约完成后，根据实际 ABI 调整
};

#endif
