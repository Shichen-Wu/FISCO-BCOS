#include "contract/abi_codec.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// ============================================================================
// 简易 keccak256 实现 (占位, 后续可替换为真实实现)
// ============================================================================

namespace {

/// 简易 DJB2 哈希 (仅用于选择器生成, 真实场景需 keccak256)
uint32_t placeholderHash(const std::string& data) {
    uint32_t h = 5381;
    for (unsigned char c : data) {
        h = ((h << 5) + h) + c;
    }
    return h;
}

/// hex 解码, pad 到 N bytes
std::string hexToBytes(const std::string& hex, size_t pad_to = 0) {
    std::string bin;
    size_t start = (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') ? 2 : 0;
    for (size_t i = start; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        sscanf(hex.c_str() + i, "%02x", &byte);
        bin.push_back(static_cast<char>(byte));
    }
    if (pad_to > 0 && bin.size() < pad_to) {
        bin = std::string(pad_to - bin.size(), '\0') + bin;
    }
    return bin;
}

} // anonymous namespace

uint32_t AbiCodec::functionSelector(const std::string& signature) {
    // TODO: 替换为 keccak256
    return placeholderHash(signature);
}

std::string AbiCodec::encodeVerifyCall(
        const SigHex&    agg_sig,
        const PubKeyHex& agg_pub,
        const Uint256&   bitmap,
        const std::string& msg) {

    // TODO: 合约完成后根据实际 ABI 实现完整编码
    // 当前仅打印参数，供调试使用

    std::cout << "[AbiCodec] ===== 验签交易参数 =====" << std::endl;
    std::cout << "[AbiCodec] 聚合签名 (G1): " << agg_sig.substr(0, 64)
              << "..." << std::endl;
    std::cout << "[AbiCodec] 聚合公钥 (G2): " << agg_pub.substr(0, 64)
              << "..." << std::endl;
    std::cout << "[AbiCodec] 组位图:        " << bitmap << std::endl;
    std::cout << "[AbiCodec] 消息:           " << msg << std::endl;
    std::cout << "[AbiCodec] ===========================" << std::endl;

    // 返回空字符串标识未编码 (stub)
    return "";
}
