#ifndef LEADER_NODE_LEADER_SIGNATURE_COLLECTOR_H_
#define LEADER_NODE_LEADER_SIGNATURE_COLLECTOR_H_

#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include <map>
#include <string>
#include <vector>

/// 签名收集器: 从文件或网络加载各组门限签名
class SignatureCollector {
public:
    /// 从目录加载所有组的签名文件
    /// @param dir_path 组签名文件目录
    /// @return group_id → GroupThresholdSignature
    std::map<GroupId, GroupThresholdSignature>
    loadFromDirectory(const std::string& dir_path);

    /// 生成测试用的256组门限签名 (使用已有私钥)
    /// @param group_seckeys 组私钥映射 (只用于测试模式)
    /// @param block_hash 区块哈希
    /// @return 生成的组签名 (每个签名与对应公钥匹配)
    std::map<GroupId, GroupThresholdSignature>
    generateTestData(
        const std::map<GroupId, FrHex>& group_seckeys,
        const std::string& block_hash);

    /// 加载组公钥映射 (从JSON文件)
    /// @param filepath 组公钥JSON文件
    /// @return group_id → 公钥 hex
    std::map<GroupId, PubKeyHex>
    loadPublicKeys(const std::string& filepath);

    /// 保存组公钥映射到JSON文件
    void savePublicKeys(const std::string& filepath,
                        const std::map<GroupId, PubKeyHex>& pubkeys);

private:
    /// 解析单个组签名JSON文件
    GroupThresholdSignature parseSignatureFile(const std::string& filepath);
};

#endif
