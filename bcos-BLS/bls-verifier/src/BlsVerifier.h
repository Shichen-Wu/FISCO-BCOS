#ifndef BLS_VERIFIER_H_
#define BLS_VERIFIER_H_

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <bls/bls.hpp>

/// @file
/// BLS 聚合签名验证模块
///
/// 集成到 FISCO-BCOS 节点中使用, 替代链上智能合约验签。
/// 核心功能:
///   1. 存储 256 组的 groupId → BLS公钥 映射
///   2. 接收聚合签名 + 组标识位图, 聚合参与组公钥并验证签名
///
/// 使用方式:
///   1. 系统初始化时调用 init() 初始化 BLS 库
///   2. 逐组调用 setGroupPublicKey() 注册各组公钥
///   3. 共识过程中调用 verify() 验证聚合签名

class BlsVerifier {
public:
    // ================================================================
    // 错误码
    // ================================================================
    enum ErrorCode {
        OK                    =  0,
        ERR_NOT_INITIALIZED   = -1,
        ERR_ALREADY_INIT      = -2,
        ERR_INVALID_GROUP_ID  = -3,
        ERR_INVALID_PUBKEY    = -4,
        ERR_INVALID_SIGNATURE = -5,
        ERR_INVALID_BITMAP    = -6,
        ERR_EMPTY_BITMAP      = -7,
        ERR_PUBKEY_NOT_FOUND  = -8,
        ERR_VERIFY_FAILED     = -9,
        ERR_INTERNAL          = -10,
    };

    /// 单例访问 (FISCO-BCOS 节点内全局唯一即可)
    static BlsVerifier& instance();

    // ================================================================
    // 初始化
    // ================================================================

    /// 初始化 BLS 密码学库 (使用 BLS12-381 曲线)
    /// @return OK / ERR_ALREADY_INIT
    int init();

    /// 是否已初始化
    bool initialized() const { return initialized_; }

    // ================================================================
    // 公钥管理
    // ================================================================

    /// 注册单个组的公钥
    /// @param groupId  组ID (1 ~ 256)
    /// @param pubkeyHex BLS公钥, G2点序列化为hex字符串
    /// @return OK / 错误码
    int setGroupPublicKey(uint32_t groupId, const std::string& pubkeyHex);

    /// 获取已注册的公钥 (hex)
    /// @return 公钥hex, 不存在则返回空字符串
    std::string getGroupPublicKey(uint32_t groupId) const;

    /// 是否已注册
    bool hasGroup(uint32_t groupId) const;

    /// 已注册的组数
    size_t groupCount() const;

    // ================================================================
    // 验签
    // ================================================================

    /// 验证聚合签名
    ///
    /// 内部流程:
    ///   1. 解析 bitmap, 提取参与组 ID 列表
    ///   2. 查询各组公钥, 在 G2 上累加得到聚合公钥
    ///   3. 将 aggSig 反序列化为 G1
    ///   4. BLS 配对验证: e(sig, G2) == e(H(m), aggPub)
    ///
    /// @param aggSigHex  聚合签名 (G1点, hex序列化)
    /// @param bitmapHex  组标识位图 (uint256, hex含0x前缀)
    ///                    例: "0xffc0..." 表示仅第1-10组参与
    /// @param message    被签名消息 (区块哈希等)
    /// @param[out] result 验签结果: true=通过, false=失败
    /// @return OK / 错误码
    int verify(const std::string& aggSigHex,
               const std::string& bitmapHex,
               const std::string& message,
               bool& result);

    /// 同上, 返回 bool (简洁接口)
    bool verify(const std::string& aggSigHex,
                const std::string& bitmapHex,
                const std::string& message);

    // ================================================================
    // 暂存待上链的 BLS 聚合签名 (出块后暂存, 下一区块写入后清空)
    // ================================================================

    /// 暂存 BLS 聚合签名 (Leader 通过 RPC 提交后调用)
    /// @param aggSigHex  聚合签名 (G1点, hex序列化)
    /// @param bitmapHex  组标识位图 (uint256, hex含0x前缀)
    /// @param message    被签名的消息 (当前最新区块的 hash)
    /// @return OK / 错误码 (验签失败返回 ERR_VERIFY_FAILED)
    int setPendingBlsSignature(const std::string& aggSigHex,
                               const std::string& bitmapHex,
                               const std::string& message);

    /// 获取暂存的聚合签名, 用于打包进下一区块
    /// @param[out] aggSigHex  暂存的聚合签名
    /// @param[out] bitmapHex  暂存的组标识位图
    /// @return 是否有暂存的签名
    bool getPendingBlsSignature(std::string& aggSigHex,
                                std::string& bitmapHex) const;

    /// 是否已有暂存的签名
    bool hasPendingBlsSignature() const;

    /// 清空暂存 (下一区块出块成功后调用)
    void clearPendingBlsSignature();

private:
    BlsVerifier() = default;
    ~BlsVerifier() = default;
    BlsVerifier(const BlsVerifier&) = delete;
    BlsVerifier& operator=(const BlsVerifier&) = delete;

    // 解析 bitmap hex 为 group_id 列表
    // @param bitmapHex "0x" + 64 hex chars
    // @param[out] groupIds 置位的 group_id (升序)
    // @return 实际参与组数
    int parseBitmap(const std::string& bitmapHex,
                    std::vector<uint32_t>& groupIds) const;

    /// verify 的核心逻辑 (调用者必须已持有 mutex_)
    int verifyLocked(const std::string& aggSigHex,
                     const std::string& bitmapHex,
                     const std::string& message,
                     bool& result);

    bool initialized_ = false;
    mutable std::mutex mutex_;

    /// groupId → G2 公钥 (hex 存储)
    std::map<uint32_t, std::string> pubkeys_;

    /// 暂存的待上链 BLS 聚合签名
    std::string pendingAggSig_;
    std::string pendingBitmap_;
    bool hasPending_ = false;
};

#endif // BLS_VERIFIER_H_
