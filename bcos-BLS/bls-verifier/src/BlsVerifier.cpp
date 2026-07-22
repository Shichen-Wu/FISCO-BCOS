#include "BlsVerifier.h"
#include <iostream>
#include <cstring>
#include <cstdio>
#include <algorithm>

// ============================================================================
// 单例
// ============================================================================

BlsVerifier& BlsVerifier::instance() {
    static BlsVerifier inst;
    return inst;
}

// ============================================================================
// 初始化
// ============================================================================

int BlsVerifier::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return ERR_ALREADY_INIT;

    int err = ::blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (err != 0) {
        std::cerr << "[BlsVerifier] blsInit 失败, err=" << err << std::endl;
        return ERR_INTERNAL;
    }
    initialized_ = true;
    return OK;
}

// ============================================================================
// 公钥管理
// ============================================================================

int BlsVerifier::setGroupPublicKey(uint32_t groupId,
                                   const std::string& pubkeyHex) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return ERR_NOT_INITIALIZED;
    if (groupId < 1 || groupId > 256) return ERR_INVALID_GROUP_ID;

    // 反序列化校验公钥格式
    try {
        bls::PublicKey pk;
        pk.deserializeHexStr(pubkeyHex);
    } catch (...) {
        return ERR_INVALID_PUBKEY;
    }

    pubkeys_[groupId] = pubkeyHex;
    return OK;
}

std::string BlsVerifier::getGroupPublicKey(uint32_t groupId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pubkeys_.find(groupId);
    return (it != pubkeys_.end()) ? it->second : "";
}

bool BlsVerifier::hasGroup(uint32_t groupId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pubkeys_.count(groupId) > 0;
}

size_t BlsVerifier::groupCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pubkeys_.size();
}

// ============================================================================
// Bitmap 解析
// ============================================================================

int BlsVerifier::parseBitmap(const std::string& bitmapHex,
                              std::vector<uint32_t>& groupIds) const {
    // bitmap 格式: "0x" + 64 hex chars = 32 bytes = 256 bits
    if (bitmapHex.size() < 2 || bitmapHex[0] != '0' || bitmapHex[1] != 'x')
        return ERR_INVALID_BITMAP;

    std::string hex = bitmapHex.substr(2);
    if (hex.size() != 64) return ERR_INVALID_BITMAP;

    groupIds.clear();
    groupIds.reserve(256);

    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        if (sscanf(hex.c_str() + i, "%02x", &byte) != 1)
            return ERR_INVALID_BITMAP;

        for (int bit = 7; bit >= 0; --bit) {
            if (byte & (1u << bit)) {
                // byte索引 i/2, bit 7..0 → 实际group_id
                uint32_t gid = static_cast<uint32_t>((i / 2) * 8 + (7 - bit) + 1);
                if (gid >= 1 && gid <= 256)
                    groupIds.push_back(gid);
            }
        }
    }

    return static_cast<int>(groupIds.size());
}

// ============================================================================
// 验签
// ============================================================================

int BlsVerifier::verify(const std::string& aggSigHex,
                         const std::string& bitmapHex,
                         const std::string& message,
                         bool& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    return verifyLocked(aggSigHex, bitmapHex, message, result);
}

int BlsVerifier::verifyLocked(const std::string& aggSigHex,
                               const std::string& bitmapHex,
                               const std::string& message,
                               bool& result) {
    if (!initialized_) { return ERR_NOT_INITIALIZED; }

    result = false;

    // 1. 解析 bitmap
    std::vector<uint32_t> groupIds;
    int n = parseBitmap(bitmapHex, groupIds);
    if (n < 0) { return n; }
    if (groupIds.empty()) { return ERR_EMPTY_BITMAP; }

    // 2. 聚合公钥 (G2 加法) + 查表
    bls::PublicKey aggPub;
    aggPub.clear();

    for (uint32_t gid : groupIds) {
        auto it = pubkeys_.find(gid);
        if (it == pubkeys_.end()) {
            std::cerr << "[BlsVerifier] 组 " << gid
                      << " 的公钥未注册!" << std::endl;
            return ERR_PUBKEY_NOT_FOUND;
        }

        bls::PublicKey pk;
        try {
            pk.deserializeHexStr(it->second);
        } catch (...) {
            return ERR_INVALID_PUBKEY;
        }
        aggPub.add(pk);
    }

    // 3. 反序列化聚合签名
    bls::Signature aggSig;
    try {
        aggSig.deserializeHexStr(aggSigHex);
    } catch (...) {
        return ERR_INVALID_SIGNATURE;
    }

    // 4. BLS 验签: e(sig, G2) == e(H(m), pub)
    try {
        result = aggSig.verify(aggPub, message.data(), message.size());
    } catch (...) {
        return ERR_INTERNAL;
    }

    return result ? OK : ERR_VERIFY_FAILED;
}

bool BlsVerifier::verify(const std::string& aggSigHex,
                          const std::string& bitmapHex,
                          const std::string& message) {
    bool result = false;
    verify(aggSigHex, bitmapHex, message, result);
    return result;
}

// ============================================================================
// 暂存待上链 BLS 聚合签名
// ============================================================================

int BlsVerifier::setPendingBlsSignature(const std::string& aggSigHex,
                                         const std::string& bitmapHex,
                                         const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) { return ERR_NOT_INITIALIZED; }

    // verify the signature before storing (caller already holds mutex_)
    bool result = false;
    int rc = verifyLocked(aggSigHex, bitmapHex, message, result);
    if (rc != OK) { return rc; }
    if (!result) { return ERR_VERIFY_FAILED; }

    pendingAggSig_ = aggSigHex;
    pendingBitmap_ = bitmapHex;
    hasPending_ = true;
    std::cout << "[BlsVerifier] 暂存 BLS 聚合签名, 等待下一区块出块" << std::endl;
    return OK;
}

bool BlsVerifier::getPendingBlsSignature(std::string& aggSigHex,
                                          std::string& bitmapHex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!hasPending_) { return false; }
    aggSigHex = pendingAggSig_;
    bitmapHex = pendingBitmap_;
    return true;
}

bool BlsVerifier::hasPendingBlsSignature() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hasPending_;
}

void BlsVerifier::clearPendingBlsSignature() {
    std::lock_guard<std::mutex> lock(mutex_);
    pendingAggSig_.clear();
    pendingBitmap_.clear();
    hasPending_ = false;
}
