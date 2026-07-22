#ifndef GROUP_SIMULATOR_CRYPTO_BLS_WRAPPER_H_
#define GROUP_SIMULATOR_CRYPTO_BLS_WRAPPER_H_

#include "common/types.h"
#include <string>
#include <vector>
#include <bls/bls.hpp>

// ============================================================================
// BLS 类型别名 (依赖 herumi/bls 库)
// ============================================================================

/// 私钥 / Fr 域元素
using FrNative = bls::SecretKey;

/// 组公钥 (G2 点)
using G2Native = bls::PublicKey;

/// BLS签名 (G1 点)
using G1Native = bls::Signature;

// ============================================================================
// BLS 密码学操作封装
// 使用 herumi/bls 库，默认模式 (公钥∈G2, 签名∈G1)，曲线: BLS12-381
// ============================================================================

class BlsWrapper {
public:
    /// 初始化BLS库 (全局调用一次)
    static bool init();

    // === 类型转换: hex ↔ native ===

    static FrNative frFromHex(const FrHex& hex);
    static FrHex    frToHex(const FrNative& fr);
    static G2Native g2FromHex(const PubKeyHex& hex);
    static PubKeyHex g2ToHex(const G2Native& g2);
    static G1Native g1FromHex(const SigHex& hex);
    static SigHex    g1ToHex(const G1Native& g1);

    // === 密钥操作 ===

    static FrNative generateSecretKey();
    static G2Native getPublicKey(const FrNative& sk);
    static std::vector<FrNative> generatePolynomial(uint32_t degree);
    static FrNative evaluatePolynomial(
        const std::vector<FrNative>& coeffs, uint32_t x);

    /// 将 FrNative 份额列表转为 KeyShare 列表
    static std::vector<KeyShare> makeKeyShares(
        uint32_t total_nodes,
        const std::vector<FrNative>& shares);

    // === 签名操作 ===

    static G1Native sign(const FrNative& sk_share, const std::string& message);
    static bool verify(const G1Native& sig, const G2Native& pub,
                       const std::string& message);

    // === G1 聚合操作 ===

    static G1Native scalarMul(const G1Native& g1, const FrNative& fr);
    static G1Native addG1(const G1Native& a, const G1Native& b);
    static G1Native aggregateSignatures(const std::vector<G1Native>& sigs);

    // === G2 聚合操作 ===

    static G2Native addG2(const G2Native& a, const G2Native& b);
    static G2Native aggregatePublicKeys(const std::vector<G2Native>& pubs);

    // === Fr 标量算术 ===

    static FrNative frAdd(const FrNative& a, const FrNative& b);
    static FrNative frMul(const FrNative& a, const FrNative& b);
    static FrNative frInverse(const FrNative& a);
    static FrNative frNegate(const FrNative& a);
    static FrNative frFromInt(int64_t val);
    static bool     frIsZero(const FrNative& a);
    static bool     frEqual(const FrNative& a, const FrNative& b);

private:
    static bool initialized_;
};

#endif
