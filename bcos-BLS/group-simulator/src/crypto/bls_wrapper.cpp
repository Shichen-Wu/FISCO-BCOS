#include "crypto/bls_wrapper.h"
#include <iostream>

bool BlsWrapper::initialized_ = false;

bool BlsWrapper::init() {
    if (initialized_) return true;
    int err = ::blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (err != 0) {
        std::cerr << "[BlsWrapper] blsInit 失败, 错误码: " << err << std::endl;
        return false;
    }
    initialized_ = true;
    return true;
}

// ========================================================================
// 类型转换: hex ↔ native (bls C++ 类自带序列化)
// ========================================================================

FrNative BlsWrapper::frFromHex(const FrHex& hex) {
    FrNative fr;
    fr.deserializeHexStr(hex);
    return fr;
}

FrHex BlsWrapper::frToHex(const FrNative& fr) {
    return fr.serializeToHexStr();
}

G2Native BlsWrapper::g2FromHex(const PubKeyHex& hex) {
    G2Native g2;
    g2.deserializeHexStr(hex);
    return g2;
}

PubKeyHex BlsWrapper::g2ToHex(const G2Native& g2) {
    return g2.serializeToHexStr();
}

G1Native BlsWrapper::g1FromHex(const SigHex& hex) {
    G1Native g1;
    g1.deserializeHexStr(hex);
    return g1;
}

SigHex BlsWrapper::g1ToHex(const G1Native& g1) {
    return g1.serializeToHexStr();
}

// ========================================================================
// 密钥操作
// ========================================================================

FrNative BlsWrapper::generateSecretKey() {
    FrNative sk;
    sk.init();
    return sk;
}

G2Native BlsWrapper::getPublicKey(const FrNative& sk) {
    G2Native pk;
    sk.getPublicKey(pk);
    return pk;
}

std::vector<FrNative> BlsWrapper::generatePolynomial(uint32_t degree) {
    std::vector<FrNative> coeffs(degree + 1);
    for (uint32_t i = 0; i <= degree; ++i) {
        coeffs[i].init();
    }
    return coeffs;
}

FrNative BlsWrapper::evaluatePolynomial(
        const std::vector<FrNative>& coeffs, uint32_t x) {
    // Horner法 — 使用 mcl C API
    mclBnFr result, x_fr;
    mclBnFr_setInt(&result, 0);
    mclBnFr_setInt(&x_fr, x);

    for (int i = static_cast<int>(coeffs.size()) - 1; i >= 0; --i) {
        mclBnFr_mul(&result, &result, &x_fr);
        mclBnFr_add(&result, &result, &coeffs[static_cast<size_t>(i)].getPtr()->v);
    }

    char buf[2048];
    size_t n = mclBnFr_getStr(buf, sizeof(buf), &result, 2048);
    if (n == 0) throw std::runtime_error("mclBnFr_getStr failed");
    FrNative out;
    out.deserializeHexStr(std::string(buf, n));
    return out;
}

std::vector<KeyShare> BlsWrapper::makeKeyShares(
        uint32_t total_nodes,
        const std::vector<FrNative>& shares) {
    std::vector<KeyShare> result;
    result.reserve(total_nodes);
    for (NodeId j = 1; j <= total_nodes; ++j) {
        KeyShare ks;
        ks.node_id = j;
        ks.secret_key_share = shares[j - 1].serializeToHexStr();
        result.push_back(ks);
    }
    return result;
}

// ========================================================================
// 签名操作
// ========================================================================

G1Native BlsWrapper::sign(const FrNative& sk_share,
                           const std::string& message) {
    G1Native sig;
    sk_share.sign(sig, message.data(), message.size());
    return sig;
}

bool BlsWrapper::verify(const G1Native& sig, const G2Native& pub,
                        const std::string& message) {
    return sig.verify(pub, message.data(), message.size());
}

// ========================================================================
// G1 聚合 (G1加法: bls::Signature::add, G1×Fr标量乘: blsSignatureMul)
// ========================================================================

G1Native BlsWrapper::scalarMul(const G1Native& g1, const FrNative& fr) {
    // blsSignatureMul(y, x) → y->v = y->v * x->v  (G1 * Fr 标量乘)
    G1Native result = g1;
    blsSignatureMul(result.getPtr(), fr.getPtr());
    return result;
}

G1Native BlsWrapper::addG1(const G1Native& a, const G1Native& b) {
    G1Native result = a;
    result.add(b);
    return result;
}

G1Native BlsWrapper::aggregateSignatures(const std::vector<G1Native>& sigs) {
    G1Native result;
    result.clear();
    for (const auto& s : sigs) {
        result.add(s);
    }
    return result;
}

// ========================================================================
// G2 聚合 (G2加法: bls::PublicKey::add)
// ========================================================================

G2Native BlsWrapper::addG2(const G2Native& a, const G2Native& b) {
    G2Native result = a;
    result.add(b);
    return result;
}

G2Native BlsWrapper::aggregatePublicKeys(const std::vector<G2Native>& pubs) {
    G2Native result;
    result.clear();
    for (const auto& p : pubs) {
        result.add(p);
    }
    return result;
}

// ========================================================================
// Fr 标量算术 (使用 mcl C API)
// ========================================================================

namespace {

FrNative frFromRaw(const mclBnFr& fr) {
    char buf[2048];
    size_t n = mclBnFr_getStr(buf, sizeof(buf), &fr, 2048);
    if (n == 0) throw std::runtime_error("mclBnFr_getStr failed");
    FrNative out;
    out.deserializeHexStr(std::string(buf, n));
    return out;
}

} // anonymous namespace

FrNative BlsWrapper::frAdd(const FrNative& a, const FrNative& b) {
    mclBnFr result;
    mclBnFr_add(&result, &a.getPtr()->v, &b.getPtr()->v);
    return frFromRaw(result);
}

FrNative BlsWrapper::frMul(const FrNative& a, const FrNative& b) {
    mclBnFr result;
    mclBnFr_mul(&result, &a.getPtr()->v, &b.getPtr()->v);
    return frFromRaw(result);
}

FrNative BlsWrapper::frInverse(const FrNative& a) {
    mclBnFr result;
    mclBnFr_inv(&result, &a.getPtr()->v);
    return frFromRaw(result);
}

FrNative BlsWrapper::frNegate(const FrNative& a) {
    mclBnFr result;
    mclBnFr_neg(&result, &a.getPtr()->v);
    return frFromRaw(result);
}

FrNative BlsWrapper::frFromInt(int64_t val) {
    mclBnFr result;
    bool negative = val < 0;
    uint64_t abs_val = static_cast<uint64_t>(negative ? -val : val);
    mclBnFr_setInt(&result, abs_val);
    if (negative) {
        mclBnFr_neg(&result, &result);
    }
    return frFromRaw(result);
}

bool BlsWrapper::frIsZero(const FrNative& a) {
    return mclBnFr_isZero(&a.getPtr()->v) == 1;
}

bool BlsWrapper::frEqual(const FrNative& a, const FrNative& b) {
    return mclBnFr_isEqual(&a.getPtr()->v, &b.getPtr()->v) == 1;
}
