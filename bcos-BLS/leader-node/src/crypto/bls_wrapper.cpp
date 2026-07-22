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

FrNative BlsWrapper::frFromHex(const FrHex& hex) {
    FrNative fr; fr.deserializeHexStr(hex); return fr;
}
FrHex BlsWrapper::frToHex(const FrNative& fr) {
    return fr.serializeToHexStr();
}
G2Native BlsWrapper::g2FromHex(const PubKeyHex& hex) {
    G2Native g2; g2.deserializeHexStr(hex); return g2;
}
PubKeyHex BlsWrapper::g2ToHex(const G2Native& g2) {
    return g2.serializeToHexStr();
}
G1Native BlsWrapper::g1FromHex(const SigHex& hex) {
    G1Native g1; g1.deserializeHexStr(hex); return g1;
}
SigHex BlsWrapper::g1ToHex(const G1Native& g1) {
    return g1.serializeToHexStr();
}

FrNative BlsWrapper::generateSecretKey() {
    FrNative sk; sk.init(); return sk;
}
G2Native BlsWrapper::getPublicKey(const FrNative& sk) {
    G2Native pk; sk.getPublicKey(pk); return pk;
}

G1Native BlsWrapper::sign(const FrNative& sk, const std::string& msg) {
    G1Native sig; sk.sign(sig, msg.data(), msg.size()); return sig;
}
bool BlsWrapper::verify(const G1Native& sig, const G2Native& pub,
                        const std::string& msg) {
    return sig.verify(pub, msg.data(), msg.size());
}

G1Native BlsWrapper::addG1(const G1Native& a, const G1Native& b) {
    G1Native r(a); r.add(b); return r;
}
G1Native BlsWrapper::aggregateSignatures(const std::vector<G1Native>& sigs) {
    G1Native r; r.clear();
    for (const auto& s : sigs) r.add(s);
    return r;
}

G2Native BlsWrapper::addG2(const G2Native& a, const G2Native& b) {
    G2Native r(a); r.add(b); return r;
}
G2Native BlsWrapper::aggregatePublicKeys(const std::vector<G2Native>& pubs) {
    G2Native r; r.clear();
    for (const auto& p : pubs) r.add(p);
    return r;
}
