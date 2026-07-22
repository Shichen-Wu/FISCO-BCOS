#ifndef LEADER_NODE_CRYPTO_BLS_WRAPPER_H_
#define LEADER_NODE_CRYPTO_BLS_WRAPPER_H_

#include "common/types.h"
#include <string>
#include <vector>
#include <bls/bls.hpp>

using FrNative = bls::SecretKey;
using G2Native = bls::PublicKey;
using G1Native = bls::Signature;

class BlsWrapper {
public:
    static bool init();

    static FrNative frFromHex(const FrHex& hex);
    static FrHex    frToHex(const FrNative& fr);
    static G2Native g2FromHex(const PubKeyHex& hex);
    static PubKeyHex g2ToHex(const G2Native& g2);
    static G1Native g1FromHex(const SigHex& hex);
    static SigHex    g1ToHex(const G1Native& g1);

    static FrNative generateSecretKey();
    static G2Native getPublicKey(const FrNative& sk);

    static G1Native sign(const FrNative& sk, const std::string& msg);
    static bool verify(const G1Native& sig, const G2Native& pub,
                       const std::string& msg);

    static G1Native addG1(const G1Native& a, const G1Native& b);
    static G1Native aggregateSignatures(const std::vector<G1Native>& sigs);

    static G2Native addG2(const G2Native& a, const G2Native& b);
    static G2Native aggregatePublicKeys(const std::vector<G2Native>& pubs);

private:
    static bool initialized_;
};

#endif
