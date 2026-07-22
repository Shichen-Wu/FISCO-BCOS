/// @file
/// RPC interfaces integration test (simulates Leader RPC calls)
///
/// Simulates the following RPC workflows:
///   1. Leader calls addGroupPublicKey for each of N groups
///   2. After block N is produced, Leader calls submitBlsAggregatedSignature
///   3. Node verifies signature against blockHash and stores it as pending
///   4. When block N+1 is about to be sealed, node retrieves pending signature
///   5. After block N+1 is sealed, node clears pending
///   6. Error cases: wrong hash, missing pubkey, empty bitmap

#include "BlsVerifier.h"
#include <iostream>
#include <vector>
#include <chrono>

namespace blsutil {
bls::SecretKey randomSk() { bls::SecretKey s; s.init(); return s; }
bls::PublicKey  getPub(const bls::SecretKey& sk) { bls::PublicKey p; sk.getPublicKey(p); return p; }
bls::Signature  sign(const bls::SecretKey& sk, const std::string& m) {
    bls::Signature s; sk.sign(s, m.data(), m.size()); return s;
}
std::string makeBitmap(const std::vector<uint32_t>& gids) {
    uint8_t bytes[32] = {0};
    for (uint32_t g : gids) {
        uint32_t i = g - 1;
        bytes[i / 8] |= (1u << (7 - (i % 8)));
    }
    char buf[67];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 32; ++i) { snprintf(buf + 2 + i * 2, 3, "%02x", bytes[i]); }
    return std::string(buf);
}
}

using namespace blsutil;

static int g_pass = 0, g_fail = 0;
#define TEST(n) std::cout << "  [" << n << "] "; std::cout.flush()
#define CHECK(c) do { if(c) { std::cout << "PASS\n"; ++g_pass; } \
    else { std::cout << "FAIL L" << __LINE__ << "\n"; ++g_fail; } } while(0)
#define CHECK_EQ(a,b) CHECK((a)==(b))
#define CHECK_NE(a,b) CHECK((a)!=(b))

static int simulatedAddGroupPublicKey(int blsGroupId, const std::string& pubkeyHex) {
    auto& v = BlsVerifier::instance();
    return v.setGroupPublicKey(static_cast<uint32_t>(blsGroupId), pubkeyHex);
}
static int simulatedSubmitBlsAggregatedSignature(
    const std::string& aggSigHex, const std::string& bitmapHex,
    const std::string& signedBlockHash) {
    auto& v = BlsVerifier::instance();
    return v.setPendingBlsSignature(aggSigHex, bitmapHex, signedBlockHash);
}

int main() {
    std::cout << "======================================\n";
    std::cout << "  RPC Interface Integration Test\n";
    std::cout << "======================================\n\n";

    BlsVerifier& v = BlsVerifier::instance();
    int rc = v.init();
    if (rc != BlsVerifier::OK && rc != BlsVerifier::ERR_ALREADY_INIT) {
        std::cerr << "Failed to init BlsVerifier!\n"; return 1;
    }

    const uint32_t N = 3;
    std::vector<bls::SecretKey> sks(N);
    std::vector<bls::PublicKey>  pks(N);
    std::vector<std::string>     pkHex(N);
    for (uint32_t i = 0; i < N; ++i) {
        sks[i] = randomSk(); pks[i] = getPub(sks[i]);
        pkHex[i] = pks[i].serializeToHexStr();
    }

    // Test 1: addGroupPublicKey
    std::cout << "[Test 1] addGroupPublicKey\n";
    for (uint32_t i = 0; i < N; ++i) {
        TEST("add-group-" + std::to_string(i+1));
        CHECK_EQ(simulatedAddGroupPublicKey(i+1, pkHex[i]), BlsVerifier::OK);
    }
    TEST("group-count"); CHECK_EQ(v.groupCount(), (size_t)N);
    TEST("bad-id-0"); CHECK_NE(simulatedAddGroupPublicKey(0, pkHex[0]), BlsVerifier::OK);
    TEST("bad-pubkey"); CHECK_NE(simulatedAddGroupPublicKey(5, "bad"), BlsVerifier::OK);

    // Test 2: submitBlsAggregatedSignature (normal)
    std::cout << "\n[Test 2] submitBlsAggregatedSignature (normal)\n";
    std::string blockHash = "block_hash_0xAAAABBBBCCCC";
    bls::Signature aggSig; aggSig.clear();
    for (uint32_t i = 0; i < N; ++i) { aggSig.add(sign(sks[i], blockHash)); }
    std::string aggSigHex = aggSig.serializeToHexStr();
    std::string bitmap = makeBitmap({1, 2, 3});

    TEST("submit-ok"); CHECK_EQ(simulatedSubmitBlsAggregatedSignature(
        aggSigHex, bitmap, blockHash), BlsVerifier::OK);
    TEST("has-pending"); CHECK(v.hasPendingBlsSignature());

    // Test 3: retrieve pending
    std::cout << "\n[Test 3] Retrieve pending\n";
    {
        std::string s, b;
        TEST("get-pending"); CHECK(v.getPendingBlsSignature(s, b));
        TEST("sig-match"); CHECK_EQ(s, aggSigHex);
        TEST("bitmap-match"); CHECK_EQ(b, bitmap);
    }
    v.clearPendingBlsSignature();
    TEST("cleared"); CHECK(!v.hasPendingBlsSignature());

    // Test 4: wrong block hash
    std::cout << "\n[Test 4] Wrong block hash\n";
    TEST("reject-wrong-hash"); CHECK_NE(simulatedSubmitBlsAggregatedSignature(
        aggSigHex, bitmap, "wrong_hash"), BlsVerifier::OK);
    TEST("no-pending"); CHECK(!v.hasPendingBlsSignature());

    // Test 5: missing public key
    std::cout << "\n[Test 5] Missing public key\n";
    std::string badBitmap = makeBitmap({99});
    TEST("reject-missing-pk"); CHECK_NE(simulatedSubmitBlsAggregatedSignature(
        aggSigHex, badBitmap, blockHash), BlsVerifier::OK);

    // Test 6: subset participation
    std::cout << "\n[Test 6] Subset participation\n";
    {
        std::string msg2 = "block_hash_subset_test";
        bls::Signature ss; ss.clear();
        ss.add(sign(sks[0], msg2)); ss.add(sign(sks[2], msg2));
        std::string ssHex = ss.serializeToHexStr();
        std::string bm2 = makeBitmap({1, 3});
        TEST("submit-subset"); CHECK_EQ(simulatedSubmitBlsAggregatedSignature(
            ssHex, bm2, msg2), BlsVerifier::OK);
        TEST("verify-subset"); CHECK(v.verify(ssHex, bm2, msg2));
        v.clearPendingBlsSignature();
    }

    // Test 7: multi-round
    std::cout << "\n[Test 7] Multi-round (3 blocks)\n";
    bool ok = true;
    for (int r = 0; r < 3; ++r) {
        std::string h = "round_" + std::to_string(r) + "_hash";
        bls::Signature rs; rs.clear();
        for (uint32_t i = 0; i < N; ++i) { rs.add(sign(sks[i], h)); }
        std::string rsHex = rs.serializeToHexStr();
        if (simulatedSubmitBlsAggregatedSignature(rsHex, bitmap, h) != BlsVerifier::OK) ok = false;
        if (!v.verify(rsHex, bitmap, h)) ok = false;
        v.clearPendingBlsSignature();
    }
    TEST("3-rounds"); CHECK(ok);

    // Test 8: 256 groups stress
    std::cout << "\n[Test 8] 256 groups stress\n";
    {
        const uint32_t SG = 256;
        std::vector<bls::SecretKey> ssks(SG);
        for (uint32_t i = 0; i < SG; ++i) {
            ssks[i] = randomSk();
            simulatedAddGroupPublicKey(i + 4, getPub(ssks[i]).serializeToHexStr());
        }
        std::string msg = "stress_msg";
        bls::Signature sas; sas.clear();
        std::vector<uint32_t> ids;
        for (uint32_t i = 0; i < 205; ++i) {
            sas.add(sign(ssks[i], msg));
            ids.push_back(i + 4);
        }
        auto t0 = std::chrono::high_resolution_clock::now();
        bool res = v.verify(sas.serializeToHexStr(), makeBitmap(ids), msg);
        auto t1 = std::chrono::high_resolution_clock::now();
        TEST("stress-205-of-256"); CHECK(res);
        std::cout << "    verify time: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count()
            << " ms" << std::endl;
    }

    std::cout << "\nResults: " << g_pass << " pass, " << g_fail << " fail\n";
    return g_fail == 0 ? 0 : 1;
}
