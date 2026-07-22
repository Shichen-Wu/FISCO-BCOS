/// @file
/// BlsVerifier + consensus verification integration test
///
/// Tests:
///   1. Pending signature storage (setPendingBlsSignature / getPendingBlsSignature)
///   2. Consensus verification pattern (simulates BlockValidator.checkBlsAggregatedSignature)
///   3. Negative tests (wrong message, wrong bitmap, missing public key)
///   4. Clear pending after block finalized
///   5. Concurrent access safety

#include "BlsVerifier.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <thread>

// ============================================================================
// BLS utilities (herumi/bls C++ API)
// ============================================================================

namespace blsutil {

bls::SecretKey randomSk() { bls::SecretKey s; s.init(); return s; }
bls::PublicKey  getPub(const bls::SecretKey& sk) { bls::PublicKey p; sk.getPublicKey(p); return p; }
bls::Signature  sign(const bls::SecretKey& sk, const std::string& m) {
    bls::Signature s; sk.sign(s, m.data(), m.size()); return s;
}
bool verify(const bls::Signature& s, const bls::PublicKey& p, const std::string& m) {
    return s.verify(p, m.data(), m.size());
}

std::string makeBitmap(const std::vector<uint32_t>& gids) {
    uint8_t bytes[32] = {0};
    for (uint32_t g : gids) {
        uint32_t i = g - 1;
        bytes[i / 8] |= (1u << (7 - (i % 8)));
    }
    char buf[67];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 32; ++i) {
        snprintf(buf + 2 + i * 2, 3, "%02x", bytes[i]);
    }
    return std::string(buf);
}
} // namespace blsutil

using namespace blsutil;

// ============================================================================
// Test framework (minimal, no external dependency)
// ============================================================================

static int g_pass = 0, g_fail = 0;

#define TEST(name) std::cout << "  [" << name << "] "; std::cout.flush()
#define CHECK(cond) do { \
    if (cond) { std::cout << "PASS\n"; ++g_pass; } \
    else { std::cout << "FAIL L" << __LINE__ << "\n"; ++g_fail; } \
} while(0)
#define CHECK_EQ(a,b) CHECK((a) == (b))
#define CHECK_NE(a,b) CHECK((a) != (b))
#define CHECK_NE(a,b) CHECK((a) != (b))

// ============================================================================
// Test entry
// ============================================================================

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "  BlsVerifier + Consensus Verification Integration Test" << std::endl;
    std::cout << "============================================================\n" << std::endl;

    // ---- Step 0: Initialize BlsVerifier ----
    std::cout << "[Step 0] BlsVerifier initialization...\n";
    BlsVerifier& v = BlsVerifier::instance();
    TEST("init");          CHECK_EQ(v.init(), BlsVerifier::OK);
    TEST("re-init");       CHECK_EQ(v.init(), BlsVerifier::ERR_ALREADY_INIT);
    TEST("initialized");   CHECK(v.initialized());

    // ---- Step 1: Register group public keys ----
    std::cout << "\n[Step 1] Register group public keys...\n";
    const uint32_t NUM_GROUPS = 10;
    std::vector<bls::SecretKey> sks(NUM_GROUPS);
    std::vector<bls::PublicKey>  pks(NUM_GROUPS);
    std::vector<std::string>     pkHex(NUM_GROUPS);

    for (uint32_t i = 0; i < NUM_GROUPS; ++i) {
        sks[i] = randomSk();
        pks[i] = getPub(sks[i]);
        pkHex[i] = pks[i].serializeToHexStr();
    }

    TEST("register-all");
    bool allOk = true;
    for (uint32_t i = 0; i < NUM_GROUPS; ++i) {
        int rc = v.setGroupPublicKey(i + 1, pkHex[i]);
        if (rc != BlsVerifier::OK) { allOk = false; }
    }
    CHECK(allOk);
    TEST("group-count");   CHECK_EQ(v.groupCount(), (size_t)NUM_GROUPS);
    TEST("has-group-5");   CHECK(v.hasGroup(5));
    TEST("no-group-0");    CHECK(!v.hasGroup(0));
    TEST("invalid-id");    CHECK_EQ(v.setGroupPublicKey(0, pkHex[0]), BlsVerifier::ERR_INVALID_GROUP_ID);
    TEST("invalid-pubkey"); CHECK_EQ(v.setGroupPublicKey(11, "bad_pubkey"), BlsVerifier::ERR_INVALID_PUBKEY);

    // ---- Step 2: Basic verify (all groups participate) ----
    std::cout << "\n[Step 2] Basic BLS verify (all groups)...\n";
    std::string msg = "block_hash_0xabcdef1234567890";
    std::string bmAll = makeBitmap({1,2,3,4,5,6,7,8,9,10});

    bls::Signature aggSigAll; aggSigAll.clear();
    bls::PublicKey  aggPubAll; aggPubAll.clear();
    for (uint32_t i = 0; i < NUM_GROUPS; ++i) {
        aggSigAll.add(sign(sks[i], msg));
        aggPubAll.add(pks[i]);
    }
    std::string aggSigHexAll = aggSigAll.serializeToHexStr();

    TEST("pre-verify");    CHECK(verify(aggSigAll, aggPubAll, msg));
    TEST("verify-pass");   CHECK(v.verify(aggSigHexAll, bmAll, msg));
    TEST("verify-wrong");  CHECK(!v.verify(aggSigHexAll, bmAll, "wrong_message"));

    // ---- Step 3: Subset groups verification ----
    std::cout << "\n[Step 3] Subset groups verify (groups 1,3,5,7,9)...\n";
    std::vector<uint32_t> oddGroups = {1,3,5,7,9};
    std::string bmOdd = makeBitmap(oddGroups);

    bls::Signature aggSigOdd; aggSigOdd.clear();
    bls::PublicKey  aggPubOdd; aggPubOdd.clear();
    for (uint32_t g : oddGroups) {
        aggSigOdd.add(sign(sks[g-1], msg));
        aggPubOdd.add(pks[g-1]);
    }
    std::string aggSigHexOdd = aggSigOdd.serializeToHexStr();

    TEST("pre-verify-odd"); CHECK(verify(aggSigOdd, aggPubOdd, msg));
    TEST("verify-odd");     CHECK(v.verify(aggSigHexOdd, bmOdd, msg));

    // ---- Step 4: Negative test - missing public key ----
    std::cout << "\n[Step 4] Negative tests...\n";
    std::string bmMissing = makeBitmap({11});
    bool resultMissing = false;
    int rcMissing = v.verify(aggSigHexAll, bmMissing, msg, resultMissing);
    TEST("missing-pk");    CHECK_EQ(rcMissing, BlsVerifier::ERR_PUBKEY_NOT_FOUND);

    // ---- Step 5: Pending BLS signature workflow ----
    std::cout << "\n[Step 5] Pending BLS signature workflow...\n";
    std::string blockHash = "block_hash_from_fisco_bcos_001";

    TEST("no-pending-init"); CHECK(!v.hasPendingBlsSignature());

    // Generate aggregated signature for blockHash (simulate Leader signing the block)
    bls::Signature aggSigForBlock; aggSigForBlock.clear();
    for (uint32_t i = 0; i < NUM_GROUPS; ++i) {
        aggSigForBlock.add(sign(sks[i], blockHash));
    }
    std::string aggSigHexForBlock = aggSigForBlock.serializeToHexStr();

    // Submit via "RPC" — verifies against blockHash then stores
    int rc = v.setPendingBlsSignature(aggSigHexForBlock, bmAll, blockHash);
    TEST("set-pending-ok"); CHECK_EQ(rc, BlsVerifier::OK);
    TEST("has-pending");    CHECK(v.hasPendingBlsSignature());

    // Try to set with wrong block hash (should reject)
    int rcBad = v.setPendingBlsSignature(aggSigHexForBlock, bmAll, "wrong_block_hash");
    TEST("set-pending-bad-msg"); CHECK_NE(rcBad, BlsVerifier::OK);

    // The still-valid pending signature should remain
    TEST("has-pending-after-reject"); CHECK(v.hasPendingBlsSignature());

    // Retrieve pending signature (simulates block sealing)
    std::string pendingSig, pendingBitmap;
    bool got = v.getPendingBlsSignature(pendingSig, pendingBitmap);
    TEST("get-pending");    CHECK(got);
    TEST("pending-sig-match"); CHECK_EQ(pendingSig, aggSigHexForBlock);
    TEST("pending-bitmap-match"); CHECK_EQ(pendingBitmap, bmAll);

    // Clear pending (simulates block sealed successfully)
    v.clearPendingBlsSignature();
    TEST("cleared"); CHECK(!v.hasPendingBlsSignature());

    // ---- Step 6: Consensus verification pattern simulation ----
    // Simulates what BlockValidator.checkBlsAggregatedSignature() does:
    // 1. Read blsAggregatedSignature from block header
    // 2. Read parentInfo[0].blockHash as the signed message
    // 3. Call BlsVerifier.verify()
    std::cout << "\n[Step 6] Consensus verification pattern simulation...\n";

    // Generate signature for parentHash (simulate Leader signing block N's hash)
    std::string parentHashHex = "parent_block_aaaaaabbbbccccdddd";
    bls::Signature sigForParent; sigForParent.clear();
    for (uint32_t i = 0; i < NUM_GROUPS; ++i) {
        sigForParent.add(sign(sks[i], parentHashHex));
    }
    std::string sigForParentHex = sigForParent.serializeToHexStr();

    // RPC: submit for block N
    rc = v.setPendingBlsSignature(sigForParentHex, bmAll, parentHashHex);
    TEST("set-pending-parent"); CHECK_EQ(rc, BlsVerifier::OK);

    // On the next block: the node reads pendingSig + parentHash from header
    std::string actualSig, actualBitmap;
    CHECK(v.getPendingBlsSignature(actualSig, actualBitmap));
    CHECK_EQ(actualSig, sigForParentHex);

    // Verify using the parent hash from the block header
    TEST("verify-parent-hash"); CHECK(v.verify(actualSig, actualBitmap, parentHashHex));
    TEST("verify-wrong-parent"); CHECK(!v.verify(actualSig, actualBitmap, "wrong_parent_hash"));

    // Clear for next round
    v.clearPendingBlsSignature();
    TEST("cleared-final"); CHECK(!v.hasPendingBlsSignature());

    // ---- Step 7: Concurrent access safety ----
    std::cout << "\n[Step 7] Concurrent access safety...\n";
    std::atomic<int> concurrentOk{0};
    const int numThreads = 4;

    auto threadFunc = [&](int threadId) {
        // Each thread registers a different group and verifies
        uint32_t gid = static_cast<uint32_t>(11 + threadId);
        bls::SecretKey sk = randomSk();
        bls::PublicKey pk = getPub(sk);
        std::string pkStr = pk.serializeToHexStr();

        int rc1 = v.setGroupPublicKey(gid, pkStr);
        if (rc1 == BlsVerifier::OK) {
            concurrentOk++;
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(threadFunc, i);
    }
    for (auto& t : threads) { t.join(); }

    TEST("concurrent-register"); CHECK_EQ(concurrentOk.load(), numThreads);
    TEST("post-concurrent-count"); CHECK_EQ(v.groupCount(), (size_t)(NUM_GROUPS + numThreads));

    // ---- Summary ----
    std::cout << "\n============================================================" << std::endl;
    std::cout << "  Results: " << g_pass << " passed, " << g_fail << " failed" << std::endl;
    if (g_fail == 0) {
        std::cout << "  All tests passed!" << std::endl;
    }
    std::cout << "============================================================" << std::endl;

    return g_fail == 0 ? 0 : 1;
}
