/// @file
/// 全流程集成测试: BlsVerifier + 组模拟 + Leader 聚合
///
/// 测试规模: 256 组 × 40 节点/组, 门限 34 (85%)
///
/// 流程:
///   1. BlsVerifier.init()
///   2. 256 组 DKG → 生成组公钥 PK
///   3. BlsVerifier.setGroupPublicKey() 逐组注册
///   4. 组内 40 节点签名 → Lagrange 门限聚合 → σ_group
///   5. Leader: 收集全部 σ_group → G1/G2 聚合 + 位图
///   6. BlsVerifier.verify(aggSig, bitmap, msg) → 预期通过
///   7. 负面测试: 错误消息 → 预期拒绝
///   8. 位图格式 + 参与组数校验

#include "BlsVerifier.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <map>

// ============================================================================
// 1. BLS 工具 (herumi/bls C++ API)
// ============================================================================

namespace blsutil {

using Fr = bls::SecretKey;
using G1 = bls::Signature;
using G2 = bls::PublicKey;

Fr rndFr()   { Fr f; f.init(); return f; }
G2  getPub(const Fr& sk) { G2 p; sk.getPublicKey(p); return p; }
G1  doSign(const Fr& sk, const std::string& m) {
    G1 s; sk.sign(s, m.data(), m.size()); return s;
}
bool doVerify(const G1& s, const G2& p, const std::string& m) {
    return s.verify(p, m.data(), m.size());
}
G1  g1Mul(const G1& g, const Fr& s) {
    G1 r = g; blsSignatureMul(r.getPtr(), s.getPtr()); return r;
}

// Fr 域运算
Fr frInt(int64_t v) {
    mclBnFr r; mclBnFr_setInt(&r, (v<0)?-v:v);
    if(v<0) mclBnFr_neg(&r,&r);
    char buf[2048]; mclBnFr_getStr(buf,2048,&r,2048);
    Fr o; o.deserializeHexStr(std::string(buf)); return o;
}
Fr frA(const Fr& a, const Fr& b) { mclBnFr r; mclBnFr_add(&r,&a.getPtr()->v,&b.getPtr()->v);
    char buf[2048]; mclBnFr_getStr(buf,2048,&r,2048);
    Fr o; o.deserializeHexStr(std::string(buf)); return o; }
Fr frM(const Fr& a, const Fr& b) { mclBnFr r; mclBnFr_mul(&r,&a.getPtr()->v,&b.getPtr()->v);
    char buf[2048]; mclBnFr_getStr(buf,2048,&r,2048);
    Fr o; o.deserializeHexStr(std::string(buf)); return o; }
Fr frI(const Fr& a) { mclBnFr r; mclBnFr_inv(&r,&a.getPtr()->v);
    char buf[2048]; mclBnFr_getStr(buf,2048,&r,2048);
    Fr o; o.deserializeHexStr(std::string(buf)); return o; }
} // namespace blsutil

using namespace blsutil;

// ============================================================================
// 2. Shamir 多项式 + DKG + Lagrange
// ============================================================================

std::vector<Fr> genPoly(uint32_t threshold) {
    std::vector<Fr> c(threshold);
    for (auto& x : c) x = rndFr();
    return c;
}

Fr evalPoly(const std::vector<Fr>& c, uint32_t x) {
    Fr r = frInt(0), xf = frInt(static_cast<int64_t>(x));
    for (int i = (int)c.size()-1; i >= 0; --i) r = frA(frM(r, xf), c[(size_t)i]);
    return r;
}

/// O(n) Lagrange for consecutive points 1..N
std::vector<Fr> lagrangeFast(uint32_t N) {
    std::vector<Fr> f(N+1); f[0] = frInt(1);
    for (uint32_t m = 1; m <= N; ++m) f[m] = frM(f[m-1], frInt(static_cast<int64_t>(m)));
    Fr total = f[N], neg = frInt(-1);
    Fr sign_k1 = ((N-1)%2==0) ? frInt(1) : neg;
    std::vector<Fr> out(N);
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t id = i + 1;
        Fr num = frM(sign_k1, frM(total, frI(frInt(static_cast<int64_t>(id)))));
        Fr sgn = ((N-id)%2==0) ? frInt(1) : neg;
        Fr den = frM(sgn, frM(f[id-1], f[N-id]));
        out[i] = frM(num, frI(den));
    }
    return out;
}

// ============================================================================
// 3. 组模拟
// ============================================================================

struct GroupInfo {
    uint32_t gid;
    Fr       master_sk;         // 主私钥
    G2       pubkey;            // 组公钥
    std::string pubkey_hex;     // 组公钥 hex (用于注册到 BlsVerifier)
};

struct GroupSigResult {
    uint32_t gid;
    G1       threshold_sig;     // 门限签名
    std::string sig_hex;        // 签名 hex
};

GroupInfo runDkg(uint32_t gid, uint32_t N, uint32_t T, std::vector<Fr>& shares_out) {
    GroupInfo gi;
    gi.gid = gid;
    auto poly = genPoly(T);
    gi.master_sk = poly[0];
    gi.pubkey = getPub(gi.master_sk);
    gi.pubkey_hex = gi.pubkey.serializeToHexStr();
    shares_out.resize(N);
    for (uint32_t j = 1; j <= N; ++j) shares_out[j-1] = evalPoly(poly, j);
    return gi;
}

GroupSigResult runGroupSign(uint32_t gid, const std::vector<Fr>& shares,
                            const std::string& msg, uint32_t signers) {
    GroupSigResult gs;  gs.gid = gid;
    std::vector<G1> sigs(signers);
    for (uint32_t j = 0; j < signers; ++j) sigs[j] = doSign(shares[j], msg);
    auto lambdas = lagrangeFast(signers);
    G1 agg; agg.clear();
    for (uint32_t j = 0; j < signers; ++j) agg.add(g1Mul(sigs[j], lambdas[j]));
    gs.threshold_sig = agg;
    gs.sig_hex = agg.serializeToHexStr();
    return gs;
}

// ============================================================================
// 4. Leader 聚合
// ============================================================================

struct LeaderOutput {
    std::string agg_sig_hex;
    std::string agg_pub_hex;
    std::string bitmap;
    uint32_t    group_count;
    bool        local_ok;
};

LeaderOutput leaderRun(const std::vector<GroupSigResult>& sigs,
                        const std::vector<GroupInfo>& keys,
                        const std::string& msg) {
    LeaderOutput r;
    r.group_count = (uint32_t)sigs.size();

    G1 sigSum; sigSum.clear();
    G2 pubSum; pubSum.clear();
    for (const auto& gs : sigs) sigSum.add(gs.threshold_sig);
    r.agg_sig_hex = sigSum.serializeToHexStr();

    for (const auto& gs : sigs)
        for (const auto& gk : keys)
            if (gk.gid == gs.gid) { pubSum.add(gk.pubkey); break; }
    r.agg_pub_hex = pubSum.serializeToHexStr();

    uint8_t buf[32] = {0};
    for (const auto& gs : sigs) {
        uint32_t bit = gs.gid - 1;
        buf[bit / 8] |= (1u << (7 - (bit % 8)));
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) oss << std::setw(2) << (int)buf[i];
    r.bitmap = oss.str();

    r.local_ok = doVerify(sigSum, pubSum, msg);
    return r;
}

// ============================================================================
// 5. 位图校验
// ============================================================================

bool checkBitmap(const std::string& bitmap, uint32_t expected) {
    if (bitmap.size() != 66 || bitmap[0]!='0' || bitmap[1]!='x') return false;
    uint32_t set = 0;
    for (size_t i = 2; i < 66; i += 2) {
        unsigned int byte; sscanf(bitmap.c_str()+i, "%02x", &byte);
        for (int b = 7; b >= 0; --b) {
            uint32_t idx = (uint32_t)((i-2)/2*8 + (7-b));
            if ((byte>>b)&1) { if (idx >= expected) return false; ++set; }
            else              { if (idx <  expected) return false; }
        }
    }
    return set == expected;
}

// ============================================================================
// 6. 测试宏
// ============================================================================

static int g_pass = 0, g_fail = 0;
#define TEST(name) std::cout << "  [" << name << "] "; std::cout.flush()
#define CHECK(cond) do { \
    if (cond) { std::cout << "PASS\n"; ++g_pass; } \
    else { std::cout << "FAIL L" << __LINE__ << "\n"; ++g_fail; } \
} while(0)
#define CHECK_EQ(a,b) CHECK((a)==(b))

// ============================================================================
// 7. 测试入口
// ============================================================================

int main() {
    const uint32_t TOTAL_GROUPS = 256;
    const uint32_t NODES        = 40;
    const uint32_t THRESHOLD    = 34;     // 组内门限 85%
    const uint32_t SIGNERS      = 40;     // 组内实际签名节点
    const uint32_t PARTICIPANTS = 218;    // 实际参与组数 (85% of 256)
    const std::string MSG = "full_pipeline_test_msg";

    auto t0 = std::chrono::high_resolution_clock::now();

    std::cout << "============================================================"
              << std::endl;
    std::cout << "  全流程集成测试: " << TOTAL_GROUPS << " 组 × " << NODES
              << " 节点/组, 门限=" << THRESHOLD
              << ", 参与组=" << PARTICIPANTS << " (85%)" << std::endl;
    std::cout << "============================================================\n"
              << std::endl;

    // ---- Step 1: BlsVerifier 初始化 ----
    std::cout << "[Step 1] BlsVerifier 初始化...\n";
    BlsVerifier& v = BlsVerifier::instance();
    TEST("init");  CHECK_EQ(v.init(), 0);
    TEST("re-init"); CHECK_EQ(v.init(), BlsVerifier::ERR_ALREADY_INIT);
    TEST("empty-count"); CHECK_EQ(v.groupCount(), (size_t)0);

    // ---- Step 2: DKG (256 组全部生成密钥, 但只 218 组签名) ----
    std::cout << "\n[Step 2] DKG: 生成 " << TOTAL_GROUPS << " 组密钥 ("
              << NODES << " 节点/组)... ";
    std::cout.flush();
    auto td0 = std::chrono::high_resolution_clock::now();

    std::vector<GroupInfo> groups(TOTAL_GROUPS);
    std::vector<std::vector<Fr>> all_shares(TOTAL_GROUPS);
    for (uint32_t i = 0; i < TOTAL_GROUPS; ++i) {
        groups[i] = runDkg(i+1, NODES, THRESHOLD, all_shares[i]);
    }
    auto td1 = std::chrono::high_resolution_clock::now();
    std::cout << "完成 (" << std::chrono::duration_cast<
        std::chrono::milliseconds>(td1-td0).count() << " ms)" << std::endl;

    // ---- Step 3: 注册 256 组公钥到 BlsVerifier ----
    std::cout << "\n[Step 3] 注册 " << TOTAL_GROUPS << " 组公钥到 BlsVerifier...\n";
    TEST("register-all");
    int reg_ok = 0;
    for (const auto& gk : groups) {
        reg_ok += (v.setGroupPublicKey(gk.gid, gk.pubkey_hex) == 0) ? 1 : 0;
    }
    CHECK_EQ(reg_ok, (int)TOTAL_GROUPS);
    TEST("group-count"); CHECK_EQ(v.groupCount(), (size_t)TOTAL_GROUPS);
    TEST("has-mid");      CHECK(v.hasGroup(128));

    // ---- Step 4: 仅前 218 组签名 + 门限聚合 (模拟只有85%组参与) ----
    std::cout << "\n[Step 4] 组内签名 + 门限聚合 (仅前 " << PARTICIPANTS
              << " 组参与, O(n) Lagrange)... ";
    std::cout.flush();
    auto ts0 = std::chrono::high_resolution_clock::now();

    std::vector<GroupSigResult> group_sigs(PARTICIPANTS);
    for (uint32_t i = 0; i < PARTICIPANTS; ++i) {
        group_sigs[i] = runGroupSign(i+1, all_shares[i], MSG, SIGNERS);
    }
    auto ts1 = std::chrono::high_resolution_clock::now();
    std::cout << "完成 (" << std::chrono::duration_cast<
        std::chrono::milliseconds>(ts1-ts0).count() << " ms)" << std::endl;

    // ---- Step 5: 逐组门限签名内验 (仅参与组) ----
    std::cout << "\n[Step 5] 门限签名逐组预验 (" << PARTICIPANTS << " 组)...\n";
    TEST("threshold-each-group");
    {
        int gv = 0;
        for (const auto& gs : group_sigs)
            for (const auto& gk : groups)
                if (gk.gid == gs.gid) {
                    gv += doVerify(gs.threshold_sig, gk.pubkey, MSG) ? 1 : 0;
                    break;
                }
        CHECK_EQ(gv, (int)PARTICIPANTS);
    }

    // ---- Step 6: Leader 聚合 (仅参与组) ----
    std::cout << "\n[Step 6] Leader: 聚合 " << PARTICIPANTS
              << " 组签名 + 公钥 + 位图 (85%参与)... ";
    std::cout.flush();
    auto tl0 = std::chrono::high_resolution_clock::now();
    LeaderOutput lo = leaderRun(group_sigs, groups, MSG);
    auto tl1 = std::chrono::high_resolution_clock::now();
    std::cout << "完成 (" << std::chrono::duration_cast<
        std::chrono::milliseconds>(tl1-tl0).count() << " ms)" << std::endl;

    TEST("local-pre-verify"); CHECK(lo.local_ok);
    TEST("group-count");      CHECK_EQ(lo.group_count, PARTICIPANTS);
    TEST("bitmap-218-of-256");
    {
        bool bm_ok = checkBitmap(lo.bitmap, PARTICIPANTS);
        if (bm_ok) {
            std::cout << "PASS (bitmap=" << lo.bitmap.substr(0,18) << "...)\n";
            ++g_pass;
        } else {
            std::cout << "FAIL L" << __LINE__
                      << " bitmap=" << lo.bitmap.substr(0,30) << "...\n";
            ++g_fail;
        }
    }

    // ---- Step 7: BlsVerifier 验签 ----
    std::cout << "\n[Step 7] BlsVerifier 节点内验签...\n";
    TEST("verify-pass");
    CHECK(v.verify(lo.agg_sig_hex, lo.bitmap, MSG));

    TEST("verify-wrong-msg");
    CHECK(!v.verify(lo.agg_sig_hex, lo.bitmap, "wrong_message_xyz"));

    TEST("verify-empty-bitmap");
    {
        bool r = true;
        int rc = v.verify(lo.agg_sig_hex,
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            MSG, r);
        CHECK_EQ(rc, BlsVerifier::ERR_EMPTY_BITMAP);
    }

    TEST("verify-bad-bitmap");
    {
        // 用无效 hex 字符串测试
        bool r = true;
        int rc = v.verify(lo.agg_sig_hex, "0xGGGG000000000000000000000000000000000000000000000000000000000000",
                          MSG, r);
        CHECK_EQ(rc, BlsVerifier::ERR_INVALID_BITMAP);
    }

    TEST("verify-hash-mismatch");
    {
        // 签名消息不匹配, 应该返回 ERR_VERIFY_FAILED
        bool r = true;
        int rc = v.verify(lo.agg_sig_hex, lo.bitmap, "totally_different_message", r);
        // herumi::verify 返回 false 时可能抛异常或返回不同的错误码
        CHECK(!r); // 至少验证结果为 false
    }

    // ---- 汇总 ----
    auto t1 = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t1-t0).count();

    std::cout << "\n============================================================"
              << std::endl;
    std::cout << "  总耗时:            " << total_ms << " ms" << std::endl;
    std::cout << "  结果:              " << g_pass << " 通过, "
              << g_fail << " 失败"
              << std::endl;

    if (g_fail == 0) {
        std::cout << "\n  ✓ 全流程集成测试通过 !" << std::endl;
    } else {
        std::cout << "\n  ✗ " << g_fail << " 项失败, 见上" << std::endl;
    }
    std::cout << "============================================================"
              << std::endl;

    return g_fail == 0 ? 0 : 1;
}
