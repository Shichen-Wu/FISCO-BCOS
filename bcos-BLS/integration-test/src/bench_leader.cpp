/// Leader 聚合性能基准: 256 组, 收集 80% (205组) → 聚合 → 验签 × 10轮
#include <bls/bls.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cstdio>
#include <cstring>

using Fr = bls::SecretKey;
using G1 = bls::Signature;
using G2 = bls::PublicKey;

bool initBLS() {
    int e = ::blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    return e == 0;
}
Fr rndFr() { Fr f; f.init(); return f; }
G2 pubkey(Fr sk) { G2 p; sk.getPublicKey(p); return p; }
G1 sign(Fr sk, const std::string& m) { G1 s; sk.sign(s, m.data(), m.size()); return s; }
bool verify(G1 sig, G2 pub, const std::string& m) { return sig.verify(pub, m.data(), m.size()); }

int main() {
    if (!initBLS()) { std::cerr << "BLS init fail\n"; return 1; }

    const uint32_t G = 256;       // 总组数
    const uint32_t Q = 205;       // 80% 参与组数

    std::string msg = "leader_bench_block";

    // === 一次性生成 256 组密钥对 ===
    auto k0 = std::chrono::high_resolution_clock::now();
    std::vector<Fr> sks(G);
    std::vector<G2> pks(G);
    for (uint32_t i = 0; i < G; ++i) {
        sks[i] = rndFr();
        pks[i] = pubkey(sks[i]);
    }
    auto k1 = std::chrono::high_resolution_clock::now();
    auto keygen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(k1 - k0).count();

    std::cout << "===== Leader 聚合基准 (256 组, 收集 " << Q << " 组 = 80%) =====\n\n";
    std::cout << "[初始化] 256 组密钥对生成: " << keygen_ms << " ms\n\n";

    // === 10 轮测试 ===
    int64_t sign_total = 0, aggr_total = 0, verify_total = 0;

    for (int round = 0; round < 10; ++round) {
        std::string rmsg = msg + "_r" + std::to_string(round);

        // --- 生成 205 个组的门限签名 (模拟各组聚合器发送) ---
        auto s0 = std::chrono::high_resolution_clock::now();
        std::vector<G1> sigs(Q);
        for (uint32_t i = 0; i < Q; ++i) sigs[i] = sign(sks[i], rmsg);
        auto s1 = std::chrono::high_resolution_clock::now();
        sign_total += std::chrono::duration_cast<std::chrono::milliseconds>(s1 - s0).count();

        // --- Leader 聚合签名 + 公钥 (G1 + G2 加法) ---
        auto a0 = std::chrono::high_resolution_clock::now();
        G1 agg_sig; agg_sig.clear();
        G2 agg_pub; agg_pub.clear();
        for (uint32_t i = 0; i < Q; ++i) {
            agg_sig.add(sigs[i]);
            agg_pub.add(pks[i]);
        }
        auto a1 = std::chrono::high_resolution_clock::now();
        aggr_total += std::chrono::duration_cast<std::chrono::milliseconds>(a1 - a0).count();

        // --- 验签 ---
        auto v0 = std::chrono::high_resolution_clock::now();
        bool ok = verify(agg_sig, agg_pub, rmsg);
        auto v1 = std::chrono::high_resolution_clock::now();
        verify_total += std::chrono::duration_cast<std::chrono::milliseconds>(v1 - v0).count();

        std::cout << "  轮次 " << (round + 1) << ": 验签=" << (ok ? "通过" : "失败") << "\n";
    }

    std::cout << "\n===== 统计 (10 轮) =====\n";
    std::cout << "签名生成平均: " << (sign_total / 10) << " ms/轮  (205 次 BLS 签名)\n";
    std::cout << "Leader 聚合平均: " << (aggr_total / 10)
              << " ms/轮  (G1+G2 各 205 次加法)\n";
    std::cout << "验签平均: " << (verify_total / 10) << " ms/轮\n";

    auto total = keygen_ms + sign_total + aggr_total + verify_total;
    std::cout << "总计: " << total << " ms\n";
    return 0;
}
