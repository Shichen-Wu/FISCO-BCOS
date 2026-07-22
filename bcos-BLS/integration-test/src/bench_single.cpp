/// 单组性能基准测试: DKG + 10 轮签名聚合
#include <bls/bls.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cstdio>

using Fr = bls::SecretKey;
using G1 = bls::Signature;
using G2 = bls::PublicKey;

// ---- BLS 工具 ----
bool initBLS() {
    int e = ::blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    return e == 0;
}
Fr rndFr() { Fr f; f.init(); return f; }
Fr frInt(int64_t v) {
    mclBnFr r; mclBnFr_setInt(&r, v < 0 ? -v : v);
    if (v < 0) mclBnFr_neg(&r, &r);
    char b[2048]; mclBnFr_getStr(b, sizeof(b), &r, 2048);
    Fr o; o.deserializeHexStr(std::string(b)); return o;
}
Fr frAdd(Fr a, Fr b) { mclBnFr r; mclBnFr_add(&r, &a.getPtr()->v, &b.getPtr()->v);
    char x[2048]; mclBnFr_getStr(x,2048,&r,2048); Fr o; o.deserializeHexStr(std::string(x)); return o; }
Fr frMul(Fr a, Fr b) { mclBnFr r; mclBnFr_mul(&r, &a.getPtr()->v, &b.getPtr()->v);
    char x[2048]; mclBnFr_getStr(x,2048,&r,2048); Fr o; o.deserializeHexStr(std::string(x)); return o; }
Fr frInv(Fr a) { mclBnFr r; mclBnFr_inv(&r, &a.getPtr()->v);
    char x[2048]; mclBnFr_getStr(x,2048,&r,2048); Fr o; o.deserializeHexStr(std::string(x)); return o; }
G2 pubkey(Fr sk) { G2 p; sk.getPublicKey(p); return p; }
G1 sign(Fr sk, const std::string& m) { G1 s; sk.sign(s, m.data(), m.size()); return s; }
bool verify(G1 sig, G2 pub, const std::string& m) { return sig.verify(pub, m.data(), m.size()); }
G1 g1Mul(G1 g, Fr s) { G1 r=g; blsSignatureMul(r.getPtr(), s.getPtr()); return r; }

// ---- 多项式求值 (Horner) ----
Fr polyEval(const std::vector<Fr>& c, uint32_t x) {
    Fr r = frInt(0), xf = frInt(x);
    for (int i = (int)c.size()-1; i >= 0; --i) r = frAdd(frMul(r, xf), c[(size_t)i]);
    return r;
}

// ---- Lagrange 系数 (O(n) 快速版, 连续点 1..k) ----
std::vector<Fr> lagrangeFast(uint32_t k) {
    std::vector<Fr> fact(k+1);
    fact[0] = frInt(1);
    for (uint32_t m = 1; m <= k; ++m) fact[m] = frMul(fact[m-1], frInt(m));
    Fr total = fact[k], neg = frInt(-1);
    Fr sign_k1 = ((k-1)%2==0) ? frInt(1) : neg;
    std::vector<Fr> out(k);
    for (uint32_t i = 0; i < k; ++i) {
        uint32_t id = i + 1;
        Fr num = frMul(sign_k1, frMul(total, frInv(frInt(id))));
        Fr sgn = ((k-id)%2==0) ? frInt(1) : neg;
        Fr den = frMul(sgn, frMul(fact[id-1], fact[k-id]));
        out[i] = frMul(num, frInv(den));
    }
    return out;
}

int main() {
    if (!initBLS()) { std::cerr << "BLS init fail\n"; return 1; }

    const uint32_t N = 4000, T = 3400;
    std::string msg = "benchmark_block_hash";

    // ========== DKG ==========
    auto dkg0 = std::chrono::high_resolution_clock::now();

    // 生成 T-1 次多项式
    std::vector<Fr> poly(T);
    for (auto& c : poly) c = rndFr();
    Fr master_sk = poly[0];
    G2 group_pk = pubkey(master_sk);

    // 为 N 个节点求值份额 sk_j = f(j)
    std::vector<Fr> shares(N);
    for (uint32_t j = 1; j <= N; ++j) shares[j-1] = polyEval(poly, j);

    auto dkg1 = std::chrono::high_resolution_clock::now();
    auto dkg_ms = std::chrono::duration_cast<std::chrono::milliseconds>(dkg1-dkg0).count();

    std::cout << "===== 单组性能基准 (N=" << N << ", T=" << T << ") =====\n\n";
    std::cout << "[DKG] 多项式生成 + " << N << " 节点份额求值 : "
              << dkg_ms << " ms\n\n";

    // ========== 10 轮签名 + 聚合 ==========
    auto lambdas = lagrangeFast(N);  // O(N) 预计算

    int64_t sign_total = 0, aggr_total = 0, verify_total = 0;

    for (int round = 0; round < 10; ++round) {
        std::string rmsg = msg + "_round" + std::to_string(round);

        // --- 签名 ---
        auto s0 = std::chrono::high_resolution_clock::now();
        std::vector<G1> sigs(N);
        for (uint32_t j = 0; j < N; ++j) sigs[j] = sign(shares[j], rmsg);
        auto s1 = std::chrono::high_resolution_clock::now();
        sign_total += std::chrono::duration_cast<std::chrono::milliseconds>(s1-s0).count();

        // --- 门限聚合 ---
        auto a0 = std::chrono::high_resolution_clock::now();
        G1 agg; agg.clear();
        for (uint32_t j = 0; j < N; ++j) { G1 t = g1Mul(sigs[j], lambdas[j]); agg.add(t); }
        auto a1 = std::chrono::high_resolution_clock::now();
        aggr_total += std::chrono::duration_cast<std::chrono::milliseconds>(a1-a0).count();

        // --- 验签 ---
        auto v0 = std::chrono::high_resolution_clock::now();
        bool ok = verify(agg, group_pk, rmsg);
        auto v1 = std::chrono::high_resolution_clock::now();
        verify_total += std::chrono::duration_cast<std::chrono::milliseconds>(v1-v0).count();

        std::cout << "  轮次 " << (round+1) << ": 验签=" << (ok?"通过":"失败")
                  << "\n";
    }

    std::cout << "\n===== 统计 (10轮) =====\n";
    std::cout << "签名平均: " << (sign_total/10) << " ms/轮\n";
    std::cout << "聚合平均: " << (aggr_total/10) << " ms/轮\n";
    std::cout << "验签平均: " << (verify_total/10) << " ms/轮\n";
    std::cout << "总计(含DKG): " << (dkg_ms + sign_total + aggr_total + verify_total) << " ms\n";
    return 0;
}
