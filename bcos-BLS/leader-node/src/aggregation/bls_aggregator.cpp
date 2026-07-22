#include "aggregation/bls_aggregator.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>

BlsAggregator::BlsAggregator(
        uint32_t total_groups, uint32_t min_threshold,
        const std::map<GroupId, PubKeyHex>& group_pubkeys)
    : total_groups_(total_groups)
    , min_threshold_(min_threshold)
    , group_pubkeys_(group_pubkeys) {
}

bool BlsAggregator::addGroupSignature(const GroupThresholdSignature& gs) {
    if (gs.group_id < 1 || gs.group_id > total_groups_) {
        std::cerr << "[Aggregator] 无效的组ID: " << gs.group_id << std::endl;
        return false;
    }
    if (collected_sigs_.count(gs.group_id)) {
        return false; // 已收集过
    }

    // 验证签名 block_hash 一致
    if (block_hash_.empty()) {
        block_hash_ = gs.block_hash;
    } else if (gs.block_hash != block_hash_) {
        std::cerr << "[Aggregator] 组 " << gs.group_id
                  << " 区块哈希不匹配!" << std::endl;
        return false;
    }

    // 验证门限签名本身的有效性: e(σ, G2) == e(H(m), PK)
    {
        auto pk_it = group_pubkeys_.find(gs.group_id);
        if (pk_it == group_pubkeys_.end()) {
            std::cerr << "[Aggregator] 组 " << gs.group_id
                      << " 公钥缺失!" << std::endl;
            return false;
        }
        G1Native sig = BlsWrapper::g1FromHex(gs.signature);
        G2Native pub = BlsWrapper::g2FromHex(pk_it->second);
        if (!BlsWrapper::verify(sig, pub, gs.block_hash)) {
            std::cerr << "[Aggregator] 组 " << gs.group_id
                      << " 门限签名验签失败!" << std::endl;
            return false;
        }
    }

    collected_sigs_[gs.group_id] = gs.signature;
    ++collected_count_;

    return true;
}

std::vector<GroupId> BlsAggregator::missingGroups() const {
    std::vector<GroupId> missing;
    for (GroupId gid = 1; gid <= total_groups_; ++gid) {
        if (!collected_sigs_.count(gid)) {
            missing.push_back(gid);
        }
    }
    return missing;
}

AggregationResult BlsAggregator::aggregate() {
    auto t0 = std::chrono::high_resolution_clock::now();

    AggregationResult result;
    result.block_hash = block_hash_;

    // 1. 聚合签名 (G1 加法)
    std::vector<G1Native> sigs;
    sigs.reserve(collected_sigs_.size());
    for (const auto& kv : collected_sigs_) {
        sigs.push_back(BlsWrapper::g1FromHex(kv.second));
    }
    G1Native agg_sig = BlsWrapper::aggregateSignatures(sigs);
    result.aggregated_signature = BlsWrapper::g1ToHex(agg_sig);

    // 2. 聚合公钥 (G2 加法)
    std::vector<G2Native> pubs;
    pubs.reserve(collected_sigs_.size());
    for (const auto& kv : collected_sigs_) {
        auto it = group_pubkeys_.find(kv.first);
        if (it != group_pubkeys_.end()) {
            pubs.push_back(BlsWrapper::g2FromHex(it->second));
        }
    }
    G2Native agg_pub = BlsWrapper::aggregatePublicKeys(pubs);
    result.aggregated_pubkey = BlsWrapper::g2ToHex(agg_pub);

    // 3. 生成组标识位图 (uint256, big-endian hex)
    {
        // bit(i-1) = 1 表示组 i 参与
        // 256 bits = 32 bytes → hex
        uint8_t bitmap_bytes[32] = {0};
        for (const auto& kv : collected_sigs_) {
            GroupId gid = kv.first;                     // 1-based
            uint32_t bit_pos = gid - 1;                 // 0-based in bitmap
            uint32_t byte_idx = bit_pos / 8;
            uint32_t bit_idx  = 7 - (bit_pos % 8);      // MSB-first
            bitmap_bytes[byte_idx] |= (1u << bit_idx);
        }
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 32; ++i) {
            oss << std::setw(2) << static_cast<int>(bitmap_bytes[i]);
        }
        result.group_bitmap = "0x" + oss.str();
    }

    result.group_count = static_cast<uint32_t>(collected_sigs_.size());

    auto t1 = std::chrono::high_resolution_clock::now();
    result.aggregate_time_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t1 - t0).count();

    return result;
}

void BlsAggregator::reset() {
    collected_sigs_.clear();
    collected_count_ = 0;
    block_hash_.clear();
}
