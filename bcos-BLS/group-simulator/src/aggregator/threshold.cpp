#include "aggregator/threshold.h"
#include <iostream>

ThresholdAggregator::ThresholdAggregator(uint32_t threshold)
    : threshold_(threshold) {}

G1Native ThresholdAggregator::aggregate(
        const std::vector<SigShareMessage>& shares) const {
    std::vector<G1Native> sigs;
    std::vector<NodeId> ids;
    sigs.reserve(shares.size());
    ids.reserve(shares.size());
    for (const auto& s : shares) {
        sigs.push_back(BlsWrapper::g1FromHex(s.signature));
        ids.push_back(s.node_id);
    }
    return aggregateRaw(sigs, ids);
}

G1Native ThresholdAggregator::aggregateRaw(
        const std::vector<G1Native>& signatures,
        const std::vector<NodeId>& signer_ids) const {

    if (signatures.size() < threshold_) {
        std::cerr << "[Threshold] 警告: 签名份额不足! "
                  << "需要 " << threshold_ << ", 实际 " << signatures.size()
                  << std::endl;
    }

    G1Native result;
    result.clear();

    for (size_t idx = 0; idx < signatures.size(); ++idx) {
        FrNative lambda = lagrangeCoefficientZero(signer_ids, signer_ids[idx]);
        G1Native term = BlsWrapper::scalarMul(signatures[idx], lambda);
        result.add(term);
    }
    return result;
}

FrNative ThresholdAggregator::lagrangeCoefficientZero(
        const std::vector<NodeId>& all_signers, NodeId i) const {

    FrNative num = BlsWrapper::frFromInt(1);
    FrNative den = BlsWrapper::frFromInt(1);

    for (NodeId j : all_signers) {
        if (j == i) continue;
        FrNative neg_j = BlsWrapper::frNegate(
            BlsWrapper::frFromInt(static_cast<int64_t>(j)));
        num = BlsWrapper::frMul(num, neg_j);

        FrNative diff = BlsWrapper::frFromInt(
            static_cast<int64_t>(static_cast<int64_t>(i) -
                                 static_cast<int64_t>(j)));
        den = BlsWrapper::frMul(den, diff);
    }

    FrNative den_inv = BlsWrapper::frInverse(den);
    return BlsWrapper::frMul(num, den_inv);
}
