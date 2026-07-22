#include "aggregator/aggregator.h"
#include <iostream>

Aggregator::Aggregator(uint32_t aggr_id, const GroupConfig& config,
                       uint32_t lead_aggr_id)
    : aggregator_id_(aggr_id), config_(config)
    , threshold_(config.threshold), lead_aggr_id_(lead_aggr_id)
    , threshold_aggregator_(
          std::make_unique<ThresholdAggregator>(config.threshold)) {}

void Aggregator::reset() { collected_shares_.clear(); }

void Aggregator::collectShare(const SigShareMessage& share) {
    collected_shares_.push_back(share);
}

void Aggregator::collectShares(const std::vector<SigShareMessage>& shares) {
    for (const auto& s : shares) collected_shares_.push_back(s);
}

GroupThresholdSignature Aggregator::aggregate(
        const std::vector<SigShareMessage>& all_shares,
        const std::string& block_hash) {

    GroupThresholdSignature result;
    result.group_id    = config_.group_id;
    result.num_signers = static_cast<uint32_t>(all_shares.size());
    result.block_hash  = block_hash;
    for (const auto& s : all_shares) {
        result.signer_ids.push_back(s.node_id);
    }

    G1Native raw_sig = threshold_aggregator_->aggregate(all_shares);
    result.signature = BlsWrapper::g1ToHex(raw_sig);
    return result;
}
