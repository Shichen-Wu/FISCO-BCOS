#ifndef GROUP_SIMULATOR_AGGREGATOR_AGGREGATOR_H_
#define GROUP_SIMULATOR_AGGREGATOR_AGGREGATOR_H_

#include "common/types.h"
#include "common/config.h"
#include "aggregator/threshold.h"
#include <vector>
#include <memory>

class Aggregator {
public:
    Aggregator(uint32_t aggr_id, const GroupConfig& config,
               uint32_t lead_aggr_id = 0);

    void reset();
    void collectShare(const SigShareMessage& share);
    void collectShares(const std::vector<SigShareMessage>& shares);

    size_t collectedCount() const { return collected_shares_.size(); }
    bool isThresholdReached() const {
        return collected_shares_.size() >= threshold_;
    }
    const std::vector<SigShareMessage>& getCollectedShares() const {
        return collected_shares_;
    }

    GroupThresholdSignature aggregate(
        const std::vector<SigShareMessage>& all_shares,
        const std::string& block_hash);

private:
    [[maybe_unused]] uint32_t aggregator_id_;
    GroupConfig config_;
    uint32_t    threshold_;
    [[maybe_unused]] uint32_t lead_aggr_id_;
    std::unique_ptr<ThresholdAggregator> threshold_aggregator_;
    std::vector<SigShareMessage> collected_shares_;
};

#endif
