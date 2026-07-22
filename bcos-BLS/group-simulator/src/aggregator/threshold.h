#ifndef GROUP_SIMULATOR_AGGREGATOR_THRESHOLD_H_
#define GROUP_SIMULATOR_AGGREGATOR_THRESHOLD_H_

#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include <vector>

class ThresholdAggregator {
public:
    explicit ThresholdAggregator(uint32_t threshold);

    G1Native aggregate(const std::vector<SigShareMessage>& shares) const;
    G1Native aggregateRaw(const std::vector<G1Native>& signatures,
                           const std::vector<NodeId>& signer_ids) const;

private:
    FrNative lagrangeCoefficientZero(const std::vector<NodeId>& all_signers,
                                      NodeId i) const;
    uint32_t threshold_;
};

#endif
