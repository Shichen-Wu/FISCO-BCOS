#ifndef GROUP_SIMULATOR_NETWORK_SIMULATOR_H_
#define GROUP_SIMULATOR_NETWORK_SIMULATOR_H_

#include "common/types.h"
#include "common/config.h"
#include "dkg/dkg_node.h"
#include "node/node_manager.h"
#include "aggregator/aggregator.h"
#include <vector>
#include <memory>
#include <chrono>

class NetworkSimulator {
public:
    NetworkSimulator(const GroupConfig& config);
    SimulationResult run();

    /// network mode: after DKG, enter loop: get block hash → sign → aggregate → send to Leader
    int runNetworkLoop();

    /// send threshold signature to Leader via HTTP
    bool sendToLeader(const GroupThresholdSignature& result);

private:
    void runDkgPhase();
    void runSignPhase(const std::string& block_hash);
    GroupThresholdSignature runAggregatePhase(const std::string& block_hash);
    bool verifyThresholdSignature(const GroupThresholdSignature& result,
                                  const std::string& block_hash);
    /// get latest block hash from Leader via HTTP
    std::string fetchBlockHashFromLeader();

    GroupConfig config_;
    std::unique_ptr<DkgNode>        dkg_node_;
    std::unique_ptr<NodeManager>    node_manager_;
    std::vector<std::unique_ptr<Aggregator>> aggregators_;
    std::vector<SigShareMessage> all_signatures_;
};

#endif
