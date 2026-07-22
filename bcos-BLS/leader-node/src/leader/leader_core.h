#ifndef LEADER_NODE_LEADER_LEADER_CORE_H_
#define LEADER_NODE_LEADER_LEADER_CORE_H_

#include "common/types.h"
#include "common/config.h"
#include "aggregation/bls_aggregator.h"
#include "leader/signature_collector.h"
#include "contract/contract_client.h"
#include "network/leader_server.h"
#include <memory>
#include <chrono>
#include <thread>

/// Leader 核心协调逻辑
class LeaderCore {
public:
    explicit LeaderCore(const LeaderConfig& config);
    int run();

private:
    bool initialize();
    std::map<GroupId, GroupThresholdSignature> collectSignatures();
    int runNetworkMode();
    bool aggregateAndSubmit(
        const std::map<GroupId, GroupThresholdSignature>& sigs);
    bool localVerify(const AggregationResult& result);

    LeaderConfig config_;
    std::unique_ptr<BlsAggregator> aggregator_;
    std::unique_ptr<SignatureCollector> collector_;
    std::unique_ptr<ContractClient> contract_client_;
    std::unique_ptr<bcos::bls::LeaderHttpServer> httpServer_;

    std::map<GroupId, PubKeyHex> group_pubkeys_;
    std::map<GroupId, FrHex>     group_seckeys_;  ///< 测试模式下的私钥
};

#endif
