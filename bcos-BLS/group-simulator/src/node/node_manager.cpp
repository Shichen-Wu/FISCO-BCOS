#include "node/node_manager.h"
#include <iostream>
#include <stdexcept>

void NodeManager::initialize(const GroupConfig& config,
                              const std::map<NodeId, KeyShare>& key_shares) {
    total_nodes_ = config.total_nodes;
    nodes_.clear();
    nodes_.reserve(total_nodes_);

    for (NodeId id = 1; id <= total_nodes_; ++id) {
        auto it = key_shares.find(id);
        if (it == key_shares.end()) {
            throw std::runtime_error(
                "NodeManager: 缺少节点 " + std::to_string(id) + " 的密钥份额");
        }
        FrNative sk = BlsWrapper::frFromHex(it->second.secret_key_share);
        uint32_t aggr_id = config.aggregatorForNode(id);
        nodes_.push_back(std::make_unique<SignerNode>(id, sk, aggr_id));
    }

    std::cout << "[NodeManager] 已初始化 " << total_nodes_
              << " 个签名节点, 分配到 " << config.num_aggregators
              << " 个聚合器" << std::endl;
}

std::vector<SigShareMessage> NodeManager::signAll(const std::string& block_hash) {
    std::vector<SigShareMessage> results;
    results.reserve(nodes_.size());
    for (auto& node : nodes_) {
        results.push_back(node->sign(block_hash));
    }
    return results;
}

SignerNode* NodeManager::getNode(NodeId node_id) {
    if (node_id < 1 || node_id > static_cast<NodeId>(nodes_.size())) {
        return nullptr;
    }
    return nodes_[node_id - 1].get();
}
