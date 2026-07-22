#ifndef GROUP_SIMULATOR_NODE_NODE_MANAGER_H_
#define GROUP_SIMULATOR_NODE_NODE_MANAGER_H_

#include "common/types.h"
#include "common/config.h"
#include "node/signer_node.h"
#include <vector>
#include <map>
#include <memory>

class NodeManager {
public:
    void initialize(const GroupConfig& config,
                    const std::map<NodeId, KeyShare>& key_shares);

    std::vector<SigShareMessage> signAll(const std::string& block_hash);
    SignerNode* getNode(NodeId node_id);
    const std::vector<std::unique_ptr<SignerNode>>& getAllNodes() const {
        return nodes_;
    }
    size_t size() const { return nodes_.size(); }

private:
    std::vector<std::unique_ptr<SignerNode>> nodes_;
    uint32_t total_nodes_ = 0;
};

#endif
