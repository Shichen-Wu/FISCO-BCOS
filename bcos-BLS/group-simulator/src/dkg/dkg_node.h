#ifndef GROUP_SIMULATOR_DKG_DKG_NODE_H_
#define GROUP_SIMULATOR_DKG_DKG_NODE_H_

#include "common/types.h"
#include "dkg/polynomial.h"
#include "crypto/bls_wrapper.h"
#include <vector>
#include <map>
#include <string>

class DkgNode {
public:
    DkgNode(uint32_t threshold, uint32_t total_nodes);
    void execute();

    G2Native getGroupPublicKey() const { return group_public_key_; }
    PubKeyHex getGroupPublicKeyHex() const;

    const KeyShare* getKeyShare(NodeId node_id) const;
    const std::map<NodeId, KeyShare>& getAllKeyShares() const {
        return key_shares_;
    }

    uint32_t getThreshold() const { return threshold_; }
    uint32_t getTotalNodes() const { return total_nodes_; }

private:
    uint32_t    threshold_;
    uint32_t    total_nodes_;
    Polynomial  polynomial_;
    G2Native    group_public_key_;
    std::map<NodeId, KeyShare> key_shares_;

    void deleteMasterKey();
};

#endif
