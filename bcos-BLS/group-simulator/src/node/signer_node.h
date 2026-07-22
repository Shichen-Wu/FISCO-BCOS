#ifndef GROUP_SIMULATOR_NODE_SIGNER_NODE_H_
#define GROUP_SIMULATOR_NODE_SIGNER_NODE_H_

#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include <string>

class SignerNode {
public:
    SignerNode(NodeId node_id, const FrNative& sk_share, uint32_t aggregator_id);

    SigShareMessage sign(const std::string& block_hash);
    NodeId getNodeId() const { return node_id_; }
    uint32_t getAggregatorId() const { return aggregator_id_; }
    const SigShareMessage& getLastSignature() const { return last_signature_; }

private:
    NodeId      node_id_;
    FrNative    secret_key_share_;
    uint32_t    aggregator_id_;
    SigShareMessage last_signature_;
};

#endif
