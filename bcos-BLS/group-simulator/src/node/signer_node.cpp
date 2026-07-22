#include "node/signer_node.h"

SignerNode::SignerNode(NodeId node_id, const FrNative& sk_share,
                       uint32_t aggregator_id)
    : node_id_(node_id), secret_key_share_(sk_share)
    , aggregator_id_(aggregator_id) {}

SigShareMessage SignerNode::sign(const std::string& block_hash) {
    G1Native sig = BlsWrapper::sign(secret_key_share_, block_hash);

    SigShareMessage msg;
    msg.node_id    = node_id_;
    msg.signature  = BlsWrapper::g1ToHex(sig);
    msg.block_hash = block_hash;
    last_signature_ = msg;
    return msg;
}
