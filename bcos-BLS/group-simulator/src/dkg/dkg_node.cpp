#include "dkg/dkg_node.h"
#include <iostream>

DkgNode::DkgNode(uint32_t threshold, uint32_t total_nodes)
    : threshold_(threshold), total_nodes_(total_nodes)
    , polynomial_(threshold) {}

void DkgNode::execute() {
    std::cout << "[DKG] 开始密钥初始化: 门限=" << threshold_
              << ", 节点数=" << total_nodes_ << std::endl;

    FrNative master_sk = polynomial_.getSecret();
    group_public_key_ = BlsWrapper::getPublicKey(master_sk);

    key_shares_.clear();
    for (NodeId j = 1; j <= total_nodes_; ++j) {
        KeyShare share;
        share.node_id = j;
        share.secret_key_share = BlsWrapper::frToHex(polynomial_.evaluate(j));
        key_shares_[j] = share;
    }

    std::cout << "[DKG] 组公钥 (hex): " << getGroupPublicKeyHex() << std::endl;
    std::cout << "[DKG] 已生成 " << total_nodes_ << " 个密钥份额" << std::endl;
    deleteMasterKey();
}

PubKeyHex DkgNode::getGroupPublicKeyHex() const {
    return BlsWrapper::g2ToHex(group_public_key_);
}

const KeyShare* DkgNode::getKeyShare(NodeId node_id) const {
    auto it = key_shares_.find(node_id);
    return (it != key_shares_.end()) ? &it->second : nullptr;
}

void DkgNode::deleteMasterKey() {
    std::cout << "[DKG] 主私钥已删除 (模拟)" << std::endl;
}
