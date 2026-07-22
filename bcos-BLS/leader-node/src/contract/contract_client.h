#ifndef LEADER_NODE_CONTRACT_CONTRACT_CLIENT_H_
#define LEADER_NODE_CONTRACT_CONTRACT_CLIENT_H_

#include "common/types.h"
#include <string>
#include <vector>

/// FISCO-BCOS 智能合约调用客户端
/// 当前为 stub 实现，合约代码完成后再接入真实 SDK
class ContractClient {
public:
    bool initialize(const std::string& contract_address,
                    const std::string& abi_file,
                    const std::vector<std::string>& fisco_nodes);

    ContractCallResult verifySignature(
        const SigHex&    aggregated_sig,
        const PubKeyHex& aggregated_pub,
        const Uint256&   group_bitmap,
        const std::string& message);

private:
    std::string contract_address_;
    bool initialized_ = false;
};

#endif
