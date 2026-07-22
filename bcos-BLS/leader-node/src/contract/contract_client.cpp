#include "contract/contract_client.h"
#include "contract/abi_codec.h"
#include <iostream>

bool ContractClient::initialize(
        const std::string& contract_address,
        const std::string& abi_file,
        const std::vector<std::string>& fisco_nodes) {

    contract_address_ = contract_address;

    if (contract_address.empty()) {
        std::cout << "[ContractClient] 未配置合约地址, 使用本地验证模式"
                  << std::endl;
    } else {
        std::cout << "[ContractClient] 合约地址: " << contract_address_
                  << std::endl;
        // TODO: 初始化 FISCO-BCOS SDK 连接
        for (const auto& node : fisco_nodes) {
            std::cout << "[ContractClient] 节点: " << node << std::endl;
        }
    }

    initialized_ = true;
    return true;
}

ContractCallResult ContractClient::verifySignature(
        const SigHex&    aggregated_sig,
        const PubKeyHex& aggregated_pub,
        const Uint256&   group_bitmap,
        const std::string& message) {

    ContractCallResult result;
    result.success = false;

    // 生成 calldata
    std::string calldata = AbiCodec::encodeVerifyCall(
        aggregated_sig, aggregated_pub, group_bitmap, message);

    if (!contract_address_.empty()) {
        // TODO: 调用 FISCO-BCOS SDK 发送交易
        std::cout << "[ContractClient] 模拟发送交易到合约 "
                  << contract_address_ << std::endl;
        std::cout << "[ContractClient] calldata 大小: "
                  << calldata.size() << " bytes" << std::endl;

        result.success = true;
        result.tx_hash = "0x" + std::string(64, '0'); // placeholder
        result.gas_used = 150000;
    } else {
        // 本地验证模式: 仅输出参数，不做链上调用
        std::cout << "[ContractClient] (本地模式) 链上提交已跳过"
                  << std::endl;
        result.success = true;
        result.tx_hash = "local";
        result.gas_used = 0;
    }

    return result;
}
