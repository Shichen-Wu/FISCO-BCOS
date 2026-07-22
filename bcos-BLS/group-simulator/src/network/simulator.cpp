#include "network/simulator.h"
#include "common/SimpleHttp.h"
#include <iostream>
#include <chrono>
#include <stdexcept>
#include <sstream>

NetworkSimulator::NetworkSimulator(const GroupConfig& config)
    : config_(config) {
    if (!config_.validate())
        throw std::runtime_error("GroupConfig 验证失败");
}

SimulationResult NetworkSimulator::run() {
    SimulationResult result;
    result.group_id = config_.group_id;
    result.threshold_required = config_.threshold;

    auto total_start = std::chrono::high_resolution_clock::now();

    auto t1 = std::chrono::high_resolution_clock::now();
    runDkgPhase();
    auto t2 = std::chrono::high_resolution_clock::now();
    result.dkg_time_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t2 - t1).count();

    auto t3 = std::chrono::high_resolution_clock::now();
    runSignPhase(config_.block_hash);
    auto t4 = std::chrono::high_resolution_clock::now();
    result.sign_time_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t4 - t3).count();

    auto t5 = std::chrono::high_resolution_clock::now();
    GroupThresholdSignature threshold_sig = runAggregatePhase(config_.block_hash);
    auto t6 = std::chrono::high_resolution_clock::now();
    result.aggregate_time_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t6 - t5).count();

    result.signatures_collected = static_cast<uint32_t>(all_signatures_.size());
    result.threshold_reached =
        (result.signatures_collected >= config_.threshold);

    if (result.threshold_reached) {
        result.threshold_signature_hex = threshold_sig.signature;
    }

    if (result.threshold_reached) {
        bool ok = verifyThresholdSignature(threshold_sig, config_.block_hash);
        std::cout << "[Validator] 门限签名内验: "
                  << (ok ? "通过" : "失败") << std::endl;
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(total_end - total_start).count();

    std::cout << "\n========== 组 " << config_.group_id
              << " 模拟结果 ==========" << std::endl;
    std::cout << "节点总数:         " << config_.total_nodes << std::endl;
    std::cout << "门限阈值:         " << config_.threshold << std::endl;
    std::cout << "收集签名数:       " << result.signatures_collected << std::endl;
    std::cout << "达到阈值:         "
              << (result.threshold_reached ? "是" : "否") << std::endl;
    std::cout << "DKG耗时:          " << result.dkg_time_ms << " ms" << std::endl;
    std::cout << "签名耗时:         " << result.sign_time_ms << " ms" << std::endl;
    std::cout << "聚合耗时:         " << result.aggregate_time_ms << " ms" << std::endl;
    std::cout << "总耗时:           " << total_ms << " ms" << std::endl;
    if (result.threshold_reached) {
        std::cout << "门限签名(hex):    "
                  << result.threshold_signature_hex.substr(0, 64) << "..."
                  << std::endl;
    }
    std::cout << "================================" << std::endl;

    return result;
}

void NetworkSimulator::runDkgPhase() {
    std::cout << "\n[Phase 1] DKG 密钥初始化..." << std::endl;

    dkg_node_ = std::make_unique<DkgNode>(config_.threshold, config_.total_nodes);
    dkg_node_->execute();

    node_manager_ = std::make_unique<NodeManager>();
    node_manager_->initialize(config_, dkg_node_->getAllKeyShares());

    aggregators_.clear();
    aggregators_.reserve(config_.num_aggregators);
    for (uint32_t i = 0; i < config_.num_aggregators; ++i) {
        aggregators_.push_back(std::make_unique<Aggregator>(i, config_, 0));
    }
    std::cout << "[Phase 1] 已初始化 " << config_.num_aggregators
              << " 个聚合器节点" << std::endl;
}

void NetworkSimulator::runSignPhase(const std::string& block_hash) {
    std::cout << "\n[Phase 2] 签名阶段: 节点数=" << config_.total_nodes
              << ", 区块哈希=" << block_hash << std::endl;

    all_signatures_ = node_manager_->signAll(block_hash);

    for (const auto& sig : all_signatures_) {
        uint32_t aggr_id = config_.aggregatorForNode(sig.node_id);
        aggregators_[aggr_id]->collectShare(sig);
    }

    for (size_t i = 0; i < aggregators_.size(); ++i) {
        std::cout << "  聚合器[" << i << "] 收集签名份额: "
                  << aggregators_[i]->collectedCount() << std::endl;
    }
    std::cout << "[Phase 2] 签名完成, 总计 " << all_signatures_.size()
              << " 个签名份额" << std::endl;
}

GroupThresholdSignature NetworkSimulator::runAggregatePhase(
        const std::string& block_hash) {
    std::cout << "\n[Phase 3] 聚合阶段..." << std::endl;

    std::vector<SigShareMessage> all_collected;
    for (auto& aggr : aggregators_) {
        const auto& shares = aggr->getCollectedShares();
        all_collected.insert(all_collected.end(), shares.begin(), shares.end());
    }

    std::cout << "  牵头聚合器[0] 汇总所有份额: " << all_collected.size()
              << " 个" << std::endl;

    if (all_collected.size() < config_.threshold) {
        std::cout << "  警告: 签名份额不足门限! "
                  << "需要 " << config_.threshold
                  << ", 实际 " << all_collected.size() << std::endl;
    }

    GroupThresholdSignature result = aggregators_[0]->aggregate(
        all_collected, block_hash);

    std::cout << "[Phase 3] 门限签名聚合完成, "
              << result.num_signers << " 个签名参与聚合" << std::endl;
    return result;
}

bool NetworkSimulator::verifyThresholdSignature(
        const GroupThresholdSignature& result,
        const std::string& block_hash) {
    G2Native group_pk = dkg_node_->getGroupPublicKey();
    G1Native sig = BlsWrapper::g1FromHex(result.signature);
    return BlsWrapper::verify(sig, group_pk, block_hash);
}

/// Send threshold signature to Leader via HTTP POST
bool NetworkSimulator::sendToLeader(const GroupThresholdSignature& result) {
    std::ostringstream body;
    body << "{"
         << "\"group_id\":" << result.group_id << ","
         << "\"signature\":\"" << result.signature << "\","
         << "\"num_signers\":" << result.num_signers << ","
         << "\"block_hash\":\"" << result.block_hash << "\""
         << "}";
    std::string resp = bcos::bls::net::httpPost(
        config_.leader_address, config_.leader_port, "/submit_signature", body.str());
    if (resp.empty()) {
        std::cerr << "[Group " << config_.group_id << "] HTTP POST failed" << std::endl;
        return false;
    }
    std::cout << "[Group " << config_.group_id << "] → Leader: " << resp << std::endl;
    return true;
}

/// Fetch latest block hash from Leader via HTTP GET
std::string NetworkSimulator::fetchBlockHashFromLeader() {
    std::string resp = bcos::bls::net::httpGet(
        config_.leader_address, config_.leader_port, "/latest_block_hash");
    // simple JSON parsing: {"block_hash":"0x...","block_number":N}
    auto pos = resp.find("\"block_hash\"");
    if (pos != std::string::npos) {
        auto start = resp.find('"', pos + 13);
        auto end = resp.find('"', start + 1);
        if (start != std::string::npos && end != std::string::npos) {
            return resp.substr(start + 1, end - start - 1);
        }
    }
    return "";
}

/// Network mode: DKG once, then loop: poll hash → sign → aggregate → send
int NetworkSimulator::runNetworkLoop() {
    std::cout << "[Network] Group " << config_.group_id
              << " entering network mode, Leader at " << config_.leader_address
              << ":" << config_.leader_port << std::endl;

    // Phase 1: DKG (one-time)
    runDkgPhase();

    // Signal DKG complete by sending group public key
    {
        std::ostringstream pkBody;
        pkBody << "{"
               << "\"group_id\":" << config_.group_id << ","
               << "\"public_key\":\"" << dkg_node_->getGroupPublicKeyHex() << "\""
               << "}";
        bcos::bls::net::httpPost(config_.leader_address, config_.leader_port,
            "/register_pubkey", pkBody.str());
    }

    // Loop: get hash, sign, aggregate, send
    std::cout << "[Network] Group " << config_.group_id
              << " entering signing loop..." << std::endl;
    std::string lastHash;

    while (true) {
        // fetch latest block hash from Leader (Leader polls FISCO-BCOS)
        std::string blockHash = fetchBlockHashFromLeader();
        if (blockHash.empty() || blockHash == lastHash) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }
        lastHash = blockHash;
        std::cout << "[Group " << config_.group_id << "] new block hash: "
                  << blockHash << std::endl;

        // sign the block hash
        runSignPhase(blockHash);

        // aggregate threshold signature
        GroupThresholdSignature thresholdSig = runAggregatePhase(blockHash);

        // verify locally
        if (thresholdSig.num_signers >= config_.threshold) {
            bool ok = verifyThresholdSignature(thresholdSig, blockHash);
            std::cout << "[Group " << config_.group_id << "] threshold sig verify: "
                      << (ok ? "PASS" : "FAIL") << std::endl;

            // send to Leader
            if (ok) {
                sendToLeader(thresholdSig);
            }
        }
    }

    return 0;
}
