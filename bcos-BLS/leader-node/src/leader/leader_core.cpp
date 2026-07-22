#include "leader/leader_core.h"
#include <iostream>
#include <iomanip>
#include <chrono>

LeaderCore::LeaderCore(const LeaderConfig& config)
    : config_(config) {
}

int LeaderCore::run() {
    auto t_start = std::chrono::high_resolution_clock::now();

    // Phase 1: 初始化
    if (!initialize()) {
        std::cerr << "初始化失败!" << std::endl;
        return 1;
    }

    // network mode: start HTTP server and polling, wait for signatures
    if (config_.network_mode) {
        return runNetworkMode();
    }

    // Phase 2: 收集签名
    auto sigs = collectSignatures();

    // Phase 3: 聚合 + 提交
    bool ok = aggregateAndSubmit(sigs);

    auto t_end = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t_end - t_start).count();

    std::cout << "\n========== Leader 节点结果 ==========" << std::endl;
    std::cout << "收集组签名数:   " << sigs.size()
              << " / " << config_.total_groups << std::endl;
    std::cout << "最低阈值:       " << config_.min_group_threshold << std::endl;
    std::cout << "聚合+提交结果:  " << (ok ? "成功" : "失败") << std::endl;
    std::cout << "总耗时:         " << total_ms << " ms" << std::endl;
    std::cout << "======================================" << std::endl;

    return ok ? 0 : 1;
}

/// network mode: continuously receive signatures, aggregate, submit to FISCO-BCOS
int LeaderCore::runNetworkMode() {
    std::cout << "\n[Network] Starting HTTP server on port " << config_.listen_port << "...\n";

    httpServer_ = std::make_unique<bcos::bls::LeaderHttpServer>(
        config_.listen_port, group_pubkeys_, config_.total_groups, config_.min_group_threshold,
        config_.fisco_rpc_nodes);

    if (!httpServer_->start()) {
        std::cerr << "Failed to start HTTP server!" << std::endl;
        return 1;
    }

    // start polling FISCO-BCOS for latest block hash (uses first FISCO node)
    httpServer_->startBlockPolling(2000);

    std::cout << "[Network] FISCO nodes: ";
    for (auto& n : config_.fisco_rpc_nodes) { std::cout << n << " "; }
    std::cout << std::endl;

    std::cout << "[Network] Leader running. Waiting for group pubkeys and signatures...\n";
    std::cout << "[Network] Groups register at POST /register_pubkey\n";
    std::cout << "[Network] Groups submit signatures at POST /submit_signature\n";
    std::cout << "[Network] Groups poll hash at GET /latest_block_hash\n";
    std::cout << "[Network] Press Ctrl+C to stop.\n";

    // main loop: wait for threshold, aggregate, submit
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (httpServer_->isThresholdReached()) {
            std::cout << "\n[Network] Threshold reached! Aggregating and submitting...\n";

            auto result = httpServer_->getAggregationResult();
            std::string blockHash = httpServer_->getLatestBlockHash();
            if (blockHash.empty()) {
                blockHash = config_.block_hash; // fallback
            }

            std::cout << "  参与组数:     " << result.group_count << "\n";
            std::cout << "  位图:         " << result.group_bitmap.substr(0, 18) << "...\n";

            // submit aggregated signature to ALL FISCO-BCOS nodes
            // (sealer rotates, any node could be the next block producer)
            for (const auto& node : config_.fisco_rpc_nodes) {
                bcos::bls::LeaderHttpServer::submitAggSigToFisco(
                    node, result.aggregated_signature, result.group_bitmap, blockHash);
            }

            // reset for next round
            httpServer_->resetForNextRound();
            std::cout << "[Network] Reset for next block round.\n";
        }
    }

    return 0;
}

bool LeaderCore::initialize() {
    std::cout << "\n[Phase 1] 初始化 Leader 节点..." << std::endl;

    collector_     = std::make_unique<SignatureCollector>();
    contract_client_ = std::make_unique<ContractClient>();

    // 1.1 加载组公钥 (优先从文件, 否则生成测试数据)
    if (!config_.group_pubkeys_file.empty()) {
        group_pubkeys_ = collector_->loadPublicKeys(config_.group_pubkeys_file);
    }

    // 1.2 无公钥时动态生成 (仅测试模式; 网络模式下等待组模拟器通过HTTP注册)
    if (group_pubkeys_.empty() && !config_.network_mode) {
        std::cout << "[Leader] 无预载公钥, 正在生成 "
                  << config_.total_groups << " 组测试密钥对..." << std::endl;
        for (GroupId gid = 1; gid <= config_.total_groups; ++gid) {
            FrNative sk = BlsWrapper::generateSecretKey();
            G2Native pk = BlsWrapper::getPublicKey(sk);
            group_pubkeys_[gid] = BlsWrapper::g2ToHex(pk);
            group_seckeys_[gid]  = BlsWrapper::frToHex(sk);
        }
        // 保存公钥 (私钥仅内存持有, 不落盘)
        std::string out_file = config_.output_dir + "/group_pubkeys.json";
        collector_->savePublicKeys(out_file, group_pubkeys_);
    }

    // 1.3 初始化 BLS 聚合器
    aggregator_ = std::make_unique<BlsAggregator>(
        config_.total_groups, config_.min_group_threshold, group_pubkeys_);

    // 1.4 初始化合约客户端
    contract_client_->initialize(
        config_.contract_address,
        config_.contract_abi_file,
        config_.fisco_nodes);

    std::cout << "[Phase 1] 初始化完成: 共 " << group_pubkeys_.size()
              << " 组公钥" << std::endl;
    return true;
}

std::map<GroupId, GroupThresholdSignature> LeaderCore::collectSignatures() {
    std::cout << "\n[Phase 2] 收集组签名..." << std::endl;

    std::map<GroupId, GroupThresholdSignature> sigs;

    if (config_.generate_test_data) {
        sigs = collector_->generateTestData(group_seckeys_, config_.block_hash);
    } else {
        // 从文件加载
        sigs = collector_->loadFromDirectory(config_.group_sigs_dir);
    }

    // 将签名喂入聚合器 (run verification on each)
    uint32_t valid_count = 0;
    for (auto& kv : sigs) {
        if (aggregator_->addGroupSignature(kv.second)) {
            ++valid_count;
        }
    }

    std::cout << "[Phase 2] 收集完成: " << sigs.size()
              << " 组签名, 有效 " << valid_count
              << ", 已达到阈值: "
              << (aggregator_->isThresholdReached() ? "是" : "否")
              << std::endl;

    return sigs;
}

bool LeaderCore::aggregateAndSubmit(
        const std::map<GroupId, GroupThresholdSignature>& sigs) {

    std::cout << "\n[Phase 3] 聚合 + 链上提交..." << std::endl;

    if (!aggregator_->isThresholdReached()) {
        std::cerr << "[Phase 3] 组签名数不足阈值! "
                  << aggregator_->collectedCount() << "/"
                  << config_.min_group_threshold << std::endl;
        auto missing = aggregator_->missingGroups();
        std::cout << "  缺失组数: " << missing.size() << std::endl;
        return false;
    }

    // 3.1 执行 BLS 聚合
    AggregationResult result = aggregator_->aggregate();

    std::cout << "  参与组数:       " << result.group_count << std::endl;
    std::cout << "  组位图:         " << result.group_bitmap.substr(0, 18)
              << "..." << std::endl;
    std::cout << "  聚合耗时:       " << result.aggregate_time_ms
              << " ms" << std::endl;

    // 3.2 本地预验证
    bool local_ok = localVerify(result);
    std::cout << "  本地预验签:     " << (local_ok ? "通过" : "失败")
              << std::endl;
    if (!local_ok) return false;

    // 3.3 链上提交
    std::cout << "\n[Phase 3] 提交到智能合约..." << std::endl;
    ContractCallResult call_result = contract_client_->verifySignature(
        result.aggregated_signature,
        result.aggregated_pubkey,
        result.group_bitmap,
        config_.block_hash);

    std::cout << "  交易哈希:       " << call_result.tx_hash << std::endl;
    std::cout << "  链上验证:       "
              << (call_result.success ? "成功" : "失败") << std::endl;
    if (!call_result.error_msg.empty()) {
        std::cout << "  错误信息:       " << call_result.error_msg << std::endl;
    }

    return call_result.success;
}

bool LeaderCore::localVerify(const AggregationResult& result) {
    // e(σ_agg, G2) == e(H(m), PK_agg)
    G1Native sig = BlsWrapper::g1FromHex(result.aggregated_signature);
    G2Native pub = BlsWrapper::g2FromHex(result.aggregated_pubkey);
    return BlsWrapper::verify(sig, pub, config_.block_hash);
}
