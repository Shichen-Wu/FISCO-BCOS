#include "common/config.h"
#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include "leader/leader_core.h"
#include <iostream>
#include <chrono>

int main(int argc, char* argv[]) {
    LeaderConfig config = parseCommandLine(argc, argv);

    // 无区块哈希时生成测试哈希
    if (config.block_hash.empty()) {
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        config.block_hash = "leader_test_block_" + std::to_string(ts);
        std::cout << "[Warning] 未指定区块哈希, 使用: "
                  << config.block_hash << std::endl;
    }

    // 默认输出目录
    if (config.output_dir.empty()) {
        config.output_dir = "./output";
    }

    if (!config.validate()) {
        std::cerr << "错误: 配置验证失败!" << std::endl;
        return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "  Leader 节点 (Leader Node)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "总组数:        " << config.total_groups << std::endl;
    std::cout << "最低阈值:      " << config.min_group_threshold
              << " (" << (100.0 * config.min_group_threshold / config.total_groups)
              << "%)" << std::endl;
    std::cout << "区块哈希:      " << config.block_hash << std::endl;
    std::cout << "模式:          "
              << (config.generate_test_data ? "生成测试数据" : "文件加载")
              << std::endl;
    std::cout << "合约地址:      "
              << (config.contract_address.empty() ? "(本地模式)" : config.contract_address)
              << std::endl;
    if (config.network_mode) {
        std::cout << "网络模式:      启用" << std::endl;
        std::cout << "监听端口:      " << config.listen_port << std::endl;
        std::cout << "FISCO节点:     ";
        for (auto& n : config.fisco_rpc_nodes) { std::cout << n << " "; }
        std::cout << std::endl;
    }
    std::cout << "========================================" << std::endl;

    // 初始化 BLS 库
    std::cout << "\n[Init] 正在初始化 BLS 密码学库..." << std::endl;
    if (!BlsWrapper::init()) {
        std::cerr << "错误: BLS 库初始化失败!" << std::endl;
        return 1;
    }
    std::cout << "[Init] BLS 库初始化成功" << std::endl;

    try {
        LeaderCore leader(config);
        return leader.run();
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
}
