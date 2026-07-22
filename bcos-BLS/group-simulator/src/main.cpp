#include "common/config.h"
#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include "network/simulator.h"
#include <iostream>
#include <chrono>
#include <string>

int main(int argc, char* argv[]) {
    GroupConfig config = parseCommandLine(argc, argv);

    if (config.block_hash.empty()) {
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        config.block_hash = "test_block_" + std::to_string(config.group_id)
                          + "_" + std::to_string(ts);
        std::cout << "[Warning] 未指定区块哈希, 使用测试哈希: "
                  << config.block_hash << std::endl;
    }

    if (!config.validate()) {
        std::cerr << "错误: 配置验证失败!" << std::endl;
        return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "  组模拟程序 (Group Simulator)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "组ID:          " << config.group_id << std::endl;
    std::cout << "节点总数:      " << config.total_nodes << std::endl;
    std::cout << "门限阈值:      " << config.threshold
              << " (" << (100.0 * config.threshold / config.total_nodes) << "%)"
              << std::endl;
    std::cout << "聚合器数量:    " << config.num_aggregators << std::endl;
    std::cout << "每聚合器节点:  " << config.nodesPerAggregator() << std::endl;
    std::cout << "区块哈希:      " << config.block_hash << std::endl;
    std::cout << "网络模式:      "
              << (config.network_mode ? "真实网络" : "进程内模拟") << std::endl;
    if (config.network_mode) {
        std::cout << "Leader地址:    " << config.leader_address
                  << ":" << config.leader_port << std::endl;
    }
    std::cout << "Leader地址:    " << config.leader_address
              << ":" << config.leader_port << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n[Init] 正在初始化BLS密码学库..." << std::endl;
    if (!BlsWrapper::init()) {
        std::cerr << "错误: BLS库初始化失败!" << std::endl;
        return 1;
    }
    std::cout << "[Init] BLS库初始化成功 (BLS12-381, 默认模式)" << std::endl;

    try {
        NetworkSimulator simulator(config);
        if (config.network_mode) {
            return simulator.runNetworkLoop();
        }
        SimulationResult result = simulator.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
}
