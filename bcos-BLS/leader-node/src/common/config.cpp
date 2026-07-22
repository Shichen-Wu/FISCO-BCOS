#include "common/config.h"
#include <iostream>
#include <cstring>
#include <cstdlib>

void printUsage(const char* prog_name) {
    std::cout << "用法: " << prog_name << " [选项]\n"
              << "选项:\n"
              << "  --total-groups N         总组数 (默认: 256)\n"
              << "  --min-threshold N        最少需要的组签名数 (默认: 205, 即80%)\n"
              << "  --block-hash HASH        区块哈希 (hex)\n"
              << "  --group-pubkeys FILE     组公钥JSON文件路径\n"
              << "  --group-sigs-dir DIR     组签名文件目录 (每个文件一组)\n"
              << "  --output-dir DIR         输出目录 (默认: ./output)\n"
              << "  --contract-address ADDR  验签合约地址\n"
              << "  --fisco-node ADDR        FISCO-BCOS节点地址 (可重复)\n"
              << "  --network-mode           启用网络模式 (HTTP接收签名 + 轮询FISCO-BCOS)\n"
              << "  --listen-port PORT       Leader HTTP监听端口 (默认: 9000)\n"
              << "  --fisco-rpc HOST:PORT    FISCO-BCOS RPC地址 (可多次指定，如4个节点)\n"
              << "  --generate-test-data     自动生成256组测试签名数据\n"
              << "  --help                   打印帮助\n"
              << "\n"
              << "示例:\n"
              << "  " << prog_name << " --generate-test-data --block-hash 0xabcd...\n"
              << "  " << prog_name << " --group-sigs-dir ./sigs --group-pubkeys pubkeys.json\n"
              << std::endl;
}

LeaderConfig parseCommandLine(int argc, char* argv[]) {
    LeaderConfig config;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            std::exit(0);
        } else if (arg == "--total-groups" && i + 1 < argc) {
            config.total_groups = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--min-threshold" && i + 1 < argc) {
            config.min_group_threshold = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--block-hash" && i + 1 < argc) {
            config.block_hash = argv[++i];
        } else if (arg == "--group-pubkeys" && i + 1 < argc) {
            config.group_pubkeys_file = argv[++i];
        } else if (arg == "--group-sigs-dir" && i + 1 < argc) {
            config.group_sigs_dir = argv[++i];
        } else if (arg == "--output-dir" && i + 1 < argc) {
            config.output_dir = argv[++i];
        } else if (arg == "--contract-address" && i + 1 < argc) {
            config.contract_address = argv[++i];
        } else if (arg == "--fisco-node" && i + 1 < argc) {
            config.fisco_nodes.push_back(argv[++i]);
        } else if (arg == "--generate-test-data") {
            config.generate_test_data = true;
        } else if (arg == "--network-mode") {
            config.network_mode = true;
        } else if (arg == "--listen-port" && i + 1 < argc) {
            config.listen_port = std::stoi(argv[++i]);
        } else if (arg == "--fisco-rpc" && i + 1 < argc) {
            // multiple nodes: --fisco-rpc 127.0.0.1:20200 --fisco-rpc 127.0.0.1:20201 ...
            config.fisco_rpc_nodes.push_back(argv[++i]);
        } else {
            std::cerr << "未知参数: " << arg << std::endl;
            printUsage(argv[0]);
            std::exit(1);
        }
    }
    return config;
}
