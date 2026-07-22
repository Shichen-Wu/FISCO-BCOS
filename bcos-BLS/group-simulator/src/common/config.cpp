#include "common/config.h"
#include <iostream>
#include <cstring>
#include <cstdlib>

void printUsage(const char* prog_name) {
    std::cout << "用法: " << prog_name << " [选项]\n"
              << "选项:\n"
              << "  --group-id N          组ID (1-256, 默认: 1)\n"
              << "  --num-nodes N         组内节点总数 (默认: 4000)\n"
              << "  --threshold N         门限阈值 (默认: 3400, 即85%)\n"
              << "  --num-aggregators N   聚合器数量 (默认: 10)\n"
              << "  --block-hash HASH     区块哈希 (hex)\n"
              << "  --leader-address ADDR Leader节点地址 (默认: 进程内模拟)\n"
              << "  --leader-port PORT   Leader HTTP端口 (默认: 9000)\n"
              << "  --output-dir DIR      输出目录 (默认: ./output)\n"
              << "  --help                打印帮助信息\n"
              << "\n"
              << "示例:\n"
              << "  " << prog_name << " --group-id 1 --block-hash 0xabcd...\n"
              << "  " << prog_name << " --group-id 5 --num-nodes 1000 --threshold 850 --num-aggregators 5\n"
              << std::endl;
}

GroupConfig parseCommandLine(int argc, char* argv[]) {
    GroupConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            std::exit(0);
        } else if (arg == "--group-id" && i + 1 < argc) {
            config.group_id = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--num-nodes" && i + 1 < argc) {
            config.total_nodes = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--threshold" && i + 1 < argc) {
            config.threshold = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--num-aggregators" && i + 1 < argc) {
            config.num_aggregators = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--block-hash" && i + 1 < argc) {
            config.block_hash = argv[++i];
        } else if (arg == "--leader-address" && i + 1 < argc) {
            config.leader_address = argv[++i];
            config.network_mode = true;
        } else if (arg == "--leader-port" && i + 1 < argc) {
            config.leader_port = std::stoi(argv[++i]);
        } else if (arg == "--output-dir" && i + 1 < argc) {
            config.output_dir = argv[++i];
        } else {
            std::cerr << "未知参数: " << arg << std::endl;
            printUsage(argv[0]);
            std::exit(1);
        }
    }

    return config;
}
