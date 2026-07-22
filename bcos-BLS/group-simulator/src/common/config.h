#ifndef GROUP_SIMULATOR_COMMON_CONFIG_H_
#define GROUP_SIMULATOR_COMMON_CONFIG_H_

#include <cstdint>
#include <string>
#include <cassert>
#include "common/types.h"

struct GroupConfig {
    // === 组参数 ===
    uint32_t    group_id        = 1;     ///< 组ID (1-256)
    uint32_t    total_nodes     = 4000;  ///< 组内节点总数
    uint32_t    threshold       = 3400;  ///< 门限阈值 (85%)
    uint32_t    num_aggregators = 10;    ///< 聚合器数量

    // === 区块信息 ===
    std::string block_hash;             ///< 当前区块哈希 (hex string)

    // === 输出 ===
    std::string output_dir;             ///< 输出目录

    // === Leader 连接 (网络模式) ===
    std::string leader_address;         ///< Leader地址 (host)
    int         leader_port = 9000;     ///< Leader HTTP 端口
    bool        network_mode = false;   ///< 是否启用真实网络 (false=进程内模拟)

    /// 验证参数合法性
    bool validate() const {
        if (group_id < 1 || group_id > 256) return false;
        if (total_nodes == 0) return false;
        if (threshold > total_nodes) return false;
        if (num_aggregators == 0) return false;
        if (total_nodes % num_aggregators != 0) return false;
        return true;
    }

    /// 每个聚合器负责的节点数
    uint32_t nodesPerAggregator() const {
        return total_nodes / num_aggregators;
    }

    /// 计算某节点对应的聚合器ID
    uint32_t aggregatorForNode(NodeId node_id) const {
        // node_id 从 1 开始
        return (node_id - 1) / nodesPerAggregator();
    }
};

/// 解析命令行参数
GroupConfig parseCommandLine(int argc, char* argv[]);

/// 打印用法
void printUsage(const char* prog_name);

#endif // GROUP_SIMULATOR_COMMON_CONFIG_H_
