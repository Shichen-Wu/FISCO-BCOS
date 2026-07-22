#ifndef LEADER_NODE_COMMON_CONFIG_H_
#define LEADER_NODE_COMMON_CONFIG_H_

#include "common/types.h"
#include <cstdint>
#include <string>
#include <vector>

struct LeaderConfig {
    uint32_t total_groups        = 256;
    uint32_t min_group_threshold = 205;
    std::string block_hash;
    std::string group_pubkeys_file;
    std::string group_sigs_dir;
    std::string output_dir;
    std::string contract_address;
    std::string contract_abi_file;
    std::vector<std::string> fisco_nodes;
    // network mode: receive group signatures via HTTP, poll FISCO-BCOS, submit via RPC
    bool network_mode = false;
    int  listen_port = 9000;
    // FISCO-BCOS RPC node addresses (host:port), need at least 1 for polling, 4 for registration
    std::vector<std::string> fisco_rpc_nodes = {"127.0.0.1:20200"};
    bool generate_test_data = false;

    bool validate() const {
        if (total_groups == 0 || total_groups > 256) return false;
        if (min_group_threshold > total_groups) return false;
        return true;
    }
};

LeaderConfig parseCommandLine(int argc, char* argv[]);
void printUsage(const char* prog_name);

#endif
