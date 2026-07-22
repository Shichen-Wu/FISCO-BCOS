/// @file
/// Leader's HTTP server for receiving group signatures and coordinating with FISCO-BCOS.
///
/// Full workflow for a new block round:
///   Block N produced → Leader polls FISCO-BCOS → hash H_N stored
///   → Group simulators poll /latest_block_hash → sign H_N
///   → Group simulators POST /submit_signature
///   → Threshold reached → Leader aggregates → Leader RPC-submits to FISCO-BCOS

#ifndef BCOS_BLS_LEADER_SERVER_H_
#define BCOS_BLS_LEADER_SERVER_H_

#include "common/SimpleHttp.h"
#include "common/types.h"
#include "aggregation/bls_aggregator.h"
#include "crypto/bls_wrapper.h"
#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <sstream>

namespace bcos::bls {

class LeaderHttpServer {
public:
    LeaderHttpServer(int port, const std::map<GroupId, PubKeyHex>& groupPubkeys,
                     uint32_t totalGroups, uint32_t minThreshold,
                     const std::vector<std::string>& fiscoNodes = {})
        : port_(port)
        , totalGroups_(totalGroups)
        , minThreshold_(minThreshold)
        , groupPubkeys_(groupPubkeys)
        , fiscoNodes_(fiscoNodes)
    {
        rebuildAggregator();
    }

    ~LeaderHttpServer() { stop(); }

    bool start() {
        server_ = std::make_unique<net::SimpleHttpServer>(port_,
            [this](const net::ParsedRequest& req) -> std::string {
                return handleRequest(req);
            });
        if (!server_->start()) { return false; }
        return true;
    }

    void stop() {
        keepPolling_ = false;
        if (pollThread_.joinable()) { pollThread_.join(); }
        if (server_) { server_->stop(); }
    }

    /// Start polling FISCO-BCOS for latest block hash (uses first FISCO node)
    void startBlockPolling(int intervalMs = 2000) {
        if (fiscoNodes_.empty()) {
            std::cerr << "[LeaderServer] no FISCO nodes configured, polling disabled" << std::endl;
            return;
        }
        keepPolling_ = true;
        pollThread_ = std::thread([this, intervalMs]() {
            pollFiscoBlocks(intervalMs);
        });
    }

    /// Get latest block hash (thread-safe)
    std::string getLatestBlockHash() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return latestBlockHash_;
    }

    /// Check if enough groups have registered and aggregation threshold is reached
    bool isThresholdReached() const { return aggregator_->isThresholdReached(); }

    /// Get aggregation result
    AggregationResult getAggregationResult() { return aggregator_->aggregate(); }

    /// Reset for next round (clears collected signatures, keeps pubkeys)
    void resetForNextRound() { aggregator_->reset(); }

    /// Get current registered pubkey count
    size_t registeredPubkeyCount() const {
        std::lock_guard<std::mutex> lock(pubkeyMutex_);
        return groupPubkeys_.size();
    }

    /// Submit BLS aggregated signature to FISCO-BCOS via JSON-RPC
    static std::string submitAggSigToFisco(const std::string& fiscoRpcHost, int fiscoRpcPort,
        const std::string& aggSigHex, const std::string& bitmapHex,
        const std::string& signedBlockHash);

    /// Register a single group pubkey with FISCO-BCOS via JSON-RPC
    static bool registerPubkeyToFisco(const std::string& fiscoRpcHost, int fiscoRpcPort,
        uint32_t blsGroupId, const std::string& pubkeyHex);

private:
    // ---- HTTP routing ----
    std::string handleRequest(const net::ParsedRequest& req) {
        if (req.method == "POST" && req.path == "/register_pubkey") {
            return handleRegisterPubkey(req.body);
        } else if (req.method == "POST" && req.path == "/submit_signature") {
            return handleSubmitSignature(req.body);
        } else if (req.method == "GET" && req.path == "/latest_block_hash") {
            return handleGetBlockHash();
        } else if (req.method == "GET" && req.path == "/collected_count") {
            std::ostringstream oss;
            oss << "{\"collected_count\":" << aggregator_->collectedCount()
                << ",\"threshold_reached\":" << (aggregator_->isThresholdReached() ? "true" : "false")
                << "}";
            return oss.str();
        } else if (req.method == "GET" && req.path == "/pubkey_count") {
            std::ostringstream oss;
            oss << "{\"pubkey_count\":" << registeredPubkeyCount()
                << ",\"total_groups\":" << totalGroups_ << "}";
            return oss.str();
        }
        return "{\"error\":\"unknown endpoint\"}";
    }

    /// /register_pubkey: group simulator sends its BLS public key after DKG
    std::string handleRegisterPubkey(const std::string& body) {
        auto gid = extractInt(body, "group_id");
        auto pubkey = extractStr(body, "public_key");

        if (gid < 1 || gid > totalGroups_ || pubkey.empty()) {
            std::ostringstream oss;
            oss << "{\"accepted\":false,\"error\":\"invalid group_id or public_key\"}";
            return oss.str();
        }

        // validate BLS pubkey format
        try {
            G2Native pk = BlsWrapper::g2FromHex(pubkey);
        } catch (...) {
            std::ostringstream oss;
            oss << "{\"accepted\":false,\"error\":\"invalid BLS public key format\"}";
            return oss.str();
        }

        {
            std::lock_guard<std::mutex> lock(pubkeyMutex_);
            groupPubkeys_[gid] = pubkey;
        }
        rebuildAggregator();

        // fire-and-forget: register pubkey to ALL FISCO-BCOS nodes in background
        // (avoids blocking the HTTP handler thread)
        std::string pubkeyCopy = pubkey;
        auto nodes = fiscoNodes_;
        std::thread([gid, pubkeyCopy, nodes]() {
            for (const auto& node : nodes) {
                registerPubkeyToFisco(node, gid, pubkeyCopy);
            }
        }).detach();

        std::ostringstream oss;
        oss << "{\"accepted\":true,\"registered\":" << registeredPubkeyCount()
            << ",\"total\":" << totalGroups_ << "}";
        std::cout << "[LeaderServer] group " << gid << " pubkey registered ("
                  << registeredPubkeyCount() << "/" << totalGroups_ << ")" << std::endl;
        return oss.str();
    }

    /// /submit_signature: group simulator sends its threshold signature
    std::string handleSubmitSignature(const std::string& body) {
        GroupThresholdSignature gs;
        gs.group_id = extractInt(body, "group_id");
        gs.signature = extractStr(body, "signature");
        gs.num_signers = extractInt(body, "num_signers");
        gs.block_hash = extractStr(body, "block_hash");

        bool ok = false;
        if (gs.group_id >= 1 && !gs.signature.empty() && !gs.block_hash.empty()) {
            ok = aggregator_->addGroupSignature(gs);
        }

        std::ostringstream oss;
        oss << "{\"accepted\":" << (ok ? "true" : "false")
            << ",\"collected_count\":" << aggregator_->collectedCount()
            << ",\"threshold_reached\":" << (aggregator_->isThresholdReached() ? "true" : "false")
            << "}";
        std::cout << "[LeaderServer] group " << gs.group_id
                  << " signature " << (ok ? "accepted" : "rejected")
                  << " (collected: " << aggregator_->collectedCount() << ")" << std::endl;
        return oss.str();
    }

    std::string handleGetBlockHash() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;
        oss << "{\"block_hash\":\"" << latestBlockHash_ << "\""
            << ",\"block_number\":" << latestBlockNumber_ << "}";
        return oss.str();
    }

    // ---- Poll FISCO-BCOS for latest block hash ----
    void pollFiscoBlocks(int intervalMs) {
        if (fiscoNodes_.empty()) { return; }
        auto& firstNode = fiscoNodes_[0];
        auto colon = firstNode.find(':');
        std::string host = firstNode.substr(0, colon);
        int port = std::stoi(firstNode.substr(colon + 1));

        std::string lastHash;
        int64_t lastBlockNum = 0;
        while (keepPolling_) {
            // Step 1: get latest block number
            std::string bnReq =
                R"({"jsonrpc":"2.0","method":"getBlockNumber","params":["group0"],"id":1})";
            std::string bnResp = net::httpPost(host, port, "/", bnReq);

            if (!bnResp.empty()) {
                // parse block number from response: {"result":123,...}
                auto rpos = bnResp.find("\"result\"");
                if (rpos != std::string::npos) {
                    auto valStart = rpos + 9; // skip "result":
                    auto valEnd = bnResp.find_first_of(",}\n", valStart);
                    std::string numStr = bnResp.substr(valStart, valEnd - valStart);
                    int64_t bn = 0;
                    try { bn = std::stoll(numStr); } catch (...) {}

                    // Step 2: get block hash by number (only if new block)
                    if (bn > 0 && bn > lastBlockNum) {
                        std::ostringstream hashReq;
                        hashReq << R"({"jsonrpc":"2.0","method":"getBlockHashByNumber","params":["group0","",)"
                                << bn << R"(],"id":2})";
                        std::string hashResp = net::httpPost(host, port, "/", hashReq.str());

                        std::lock_guard<std::mutex> lock(mutex_);
                        auto hashPos = hashResp.find("\"result\"");
                        if (hashPos != std::string::npos) {
                            auto start = hashResp.find('"', hashPos + 9);
                            auto end = hashResp.find('"', start + 1);
                            if (start != std::string::npos && end != std::string::npos) {
                                std::string newHash = hashResp.substr(start + 1, end - start - 1);
                                if (!newHash.empty()) {
                                    lastHash = newHash;
                                    lastBlockNum = bn;
                                    latestBlockHash_ = newHash;
                                    latestBlockNumber_ = bn;
                                    std::cout << "[LeaderServer] new block #" << bn
                                              << " hash: " << latestBlockHash_ << std::endl;
                                    aggregator_->reset();
                                }
                            }
                        }
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    }

    // rebuild aggregator with latest pubkeys (called after new pubkeys registered)
    void rebuildAggregator() {
        std::lock_guard<std::mutex> lock(pubkeyMutex_);
        aggregator_ = std::make_unique<BlsAggregator>(
            totalGroups_, minThreshold_, groupPubkeys_);
    }

    // ---- Minimal JSON value extraction (no library dependency) ----
    static std::string extractStr(const std::string& body, const std::string& key) {
        auto p = body.find("\"" + key + "\"");
        if (p == std::string::npos) { return ""; }
        p = body.find('"', p + key.size() + 3);
        if (p == std::string::npos) { return ""; }
        auto e = body.find('"', p + 1);
        if (e == std::string::npos) { return ""; }
        return body.substr(p + 1, e - p - 1);
    }

    static uint32_t extractInt(const std::string& body, const std::string& key) {
        auto p = body.find("\"" + key + "\"");
        if (p == std::string::npos) { return 0; }
        p = body.find(':', p);
        if (p == std::string::npos) { return 0; }
        return static_cast<uint32_t>(std::stoul(body.substr(p + 1)));
    }

    int port_;
    uint32_t totalGroups_;
    uint32_t minThreshold_;

    std::unique_ptr<BlsAggregator> aggregator_;
    std::unique_ptr<net::SimpleHttpServer> server_;

    // pubkeys: mutable, groups register dynamically after DKG
    std::map<GroupId, PubKeyHex> groupPubkeys_;
    mutable std::mutex pubkeyMutex_;

    // FISCO-BCOS RPC node addresses (host:port list)
    std::vector<std::string> fiscoNodes_;

    // block polling
    std::atomic<bool> keepPolling_{false};
    std::thread pollThread_;
    mutable std::mutex mutex_;
    std::string latestBlockHash_;
    int64_t latestBlockNumber_ = 0;
};

// ---- Static RPC helpers ----

inline std::string LeaderHttpServer::submitAggSigToFisco(
    const std::string& fiscoNode,  // "host:port"
    const std::string& aggSigHex, const std::string& bitmapHex,
    const std::string& signedBlockHash) {

    auto colon = fiscoNode.find(':');
    std::string host = fiscoNode.substr(0, colon);
    int port = std::stoi(fiscoNode.substr(colon + 1));

    std::ostringstream body;
    body << R"({"jsonrpc":"2.0","method":"submitBlsAggregatedSignature","params":["group0",")"
         << aggSigHex << R"(",")" << bitmapHex << R"(",")" << signedBlockHash
         << R"("],"id":1})";

    std::string resp = net::httpPost(host, port, "/", body.str());
    std::cout << "[LeaderServer] submitBlsAggregatedSignature to " << fiscoNode
              << " → " << resp << std::endl;
    return resp;
}

inline bool LeaderHttpServer::registerPubkeyToFisco(
    const std::string& fiscoNode,  // "host:port"
    uint32_t blsGroupId, const std::string& pubkeyHex) {

    auto colon = fiscoNode.find(':');
    std::string host = fiscoNode.substr(0, colon);
    int port = std::stoi(fiscoNode.substr(colon + 1));

    std::ostringstream body;
    body << R"({"jsonrpc":"2.0","method":"addGroupPublicKey","params":["group0",)"
         << blsGroupId << R"(,")" << pubkeyHex << R"("],"id":1})";

    std::string resp = net::httpPost(host, port, "/", body.str());
    if (resp.empty()) {
        std::cout << "[LeaderServer] addGroupPublicKey(group=" << blsGroupId
                  << ") to " << fiscoNode << " ✗ (network error)" << std::endl;
        return false;
    }
    bool ok = (resp.find("\"code\":0") != std::string::npos);
    if (!ok) {
        std::cout << "[LeaderServer] addGroupPublicKey(group=" << blsGroupId
                  << ") to " << fiscoNode << " ✗ response: " << resp << std::endl;
    } else {
        std::cout << "[LeaderServer] addGroupPublicKey(group=" << blsGroupId
                  << ") to " << fiscoNode << " ✓" << std::endl;
    }
    return ok;
}

} // namespace bcos::bls

#endif
