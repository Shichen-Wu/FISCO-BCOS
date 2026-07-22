#include "leader/signature_collector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <sys/stat.h>

// ============================================================================
// 简易 JSON 解析辅助 (不引入第三方库)
// ============================================================================

namespace {

std::string jsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

uint32_t jsonGetUint32(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return 0;
    pos++;
    while (pos < json.size() && std::isspace(json[pos])) pos++;
    size_t end = pos;
    while (end < json.size() && std::isdigit(json[end])) end++;
    if (end > pos) {
        return static_cast<uint32_t>(std::stoul(json.substr(pos, end - pos)));
    }
    return 0;
}

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

} // anonymous namespace

// ============================================================================
// 组公钥加载/保存
// ============================================================================

std::map<GroupId, PubKeyHex> SignatureCollector::loadPublicKeys(
        const std::string& filepath) {
    std::map<GroupId, PubKeyHex> result;
    std::ifstream f(filepath);
    if (!f) {
        std::cerr << "[Collector] 无法打开公钥文件: " << filepath << std::endl;
        return result;
    }

    std::string line;
    // 格式: {"groups": [{"group_id": 1, "pubkey": "0x..."}, ...]}
    // 简易逐行解析
    std::ostringstream oss;
    oss << f.rdbuf();
    std::string json = oss.str();

    // 查找 "groups" 数组
    size_t arr_start = json.find("\"groups\"");
    if (arr_start == std::string::npos) {
        std::cerr << "[Collector] 公钥文件格式错误: 无 'groups' 字段" << std::endl;
        return result;
    }
    arr_start = json.find('[', arr_start);
    size_t arr_end = json.find(']', arr_start);
    if (arr_start == std::string::npos || arr_end == std::string::npos) {
        return result;
    }

    // 解析每个元素
    std::string arr_content = json.substr(arr_start + 1, arr_end - arr_start - 1);
    size_t obj_start = 0;
    while (true) {
        obj_start = arr_content.find('{', obj_start);
        if (obj_start == std::string::npos) break;
        size_t obj_end = arr_content.find('}', obj_start);
        if (obj_end == std::string::npos) break;
        std::string obj = arr_content.substr(obj_start, obj_end - obj_start + 1);

        GroupId gid = jsonGetUint32(obj, "group_id");
        PubKeyHex pk = jsonGetString(obj, "pubkey");
        if (gid >= 1 && !pk.empty()) {
            result[gid] = pk;
        }
        obj_start = obj_end + 1;
    }

    std::cout << "[Collector] 已加载 " << result.size() << " 个组公钥" << std::endl;
    return result;
}

void SignatureCollector::savePublicKeys(
        const std::string& filepath,
        const std::map<GroupId, PubKeyHex>& pubkeys) {
    std::ofstream f(filepath);
    if (!f) {
        std::cerr << "[Collector] 无法写入公钥文件: " << filepath << std::endl;
        return;
    }
    f << "{\n  \"groups\": [\n";
    size_t count = 0;
    for (const auto& kv : pubkeys) {
        f << "    {\"group_id\": " << kv.first
          << ", \"pubkey\": \"" << kv.second << "\"}";
        if (++count < pubkeys.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    std::cout << "[Collector] 已保存 " << pubkeys.size()
              << " 个组公钥到 " << filepath << std::endl;
}

// ============================================================================
// 组签名加载 (从文件)
// ============================================================================

std::map<GroupId, GroupThresholdSignature>
SignatureCollector::loadFromDirectory(const std::string& dir_path) {
    std::map<GroupId, GroupThresholdSignature> result;

    for (GroupId gid = 1; gid <= 256; ++gid) {
        char fname[256];
        snprintf(fname, sizeof(fname), "%s/group_%u.json",
                 dir_path.c_str(), gid);
        struct stat st;
        if (stat(fname, &st) != 0) continue;

        GroupThresholdSignature gs = parseSignatureFile(fname);
        if (gs.group_id == gid) {
            result[gid] = gs;
        }
    }

    std::cout << "[Collector] 从 " << dir_path << " 加载了 "
              << result.size() << " 个组签名" << std::endl;
    return result;
}

GroupThresholdSignature SignatureCollector::parseSignatureFile(
        const std::string& filepath) {
    GroupThresholdSignature result = {};
    std::string json = readFile(filepath);
    if (json.empty()) return result;

    result.group_id    = jsonGetUint32(json, "group_id");
    result.signature   = jsonGetString(json, "threshold_signature");
    result.num_signers = jsonGetUint32(json, "num_signers");
    result.block_hash  = jsonGetString(json, "block_hash");

    return result;
}

// ============================================================================
// 测试数据生成 (根据已有公钥生成对应私钥并签名)
// ============================================================================

std::map<GroupId, GroupThresholdSignature>
SignatureCollector::generateTestData(
        const std::map<GroupId, FrHex>& group_seckeys,
        const std::string& block_hash) {

    std::map<GroupId, GroupThresholdSignature> result;
    if (group_seckeys.empty()) {
        std::cerr << "[Collector] 无私钥, 无法生成测试签名" << std::endl;
        return result;
    }

    std::cout << "[Collector] 正在生成 " << group_seckeys.size()
              << " 个组的测试签名 (使用匹配的私钥)..." << std::endl;

    for (const auto& kv : group_seckeys) {
        GroupId gid = kv.first;
        FrNative sk = BlsWrapper::frFromHex(kv.second);
        G1Native sig = BlsWrapper::sign(sk, block_hash);

        GroupThresholdSignature gs;
        gs.group_id    = gid;
        gs.signature   = BlsWrapper::g1ToHex(sig);
        gs.num_signers = 3400;
        gs.block_hash  = block_hash;
        result[gid] = gs;
    }

    std::cout << "[Collector] 测试签名生成完成: " << result.size() << " 个组"
              << std::endl;
    return result;
}
