#ifndef LEADER_NODE_AGGREGATION_BLS_AGGREGATOR_H_
#define LEADER_NODE_AGGREGATION_BLS_AGGREGATOR_H_

#include "common/types.h"
#include "crypto/bls_wrapper.h"
#include <vector>
#include <map>

/// 跨组 BLS 签名聚合器
class BlsAggregator {
public:
    BlsAggregator(uint32_t total_groups, uint32_t min_threshold,
                  const std::map<GroupId, PubKeyHex>& group_pubkeys);

    /// 添加一组门限签名
    bool addGroupSignature(const GroupThresholdSignature& gs);

    /// 获取已收集的组数
    uint32_t collectedCount() const { return collected_count_; }

    /// 是否达到最低组数阈值
    bool isThresholdReached() const {
        return collected_count_ >= min_threshold_;
    }

    /// 获取缺失的组ID列表
    std::vector<GroupId> missingGroups() const;

    /// 执行 BLS 聚合，返回最终结果
    AggregationResult aggregate();

    /// 重置状态 (新一轮区块)
    void reset();

private:
    uint32_t total_groups_;
    uint32_t min_threshold_;
    std::map<GroupId, PubKeyHex> group_pubkeys_;

    // 已收集的签名 (group_id → 签名 hex)
    std::map<GroupId, SigHex> collected_sigs_;
    uint32_t collected_count_ = 0;
    std::string block_hash_;
};

#endif
