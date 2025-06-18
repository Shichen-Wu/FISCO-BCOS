/**
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @brief processor for MVBA cache management
 * @file MVBACacheProcessor.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "MVBACache.h"
#include "MVBACacheFactory.h"
#include "../bcos-pbft/bcos-pbft/pbft/config/PBFTConfig.h"
#include "../interfaces/MVBAMessageInterface.h"
#include "../utilities/Common.h"
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <vector>
#include <functional>

namespace bcos::consensus
{
class MVBACacheProcessor : public std::enable_shared_from_this<MVBACacheProcessor>
{
public:
    using Ptr = std::shared_ptr<MVBACacheProcessor>;
    using CacheMap = std::map<bcos::protocol::EpochIndexType, MVBACache::Ptr>;
    using LockNotifierType = std::function<void(bcos::protocol::EpochIndexType)>;
    using FinishNotifierType = std::function<void(bcos::protocol::EpochIndexType)>;
    
    MVBACacheProcessor(PBFTConfig::Ptr _config, MVBACacheFactory::Ptr _factory = nullptr);
    virtual ~MVBACacheProcessor() = default;

    // 初始化
    virtual void init();
    
    // 重置所有缓存
    virtual void reset();

    // 处理Active消息
    virtual bool processActiveMessage(MVBAMessageInterface::Ptr _activeMsg);
    
    // 处理ActiveEcho消息
    virtual bool processActiveEchoMessage(MVBAMessageInterface::Ptr _activeEchoMsg);
    
    // 处理Lock消息
    virtual bool processLockMessage(MVBAMessageInterface::Ptr _lockMsg);
    
    // 处理LockEcho消息  
    virtual bool processLockEchoMessage(MVBAMessageInterface::Ptr _lockEchoMsg);
    
    // 处理Finish消息
    virtual bool processFinishMessage(MVBAMessageInterface::Ptr _finishMsg);

    // 获取或创建指定index的Cache
    virtual MVBACache::Ptr getOrCreateCache(bcos::protocol::EpochIndexType _index);
    
    // 获取指定index的Cache（只读）
    virtual MVBACache::Ptr getCache(bcos::protocol::EpochIndexType _index) const;
    
    // 移除指定index的Cache
    virtual void removeCache(bcos::protocol::EpochIndexType _index);
    
    // 清理过期的Cache（低于指定index的缓存）
    virtual void clearExpiredCache(bcos::protocol::EpochIndexType _minIndex);

    // 检查所有缓存状态并尝试推进
    virtual void checkAndAdvanceAll();
    
    // 检查指定Cache状态并尝试推进
    virtual void checkAndAdvance(bcos::protocol::EpochIndexType _index);

    // 注册回调函数
    virtual void registerLockNotify(LockNotifierType _notifier);
    virtual void registerFinishNotify(FinishNotifierType _notifier);

    // 获取缓存统计信息
    virtual size_t getCacheCount() const;
    virtual std::vector<bcos::protocol::EpochIndexType> getCacheIndexes() const;

    // 检查消息有效性
    virtual bool isValidMessage(MVBAMessageInterface::Ptr _msg) const;

protected:
    // 创建新的Cache实例
    virtual MVBACache::Ptr createCache(bcos::protocol::EpochIndexType _index);
    
    // 内部处理函数
    virtual bool processMessageInternal(MVBAMessageInterface::Ptr _msg, 
        std::function<void(MVBACache::Ptr)> _processor);

    // 锁回调处理
    virtual void onCacheLocked(bcos::protocol::EpochIndexType _index);
    
    // 完成回调处理
    virtual void onCacheFinished(bcos::protocol::EpochIndexType _index);

    // 日志相关
    virtual void printCacheStatus() const;

protected:
    PBFTConfig::Ptr m_config;
    MVBACacheFactory::Ptr m_factory;
    CacheMap m_caches;

    mutable std::shared_mutex m_cachesMutex;  
    
    // 回调函数
    LockNotifierType m_lockNotifier;
    FinishNotifierType m_finishNotifier;
    
    // 统计信息
    std::atomic<uint64_t> m_processedActiveCount{0};
    std::atomic<uint64_t> m_processedActiveEchoCount{0};
    std::atomic<uint64_t> m_processedLockCount{0};
    std::atomic<uint64_t> m_processedLockEchoCount{0};
    std::atomic<uint64_t> m_processedFinishCount{0};
};
}  // namespace bcos::consensus