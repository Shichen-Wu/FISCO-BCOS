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
 * @brief implementation for MVBAProcessor
 * @file MVBAProcessor.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../cache/MVBACacheProcessor.h"
#include "../interfaces/MVBACodecInterface.h"
#include "../interfaces/MVBAMessageFactory.h"
#include "../interfaces/MVBAMessageInterface.h"
#include "../protocol/MVBACodec.h"
#include "../protocol/MVBAMessageFactoryImpl.h"
#include "../bcos-pbft/bcos-pbft/pbft/config/PBFTConfig.h"
#include "../utilities/Common.h"
#include <bcos-framework/protocol/Protocol.h>
#include <bcos-crypto/interfaces/crypto/CommonType.h>
#include <bcos-utilities/Timer.h>
#include <memory>
#include <atomic>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

namespace bcos::consensus
{
class MVBAProcessor : public std::enable_shared_from_this<MVBAProcessor>
{
public:
    using Ptr = std::shared_ptr<MVBAProcessor>;
    using MessageHandler = std::function<void(MVBAMessageInterface::Ptr)>;
    using LockNotifyHandler = std::function<void(EpochIndexType)>;
    using FinishNotifyHandler = std::function<void(EpochIndexType)>;
    using RoundType = uint64_t;
    
    MVBAProcessor(PBFTConfig::Ptr _config);
    virtual ~MVBAProcessor();

    // 基础生命周期管理
    virtual void init();
    virtual void start();
    virtual void stop();
    virtual void reset();

    // 获取编解码器和消息工厂
    virtual MVBACodecInterface::Ptr codec() const { return m_codec; }
    virtual MVBAMessageFactory::Ptr messageFactory() const { return m_messageFactory; }
    virtual MVBACacheProcessor::Ptr cacheProcessor() const { return m_cacheProcessor; }

    //MVBA消息判断
    //virtual bool isMVBAMessage(bytesConstRef _data);

    // 主要消息处理入口
    virtual void handleMVBAMessage(MVBAMessageInterface::Ptr _msg);

    // MVBA协议状态管理
    virtual void startMVBAInstance(EpochIndexType _index, EquivocationProof::Ptr _input, bcos::crypto::HashType _inputHash);

    virtual void mockAndStartMVBAInstance();
    
    // 获取当前MVBA状态
    virtual bool isRunning() const { return m_running; }
    virtual EpochIndexType currentIndex() const { return m_currentIndex; }

    // 注册回调函数
    virtual void registerLockNotifyHandler(LockNotifyHandler _handler) { m_lockNotifyHandler = _handler; }
    virtual void registerFinishNotifyHandler(FinishNotifyHandler _handler) { m_finishNotifyHandler = _handler; }

    // 统计和监控接口
    virtual void printStatistics() const;
    virtual size_t getPendingMessageCount() const;
    virtual size_t getActiveMVBACount() const;

protected:
    // 消息验证 - 修正方法签名一致性
    virtual bool validateMessage(MVBAMessageInterface::Ptr _msg);
    virtual bool validateMessageBasic(MVBAMessageInterface::Ptr _msg);
    virtual bool validateMessageSignature(MVBAMessageInterface::Ptr _msg);
    virtual bool validateMessageTimestamp(MVBAMessageInterface::Ptr _msg);

    // 消息处理辅助函数
    virtual void processMessageQueue();
    virtual void enqueueMessage(MVBAMessageInterface::Ptr _msg);

    // 回调处理
    virtual void onCacheLocked(EpochIndexType _index);
    virtual void onCacheFinished(EpochIndexType _index);

    // 超时处理
    virtual void startInstanceTimer(EpochIndexType _index);
    virtual void stopInstanceTimer(EpochIndexType _index);
    virtual void onInstanceTimeout(EpochIndexType _index);

    // 清理和垃圾回收
    virtual void cleanupExpiredInstances();
    
    // MVBA协议相关
    virtual void tryBroadcastActive(EpochIndexType _index, RoundType _round);

protected:
    // 基础配置和依赖
    std::shared_ptr<PBFTConfig> m_config;
    MVBACodecInterface::Ptr m_codec;
    MVBAMessageFactory::Ptr m_messageFactory;
    MVBACacheProcessor::Ptr m_cacheProcessor;

    // 运行状态
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_started{false};
    
    // 当前MVBA实例状态
    std::atomic<EpochIndexType> m_currentIndex{0};

    // 消息队列和处理线程
    std::queue<MVBAMessageInterface::Ptr> m_messageQueue;
    mutable std::mutex m_messageQueueMutex;
    std::condition_variable m_messageQueueCondition;
    std::thread m_messageProcessThread;

    // 回调函数
    LockNotifyHandler m_lockNotifyHandler;
    FinishNotifyHandler m_finishNotifyHandler;

    // 定时器管理
    std::map<EpochIndexType, std::shared_ptr<bcos::Timer>> m_instanceTimers;
    mutable std::mutex m_timersMutex;
    
    // 配置参数
    uint64_t m_instanceTimeout{300000};  // 30秒实例超时
    uint64_t m_messageTimeout{10000};   // 10秒消息超时
    size_t m_maxPendingMessages{10000}; // 最大pending消息数
    size_t m_maxCacheInstances{100};    // 最大缓存实例数

    // 统计信息
    std::atomic<uint64_t> m_totalMessagesReceived{0};
    std::atomic<uint64_t> m_totalMessagesSent{0};
    std::atomic<uint64_t> m_totalActiveMessages{0};
    std::atomic<uint64_t> m_totalLockMessages{0};
    std::atomic<uint64_t> m_totalFinishMessages{0};
    std::atomic<uint64_t> m_totalInvalidMessages{0};

    // 互斥锁
    mutable std::shared_mutex m_mutex;
};
}  // namespace bcos::consensus