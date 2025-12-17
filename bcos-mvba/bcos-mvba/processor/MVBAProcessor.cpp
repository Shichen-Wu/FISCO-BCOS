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
 * @file MVBAProcessor.cpp
 * @author: yujiechen
 * @date 2024-12-15
 */
#include "MVBAProcessor.h"
#include "../cache/MVBACacheFactory.h"
#include <bcos-utilities/Common.h>

using namespace bcos::consensus;
using namespace bcos::protocol;
using namespace bcos::crypto;

MVBAProcessor::MVBAProcessor(PBFTConfig::Ptr _config)
  : m_config(std::move(_config))
{

    m_messageFactory = std::make_shared<MVBAMessageFactoryImpl>();

    // 创建编解码器
    m_codec = std::make_shared<MVBACodec>(
        m_config->keyPair(), 
        m_config->cryptoSuite(),
        m_messageFactory
    );
    
    
    // 创建缓存处理器
    auto cacheFactory = std::make_shared<MVBACacheFactory>();
    m_cacheProcessor = std::make_shared<MVBACacheProcessor>(m_config, cacheFactory);
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor constructed") 
                   << LOG_KV("nodeIndex", m_config->observerNodeIndex())
                   << LOG_KV("nodeId", m_config->nodeID()->hex());
}

MVBAProcessor::~MVBAProcessor()
{
    stop();
}

void MVBAProcessor::init()
{
    if (m_started)
    {
        return;
    }
    
    // 初始化缓存处理器
    m_cacheProcessor->init();
    
    // 注册缓存回调
    m_cacheProcessor->registerLockNotify([this](EpochIndexType _index) {
        onCacheLocked(_index);
    });
    
    m_cacheProcessor->registerFinishNotify([this](EpochIndexType _index) {
        onCacheFinished(_index);
    });
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor initialized");
}

void MVBAProcessor::start()
{
    if (m_started)
    {
        return;
    }
    
    init();
    
    m_running = true;
    m_started = true;
    
    // 启动消息处理线程
    m_messageProcessThread = std::thread([this]() {
        processMessageQueue();
    });
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor started");
}

void MVBAProcessor::stop()
{
    if (!m_started)
    {
        return;
    }
    
    m_running = false;
    
    // 通知消息处理线程退出
    {
        std::lock_guard<std::mutex> lock(m_messageQueueMutex);
        m_messageQueueCondition.notify_all();
    }
    
    // 等待消息处理线程结束
    if (m_messageProcessThread.joinable())
    {
        m_messageProcessThread.join();
    }
    
    // 停止所有定时器
    {
        std::lock_guard<std::mutex> lock(m_timersMutex);
        for (auto& [index, timer] : m_instanceTimers)
        {
            if (timer)
            {
                timer->stop();
            }
        }
        m_instanceTimers.clear();
    }
    
    m_started = false;
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor stopped");
}

void MVBAProcessor::reset()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    // 重置状态
    m_currentIndex = 0;
    
    
    // 清空消息队列
    {
        std::lock_guard<std::mutex> queueLock(m_messageQueueMutex);
        std::queue<MVBAMessageInterface::Ptr> empty;
        m_messageQueue.swap(empty);
    }
    
    // 重置缓存处理器
    if (m_cacheProcessor)
    {
        m_cacheProcessor->reset();
    }
    
    // 停止所有定时器
    {
        std::lock_guard<std::mutex> timerLock(m_timersMutex);
        for (auto& [index, timer] : m_instanceTimers)
        {
            if (timer)
            {
                timer->stop();
            }
        }
        m_instanceTimers.clear();
    }
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor reset");
}

void MVBAProcessor::handleMVBAMessage(MVBAMessageInterface::Ptr _msg)
{
    if (!_msg || !m_running)
    {
        return;
    }
    
    m_totalMessagesReceived.fetch_add(1);
    
    // 基础验证
    if (!validateMessage(_msg))
    {
        m_totalInvalidMessages.fetch_add(1);
        MVBA_LOG(WARNING) << LOG_DESC("handleMVBAMessage: invalid message")
                          << LOG_KV("packetType", (int32_t)_msg->packetType())
                          << LOG_KV("fromNode", _msg->from() ? _msg->from()->hex() : "unknown");
        return;
    }
    
    // 将消息放入队列异步处理
    enqueueMessage(_msg);
}

void MVBAProcessor::enqueueMessage(MVBAMessageInterface::Ptr _msg)
{
    std::lock_guard<std::mutex> lock(m_messageQueueMutex);
    
    // 检查队列大小限制
    if (m_messageQueue.size() >= m_maxPendingMessages)
    {
        MVBA_LOG(WARNING) << LOG_DESC("enqueueMessage: message queue full, dropping message")
                          << LOG_KV("queueSize", m_messageQueue.size())
                          << LOG_KV("maxSize", m_maxPendingMessages);
        return;
    }
    
    m_messageQueue.push(_msg);
    m_messageQueueCondition.notify_one();
}

void MVBAProcessor::processMessageQueue()
{
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor message processing thread started");
    
    while (m_running)
    {
        MVBAMessageInterface::Ptr msg = nullptr;
        
        // 从队列中取消息
        {
            std::unique_lock<std::mutex> lock(m_messageQueueMutex);
            m_messageQueueCondition.wait(lock, [this]() {
                return !m_messageQueue.empty() || !m_running;
            });
            
            if (!m_running)
            {
                break;
            }
            
            if (!m_messageQueue.empty())
            {
                msg = m_messageQueue.front();
                m_messageQueue.pop();
            }
        }
        
        // 处理消息
        if (msg)
        {
            if (m_cacheProcessor->isInvalidMVBAIndex(msg->index())){
                //MVBA_LOG(INFO) << LOG_DESC("Index is outdated");
                continue;
            }
            try
            {
                switch (msg->packetType())
                {
                case MVBAPacketType::ActivePacket:
                    m_cacheProcessor->processActiveMessage(msg);
                    m_totalActiveMessages.fetch_add(1);
                    break;
                case MVBAPacketType::ActiveEchoPacket:
                    m_cacheProcessor->processActiveEchoMessage(msg);
                    break;
                case MVBAPacketType::LockPacket:
                    m_cacheProcessor->processLockMessage(msg);
                    m_totalLockMessages.fetch_add(1);
                    break;
                case MVBAPacketType::LockEchoPacket:
                    m_cacheProcessor->processLockEchoMessage(msg);
                    break;
                case MVBAPacketType::FinishPacket:
                    m_cacheProcessor->processFinishMessage(msg);
                    m_totalFinishMessages.fetch_add(1);
                    break;
                case MVBAPacketType::NotifyFinishedPacket:
                    m_cacheProcessor->updateFinishedState(msg);
                    break;
                case MVBAPacketType::PrevotePacket:
                    // TODO: 实现prevote消息处理
                    // m_cacheProcessor->processPrevoteMessage(msg);
                    break;
                case MVBAPacketType::VotePacket:
                    // TODO: 实现vote消息处理
                    // m_cacheProcessor->processVoteMessage(msg);
                    break;
                default:
                    MVBA_LOG(WARNING) << LOG_DESC("processMessageQueue: unknown packet type")
                                      << LOG_KV("packetType", msg->packetType());
                    break;
                }
            }
            catch (std::exception const& e)
            {
                MVBA_LOG(WARNING) << LOG_DESC("processMessageQueue: exception processing message")
                                  << LOG_KV("packetType", msg->packetType())
                                  << LOG_KV("error", boost::diagnostic_information(e));
            }
        }
    }
    
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor message processing thread stopped");
}

void MVBAProcessor::mockAndStartMVBAInstance()
{
    if (m_config->isConsensusNode())
    {
        MVBA_LOG(INFO) << LOG_DESC("Node is not observer node");
        return ;
    }

    m_currentIndex++;
    
    auto totalNodeNum = m_config->consensusNodesNum(); 
    
    uint64_t vectorSize = (totalNodeNum - 1) / 3 + 1; 
    
    // Mock EquivocationProof
    auto equivocationProof = std::make_shared<EquivocationProof>();
     
    equivocationProof->setVersion(1);
    equivocationProof->setConflictBlockNumber(945);
    equivocationProof->setRollbackBlockNumber(944); 
    equivocationProof->setSequentialEpoch(34);

    uint64_t fixedSeed = 12345678ULL + m_currentIndex; 
    std::mt19937 gen(fixedSeed);
    
    // Mock malicious node indexes 
    std::vector<int64_t> maliciousNodes;
    std::uniform_int_distribution<int64_t> nodeIndexDis(0, static_cast<int64_t>(totalNodeNum - 1));
    std::set<int64_t> uniqueNodes; // 确保节点索引不重复

    while (uniqueNodes.size() < vectorSize) {
        uniqueNodes.insert(nodeIndexDis(gen));
    }
    maliciousNodes.assign(uniqueNodes.begin(), uniqueNodes.end());
    equivocationProof->setMaliciousNodeIndexes(maliciousNodes);

    // Mock main chain signatures 
    std::vector<bytes> mainChainSigs;
    std::uniform_int_distribution<int> byteDis(0, 255);

    for (size_t i = 0; i < vectorSize; ++i) {
        bytes sig(64); // 64字节签名
        for (size_t j = 0; j < 64; ++j) {
            sig[j] = static_cast<byte>(byteDis(gen));
        }
        mainChainSigs.push_back(std::move(sig));
    }
    equivocationProof->setMainChainSignatures(mainChainSigs);

    // Mock conflict signatures 
    std::vector<bytes> conflictSigs;
    for (size_t i = 0; i < vectorSize; ++i) {
        bytes sig(64); // 64字节签名
        for (size_t j = 0; j < 64; ++j) {
            sig[j] = static_cast<byte>(byteDis(gen));
        }
        conflictSigs.push_back(std::move(sig));
    }
    equivocationProof->setConflictSignatures(conflictSigs);
    
    // Mock hash
    // bcos::crypto::HashType inputHash;
    // std::string mockData = "mock_mvba_input_data_" + std::to_string(m_currentIndex);
    // memcpy(inputHash.data(), mockData.c_str(), std::min(mockData.length(), size_t(32)));

    bytesPointer epPayload = {};
    epPayload = equivocationProof->encode();
    auto inputHash = m_config->cryptoSuite()->hashImpl()->hash(*epPayload);

    
    MVBA_LOG(INFO) << LOG_DESC("Mock MVBA Data Generated")
                   << LOG_KV("totalNodeCount", totalNodeNum)
                   << LOG_KV("vectorSize", vectorSize)
                   << LOG_KV("epochIndex", m_currentIndex)
                   << LOG_KV("version", equivocationProof->version())
                   << LOG_KV("conflictBlockNumber", equivocationProof->conflictBlockNumber())
                   << LOG_KV("rollbackBlockNumber", equivocationProof->rollbackBlockNumber())
                   << LOG_KV("sequentialEpoch", equivocationProof->sequentialEpoch())
                   << LOG_KV("maliciousNodeCount", equivocationProof->maliciousNodeIndexes().size())
                   << LOG_KV("mainChainSigCount", equivocationProof->mainChainSignatures().size())
                   << LOG_KV("conflictSigCount", equivocationProof->conflictSignatures().size())
                   << LOG_KV("Hash", inputHash.hex());
    
    startMVBAInstance(m_currentIndex, equivocationProof, inputHash);

}

void MVBAProcessor::startMVBAInstance(EpochIndexType _index, EquivocationProof::Ptr _input, bcos::crypto::HashType _inputHash)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    MVBA_LOG(INFO) << LOG_DESC("startMVBAInstance");
    
    // 更新当前实例状态
    m_currentIndex = _index;
    
    // 启动实例定时器
    startInstanceTimer(_index);

    
    // 开始MVBA协议 - 传递给Cache Processor， 广播Active消息
    auto initialProposal = m_config->mvbaMessageFactory()->createMVBAProposal();
    initialProposal->setIndex(_index);
    initialProposal->setSealerId(m_config->observerNodeIndex()); // 使用自己的sealerId
    initialProposal->setPayloadHash(_inputHash);
    initialProposal->setMvbaInput(_input);

    // 创建Active消息
    auto initialActiveMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::ActivePacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(), 
        utcTime(),
        m_config->observerNodeIndex(),
        initialProposal,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        true,  // active = true
        false  // needProof = false
    );

    m_cacheProcessor->processActiveMessage(initialActiveMsg);

    //tryBroadcastActive(_index, _round);
}

// 消息验证函数
bool MVBAProcessor::validateMessage(MVBAMessageInterface::Ptr _msg)
{
    if (!_msg)
    {
        return false;
    }
    
    // 基础验证
    if (!validateMessageBasic(_msg))
    {
        return false;
    }
    
    // 签名验证
    if (!validateMessageSignature(_msg))
    {
        return false;
    }
    
    // 时间戳验证
    if (!validateMessageTimestamp(_msg))
    {
        return false;
    }
    
    return true;
}

bool MVBAProcessor::validateMessageBasic(MVBAMessageInterface::Ptr _msg)
{
    // TODO: 实现基础消息验证逻辑
    // 检查消息格式、字段完整性等
    return true;
}

bool MVBAProcessor::validateMessageSignature(MVBAMessageInterface::Ptr _msg)
{
    // TODO: 实现消息签名验证
    // 使用cryptoSuite验证消息签名
    return true;
}

bool MVBAProcessor::validateMessageTimestamp(MVBAMessageInterface::Ptr _msg)
{
    // TODO: 实现时间戳验证
    // 检查消息时间戳是否在有效范围内
    return true;
}

void MVBAProcessor::startInstanceTimer(EpochIndexType _index)
{
    std::lock_guard<std::mutex> lock(m_timersMutex);
    
    // 如果定时器已存在，先停止
    auto it = m_instanceTimers.find(_index);
    if (it != m_instanceTimers.end() && it->second)
    {
        it->second->stop();
    }
    
    // 创建新的定时器
    auto timer = std::make_shared<bcos::Timer>(m_instanceTimeout, "MVBAInstanceTimer");
    timer->registerTimeoutHandler([this, _index]() {
        onInstanceTimeout(_index);
    });
    
    m_instanceTimers[_index] = timer;
    timer->start();
    
    MVBA_LOG(DEBUG) << LOG_DESC("startInstanceTimer") 
                    << LOG_KV("index", _index)
                    << LOG_KV("timeout", m_instanceTimeout);
}

void MVBAProcessor::stopInstanceTimer(EpochIndexType _index)
{
    std::lock_guard<std::mutex> lock(m_timersMutex);
    
    auto it = m_instanceTimers.find(_index);
    if (it != m_instanceTimers.end())
    {
        if (it->second)
        {
            it->second->stop();
        }
        m_instanceTimers.erase(it);
        
        MVBA_LOG(DEBUG) << LOG_DESC("stopInstanceTimer") << LOG_KV("index", _index);
    }
}

void MVBAProcessor::onInstanceTimeout(EpochIndexType _index)
{
    MVBA_LOG(WARNING) << LOG_DESC("onInstanceTimeout") << LOG_KV("index", _index);
    
    // TODO: 实现超时处理逻辑
    // 可能需要重新发送消息或者进入下一轮
}

void MVBAProcessor::cleanupExpiredInstances()
{
    // TODO: 实现过期实例清理逻辑
    // 清理超过一定时间的旧实例状态和缓存
}

void MVBAProcessor::tryBroadcastActive(EpochIndexType _index, RoundType _round)
{
    // TODO: 实现Active消息广播
    MVBA_LOG(INFO) << LOG_DESC("tryBroadcastActive") 
                   << LOG_KV("index", _index)
                   << LOG_KV("round", _round);
}

void MVBAProcessor::onCacheLocked(EpochIndexType _index)
{
    MVBA_LOG(INFO) << LOG_DESC("onCacheLocked") << LOG_KV("index", _index);
    
    // 调用注册的回调函数
    if (m_lockNotifyHandler)
    {
        m_lockNotifyHandler(_index);
    }
    
    // TODO: 实现cache locked后的处理逻辑
}

void MVBAProcessor::onCacheFinished(EpochIndexType _index)
{
    MVBA_LOG(INFO) << LOG_DESC("onCacheFinished") << LOG_KV("index", _index);
    
    // 停止对应的定时器
    stopInstanceTimer(_index);
    
    // 调用注册的回调函数
    if (m_finishNotifyHandler)
    {
        m_finishNotifyHandler(_index);
    }
    
    // TODO: 实现cache finished后的处理逻辑
}

size_t MVBAProcessor::getPendingMessageCount() const
{
    std::lock_guard<std::mutex> lock(m_messageQueueMutex);
    return m_messageQueue.size();
}

size_t MVBAProcessor::getActiveMVBACount() const
{
    std::lock_guard<std::mutex> lock(m_timersMutex);
    return m_instanceTimers.size();
}

void MVBAProcessor::printStatistics() const
{
    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor Status")
                   << LOG_KV("running", m_running.load())
                   << LOG_KV("totalMessagesReceived", m_totalMessagesReceived.load())
                   << LOG_KV("activeMessages", m_totalActiveMessages.load())
                   << LOG_KV("lockMessages", m_totalLockMessages.load())
                   << LOG_KV("finishMessages", m_totalFinishMessages.load())
                   << LOG_KV("sentMessages", m_totalMessagesSent.load())
                   << LOG_KV("invalidMessages", m_totalInvalidMessages.load())
                   << LOG_KV("pendingMessages", getPendingMessageCount())
                   << LOG_KV("activeMVBAs", getActiveMVBACount());
    
    if (m_cacheProcessor)
    {
        m_cacheProcessor->printCacheStatus();
    }
}