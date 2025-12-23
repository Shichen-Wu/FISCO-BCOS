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
#include <chrono>
#include <thread>
#include <future>

using namespace bcos::consensus;
using namespace bcos::protocol;
using namespace bcos::crypto;

MVBAProcessor::MVBAProcessor(PBFTConfig::Ptr _config)
  : m_config(std::move(_config)) {
  
  if (!m_config) {
    throw std::invalid_argument("MVBAProcessor: config cannot be null");
  }

  // 检查必要的配置项
  if (!m_config->keyPair()) {
    throw std::runtime_error("MVBAProcessor: keyPair is not initialized");
  }
  if (!m_config->cryptoSuite()) {
    throw std::runtime_error("MVBAProcessor: cryptoSuite is not initialized");
  }

  try {
    m_messageFactory = std::make_shared<MVBAMessageFactoryImpl>();

    // 创建编解码器
    m_codec = std::make_shared<MVBACodec>(
        m_config->keyPair(), m_config->cryptoSuite(), m_messageFactory);

    // 创建缓存处理器
    auto cacheFactory = std::make_shared<MVBACacheFactory>();
    m_cacheProcessor =
        std::make_shared<MVBACacheProcessor>(m_config, cacheFactory);

    // 安全地获取节点信息，避免访问未初始化的配置
    try {
      auto nodeId = m_config->nodeID();
      auto observerIndex = m_config->observerNodeIndex();
      MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor constructed")
                     << LOG_KV("nodeIndex", observerIndex)
                     << LOG_KV("nodeId", nodeId ? nodeId->hex() : "null");
    }
    catch (std::exception const& e) {
      MVBA_LOG(WARNING) << LOG_DESC("MVBAProcessor constructed with warning")
                        << LOG_KV("error", boost::diagnostic_information(e));
    }
  }
  catch (std::exception const& e) {
    MVBA_LOG(ERROR) << LOG_DESC("MVBAProcessor construction failed")
                    << LOG_KV("error", boost::diagnostic_information(e));
    throw;  // 重新抛出异常，让调用者知道构造失败
  }
}

MVBAProcessor::~MVBAProcessor() { stop(); }

void MVBAProcessor::init() {
  if (m_started) {
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

void MVBAProcessor::start() {
  // 使用锁保护启动过程，避免并发启动
  std::lock_guard<std::mutex> startLock(m_startMutex);
  
  if (m_started) {
    MVBA_LOG(DEBUG) << LOG_DESC("MVBAProcessor already started");
    return;
  }

  try {
    init();

    // 先创建线程，再设置状态，避免竞态条件
    // 启动消息处理线程，添加异常处理
    std::thread newThread;
    try {
      newThread = std::thread([this]() {
        try {
          processMessageQueue();
        }
        catch (std::exception const& e) {
          MVBA_LOG(ERROR) << LOG_DESC("MVBAProcessor message thread exception")
                          << LOG_KV("error", boost::diagnostic_information(e));
        }
        catch (...) {
          MVBA_LOG(ERROR) << LOG_DESC("MVBAProcessor message thread unknown exception");
        }
      });
    }
    catch (std::exception const& e) {
      MVBA_LOG(ERROR) << LOG_DESC("Failed to create MVBAProcessor message thread")
                      << LOG_KV("error", boost::diagnostic_information(e));
      throw;  // 重新抛出异常，让调用者知道启动失败
    }
    catch (...) {
      MVBA_LOG(ERROR) << LOG_DESC("Failed to create MVBAProcessor message thread with unknown exception");
      throw;
    }

    // 线程创建成功后再设置状态，确保线程能看到正确的状态
    m_running = true;
    m_messageProcessThread = std::move(newThread);
    m_started = true;
    m_startTime = std::chrono::steady_clock::now();
    // 延迟标记启动完成，给系统一些时间稳定
    // 启动后3秒才标记为完成，期间拒绝处理大部分消息
    std::thread([this]() {
      std::this_thread::sleep_for(std::chrono::seconds(3));
      m_startupComplete = true;
      MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor startup phase completed");
    }).detach();

    MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor started successfully")
                   << LOG_KV("maxPendingMessages", m_maxPendingMessages);
  }
  catch (std::exception const& e) {
    MVBA_LOG(ERROR) << LOG_DESC("MVBAProcessor start failed")
                    << LOG_KV("error", boost::diagnostic_information(e));
    m_running = false;
    m_started = false;
    throw;  // 重新抛出异常
  }
  catch (...) {
    MVBA_LOG(ERROR) << LOG_DESC("MVBAProcessor start failed with unknown exception");
    m_running = false;
    m_started = false;
    throw;
  }
}

void MVBAProcessor::stop() {
  // 使用锁保护停止过程，避免并发停止
  std::lock_guard<std::mutex> stopLock(m_startMutex);
  
  if (!m_started) {
    return;
  }

  m_running = false;

  // 通知消息处理线程退出
  {
    std::lock_guard<std::mutex> lock(m_messageQueueMutex);
    m_messageQueueCondition.notify_all();
  }

  // 等待消息处理线程结束，添加超时机制防止无限等待
  if (m_messageProcessThread.joinable()) {
    // 简化实现：直接尝试join，如果线程卡住，至少不会阻塞整个stop过程太久
    // 在实际应用中，如果线程真的卡住，可以考虑使用detach
    try {
      // 使用超时机制：在另一个线程中等待join，主线程等待最多5秒
      std::atomic<bool> joinCompleted{false};
      std::thread joinThread([this, &joinCompleted]() {
        if (m_messageProcessThread.joinable()) {
          m_messageProcessThread.join();
        }
        joinCompleted = true;
      });
      
      // 等待最多5秒
      auto startTime = std::chrono::steady_clock::now();
      while (!joinCompleted && 
             (std::chrono::steady_clock::now() - startTime) < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      
      if (!joinCompleted) {
        MVBA_LOG(WARNING) << LOG_DESC("MVBAProcessor stop: message thread join timeout, detaching");
        joinThread.detach();
        if (m_messageProcessThread.joinable()) {
          m_messageProcessThread.detach();
        }
      } else {
        if (joinThread.joinable()) {
          joinThread.join();
        }
      }
    }
    catch (std::exception const& e) {
      MVBA_LOG(WARNING) << LOG_DESC("MVBAProcessor stop: exception during thread join")
                        << LOG_KV("error", boost::diagnostic_information(e));
      if (m_messageProcessThread.joinable()) {
        m_messageProcessThread.detach();
      }
    }
  }

  // 停止所有定时器
  {
    std::lock_guard<std::mutex> lock(m_timersMutex);
    for (auto & [ index, timer ] : m_instanceTimers) {
      if (timer) {
        timer->stop();
      }
    }
    m_instanceTimers.clear();
  }

  m_started = false;

  MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor stopped");
}

void MVBAProcessor::reset() {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  // 重置状态
  // m_currentIndex = 0;

  // 清空消息队列
  {
    std::lock_guard<std::mutex> queueLock(m_messageQueueMutex);
    std::queue<MVBAMessageInterface::Ptr> empty;
    m_messageQueue.swap(empty);
  }

  // 重置缓存处理器
  if (m_cacheProcessor) {
    m_cacheProcessor->reset();
  }

  // 停止所有定时器
  {
    std::lock_guard<std::mutex> timerLock(m_timersMutex);
    for (auto & [ index, timer ] : m_instanceTimers) {
      if (timer) {
        timer->stop();
      }
    }
    m_instanceTimers.clear();
  }

  MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor reset");
}

void MVBAProcessor::handleMVBAMessage(MVBAMessageInterface::Ptr _msg) {
  if (!_msg || !m_running) {
    return;
  }

  m_totalMessagesReceived.fetch_add(1);

  // 启动阶段保护：启动后3秒内，只处理关键消息，丢弃其他消息
  if (!m_startupComplete) {
    auto elapsed = std::chrono::steady_clock::now() - m_startTime;
    if (elapsed < std::chrono::seconds(3)) {
      // 启动阶段只处理NotifyFinishedPacket（可能来自其他节点的完成通知）
      // 其他消息在启动阶段丢弃，避免消息风暴
      if (_msg->packetType() != MVBAPacketType::NotifyFinishedPacket) {
        MVBA_LOG(DEBUG) << LOG_DESC("handleMVBAMessage: dropping message during startup")
                        << LOG_KV("packetType", (int32_t)_msg->packetType())
                        << LOG_KV("elapsedSeconds", 
                                  std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
        return;
      }
    } else {
      // 超过3秒但标志未设置，手动设置
      m_startupComplete = true;
    }
  }

  // 基础验证
  if (!validateMessage(_msg)) {
    m_totalInvalidMessages.fetch_add(1);
    MVBA_LOG(WARNING) << LOG_DESC("handleMVBAMessage: invalid message")
                      << LOG_KV("packetType", (int32_t)_msg->packetType())
                      << LOG_KV("fromNode",
                                _msg->from() ? _msg->from()->hex() : "unknown");
    return;
  }

  // 将消息放入队列异步处理
  enqueueMessage(_msg);
}

void MVBAProcessor::enqueueMessage(MVBAMessageInterface::Ptr _msg) {
  std::lock_guard<std::mutex> lock(m_messageQueueMutex);

  // 检查队列大小限制
  auto queueSize = m_messageQueue.size();
  if (queueSize >= m_maxPendingMessages) {
    // 队列满时，根据消息类型决定是否丢弃
    // 关键消息（NotifyFinishedPacket）优先保留
    if (_msg->packetType() == MVBAPacketType::NotifyFinishedPacket) {
      // 对于关键消息，尝试丢弃队列中最旧的非关键消息
      std::queue<MVBAMessageInterface::Ptr> tempQueue;
      bool foundNonCritical = false;
      while (!m_messageQueue.empty()) {
        auto msg = m_messageQueue.front();
        m_messageQueue.pop();
        if (!foundNonCritical && 
            msg->packetType() != MVBAPacketType::NotifyFinishedPacket) {
          foundNonCritical = true;
          continue;  // 丢弃这个非关键消息
        }
        tempQueue.push(msg);
      }
      m_messageQueue = std::move(tempQueue);
      MVBA_LOG(WARNING)
          << LOG_DESC("enqueueMessage: queue full, dropped non-critical message to make room")
          << LOG_KV("queueSize", m_messageQueue.size())
          << LOG_KV("maxSize", m_maxPendingMessages);
    } else {
      MVBA_LOG(WARNING)
          << LOG_DESC("enqueueMessage: message queue full, dropping message")
          << LOG_KV("queueSize", queueSize)
          << LOG_KV("maxSize", m_maxPendingMessages)
          << LOG_KV("packetType", (int32_t)_msg->packetType());
      return;
    }
  }

  m_messageQueue.push(_msg);
  m_messageQueueCondition.notify_one();
}

void MVBAProcessor::processMessageQueue() {
  MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor message processing thread started");

  while (m_running) {
    MVBAMessageInterface::Ptr msg = nullptr;

    // 从队列中取消息，使用超时等待避免无限阻塞
    {
      std::unique_lock<std::mutex> lock(m_messageQueueMutex);
      // 使用超时等待，每100ms检查一次，避免无限等待
      bool notified = m_messageQueueCondition.wait_for(
          lock, std::chrono::milliseconds(100),
          [this]() { return !m_messageQueue.empty() || !m_running; });

      if (!m_running) {
        break;
      }

      if (!m_messageQueue.empty()) {
        msg = m_messageQueue.front();
        m_messageQueue.pop();
      }
      
      // 如果队列仍然很大，记录警告
      if (m_messageQueue.size() > m_maxPendingMessages * 0.8) {
        MVBA_LOG(WARNING) << LOG_DESC("processMessageQueue: message queue approaching limit")
                          << LOG_KV("queueSize", m_messageQueue.size())
                          << LOG_KV("maxSize", m_maxPendingMessages)
                          << LOG_KV("threshold", m_maxPendingMessages * 0.8);
      }
    }

    // 处理消息
    if (msg) {
      if (m_cacheProcessor->isInvalidMVBAIndex(msg->index())) {
        MVBA_LOG(INFO) << LOG_DESC("Index is outdated")
                       << LOG_KV("index", msg->index())
                       << LOG_KV("currentIndex",
                                 m_cacheProcessor->currentIndex());
        continue;
      }

      try {
        switch (msg->packetType()) {
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
          MVBA_LOG(WARNING) << LOG_DESC(
                                   "processMessageQueue: unknown packet type")
                            << LOG_KV("packetType", msg->packetType());
          break;
        }
      }
      catch (std::exception const &e) {
        MVBA_LOG(WARNING)
            << LOG_DESC("processMessageQueue: exception processing message")
            << LOG_KV("packetType", msg->packetType())
            << LOG_KV("error", boost::diagnostic_information(e));
      }
    }
  }

  MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor message processing thread stopped");
}

void MVBAProcessor::mockAndStartMVBAInstance(EpochIndexType index) {
  m_mvbaInstanceNum++;
  MVBA_LOG(INFO) << LOG_DESC("MVBAInstanceNumber")
                 << LOG_KV("mvbaInstanceNum", m_mvbaInstanceNum);

  if (m_config->isConsensusNode()) {
    MVBA_LOG(INFO) << LOG_DESC("Node is not observer node");
    return;
  }

  auto currentIndex = index;

  auto totalNodeNum = m_config->consensusNodesNum();

  uint64_t vectorSize = (totalNodeNum - 1) / 3 + 1;

  // Mock EquivocationProof
  auto equivocationProof = std::make_shared<EquivocationProof>();

  equivocationProof->setVersion(1);
  equivocationProof->setConflictBlockNumber(945);
  equivocationProof->setRollbackBlockNumber(944);
  equivocationProof->setSequentialEpoch(34);

  uint64_t fixedSeed = 12345678ULL + currentIndex;
  std::mt19937 gen(fixedSeed);

  // Mock malicious node indexes
  std::vector<int64_t> maliciousNodes;
  std::uniform_int_distribution<int64_t> nodeIndexDis(
      0, static_cast<int64_t>(totalNodeNum - 1));
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
  // std::string mockData = "mock_mvba_input_data_" +
  // std::to_string(currentIndex);
  // memcpy(inputHash.data(), mockData.c_str(), std::min(mockData.length(),
  // size_t(32)));

  bytesPointer epPayload = {};
  epPayload = equivocationProof->encode();
  auto inputHash = m_config->cryptoSuite()->hashImpl()->hash(*epPayload);

  MVBA_LOG(INFO)
      << LOG_DESC("Mock MVBA Data Generated")
      << LOG_KV("totalNodeCount", totalNodeNum)
      << LOG_KV("vectorSize", vectorSize) << LOG_KV("epochIndex", currentIndex)
      << LOG_KV("version", equivocationProof->version())
      << LOG_KV("conflictBlockNumber", equivocationProof->conflictBlockNumber())
      << LOG_KV("rollbackBlockNumber", equivocationProof->rollbackBlockNumber())
      << LOG_KV("sequentialEpoch", equivocationProof->sequentialEpoch())
      << LOG_KV("maliciousNodeCount",
                equivocationProof->maliciousNodeIndexes().size())
      << LOG_KV("mainChainSigCount",
                equivocationProof->mainChainSignatures().size())
      << LOG_KV("conflictSigCount",
                equivocationProof->conflictSignatures().size())
      << LOG_KV("Hash", inputHash.hex());

  startMVBAInstance(currentIndex, equivocationProof, inputHash);
}

void MVBAProcessor::startMVBAInstance(EpochIndexType _index,
                                      EquivocationProof::Ptr _input,
                                      bcos::crypto::HashType _inputHash) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  MVBA_LOG(INFO) << LOG_DESC("startMVBAInstance");

  // 启动实例定时器（测试阶段关闭 Timer，避免额外线程资源消耗）
  // startInstanceTimer(_index);

  // 开始MVBA协议 - 传递给Cache Processor， 广播Active消息
  auto initialProposal = m_config->mvbaMessageFactory()->createMVBAProposal();
  initialProposal->setIndex(_index);
  initialProposal->setSealerId(
      m_config->observerNodeIndex()); // 使用自己的sealerId
  initialProposal->setPayloadHash(_inputHash);
  initialProposal->setMvbaInput(_input);

  // 创建Active消息
  auto initialActiveMsg = m_config->mvbaMessageFactory()->populateFrom(
      MVBAPacketType::ActivePacket, m_config->mvbaMsgDefaultVersion(),
      m_config->view(), utcTime(), m_config->observerNodeIndex(),
      initialProposal, m_config->cryptoSuite(), m_config->keyPair(),
      true, // active = true
      false // needProof = false
      );

  m_cacheProcessor->processActiveMessage(initialActiveMsg);

  // tryBroadcastActive(_index, _round);
}

// 消息验证函数
bool MVBAProcessor::validateMessage(MVBAMessageInterface::Ptr _msg) {
  if (!_msg) {
    return false;
  }

  // 基础验证
  if (!validateMessageBasic(_msg)) {
    return false;
  }

  // 签名验证
  if (!validateMessageSignature(_msg)) {
    return false;
  }

  // 时间戳验证
  if (!validateMessageTimestamp(_msg)) {
    return false;
  }

  return true;
}

bool MVBAProcessor::validateMessageBasic(MVBAMessageInterface::Ptr _msg) {
  // TODO: 实现基础消息验证逻辑
  // 检查消息格式、字段完整性等
  return true;
}

bool MVBAProcessor::validateMessageSignature(MVBAMessageInterface::Ptr _msg) {
  // TODO: 实现消息签名验证
  // 使用cryptoSuite验证消息签名
  return true;
}

bool MVBAProcessor::validateMessageTimestamp(MVBAMessageInterface::Ptr _msg) {
  // TODO: 实现时间戳验证
  // 检查消息时间戳是否在有效范围内
  return true;
}

void MVBAProcessor::startInstanceTimer(EpochIndexType _index) {
  // 测试阶段禁用实例定时器，直接返回
  MVBA_LOG(DEBUG) << LOG_DESC("startInstanceTimer skipped in test mode")
                  << LOG_KV("index", _index);
}

void MVBAProcessor::stopInstanceTimer(EpochIndexType _index) {
  // 测试阶段禁用实例定时器，直接返回
  MVBA_LOG(DEBUG) << LOG_DESC("stopInstanceTimer skipped in test mode")
                  << LOG_KV("index", _index);
}

void MVBAProcessor::onInstanceTimeout(EpochIndexType _index) {
  MVBA_LOG(WARNING) << LOG_DESC("onInstanceTimeout") << LOG_KV("index", _index);

  // TODO: 实现超时处理逻辑
  // 可能需要重新发送消息或者进入下一轮
}

void MVBAProcessor::cleanupExpiredInstances() {
  // TODO: 实现过期实例清理逻辑
  // 清理超过一定时间的旧实例状态和缓存
}

void MVBAProcessor::tryBroadcastActive(EpochIndexType _index,
                                       RoundType _round) {
  // TODO: 实现Active消息广播
  MVBA_LOG(INFO) << LOG_DESC("tryBroadcastActive") << LOG_KV("index", _index)
                 << LOG_KV("round", _round);
}

void MVBAProcessor::onCacheLocked(EpochIndexType _index) {
  MVBA_LOG(INFO) << LOG_DESC("onCacheLocked") << LOG_KV("index", _index);

  // 调用注册的回调函数
  if (m_lockNotifyHandler) {
    m_lockNotifyHandler(_index);
  }

  // TODO: 实现cache locked后的处理逻辑
}

void MVBAProcessor::onCacheFinished(EpochIndexType _index) {
  MVBA_LOG(INFO) << LOG_DESC("onCacheFinished") << LOG_KV("index", _index);

  // 测试阶段已禁用定时器，这里不再停止定时器
  // stopInstanceTimer(_index);

  // 调用注册的回调函数
  if (m_finishNotifyHandler) {
    m_finishNotifyHandler(_index);
  }

  // TODO: 实现cache finished后的处理逻辑
}

size_t MVBAProcessor::getPendingMessageCount() const {
  std::lock_guard<std::mutex> lock(m_messageQueueMutex);
  return m_messageQueue.size();
}

size_t MVBAProcessor::getActiveMVBACount() const {
  // 测试阶段禁用 Timer，认为当前没有活跃的定时实例
  return 0;
}

void MVBAProcessor::printStatistics() const {
  MVBA_LOG(INFO) << LOG_DESC("MVBAProcessor Status")
                 << LOG_KV("running", m_running.load())
                 << LOG_KV("totalMessagesReceived",
                           m_totalMessagesReceived.load())
                 << LOG_KV("activeMessages", m_totalActiveMessages.load())
                 << LOG_KV("lockMessages", m_totalLockMessages.load())
                 << LOG_KV("finishMessages", m_totalFinishMessages.load())
                 << LOG_KV("sentMessages", m_totalMessagesSent.load())
                 << LOG_KV("invalidMessages", m_totalInvalidMessages.load())
                 << LOG_KV("pendingMessages", getPendingMessageCount())
                 << LOG_KV("activeMVBAs", getActiveMVBACount());

  if (m_cacheProcessor) {
    m_cacheProcessor->printCacheStatus();
  }
}