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
 * @file MVBACacheProcessor.cpp
 * @author: yujiechen
 * @date 2024-12-15
 */
#include "MVBACacheProcessor.h"
#include <algorithm>
#include <chrono>
#include <shared_mutex>
#include <thread>

using namespace bcos;
using namespace bcos::consensus;
using namespace bcos::protocol;
using namespace bcos::crypto;

MVBACacheProcessor::MVBACacheProcessor(PBFTConfig::Ptr _config,
                                       MVBACacheFactory::Ptr _factory)
  : m_config(std::move(_config)),
    m_factory(_factory ? std::move(_factory)
                       : std::make_shared<MVBACacheFactory>()) {}

void MVBACacheProcessor::init() {
  MVBA_LOG(INFO) << LOG_DESC("MVBACacheProcessor::init");
}

void MVBACacheProcessor::reset() {
  std::unique_lock<std::shared_mutex> lock(m_cachesMutex);

  MVBA_LOG(INFO) << LOG_DESC("MVBACacheProcessor::reset")
                 << LOG_KV("cacheCount", m_caches.size());

  // 重置所有缓存
  for (auto &pair : m_caches) {
    if (pair.second) {
      pair.second->resetCache();
    }
  }

  m_caches.clear();

  // 重置统计信息
  m_processedActiveCount = 0;
  m_processedActiveEchoCount = 0;
  m_processedLockCount = 0;
  m_processedLockEchoCount = 0;
  m_processedFinishCount = 0;
}

void MVBACacheProcessor::startMVBAInstance(EpochIndexType _index,
                                           bytesConstRef _input) {
  auto initialMsg = m_config->mvbaCodec()->decodeToMVBAMessage(_input);
  processActiveMessage(initialMsg);
}

bool
MVBACacheProcessor::processActiveMessage(MVBAMessageInterface::Ptr _activeMsg) {
  if (!isValidMessage(_activeMsg)) {
    MVBA_LOG(WARNING) << LOG_DESC("processActiveMessage: invalid message");
    return false;
  }

  auto result =
      processMessageInternal(_activeMsg, [_activeMsg](MVBACache::Ptr cache) {
        cache->addActiveCache(_activeMsg);
      });

  if (result) {
    m_processedActiveCount++;
    // MVBA_LOG(INFO) << LOG_DESC("processActiveMessage success")
    //              << LOG_KV("index", _activeMsg->index())
    //             << LOG_KV("from", _activeMsg->generatedFrom())
    //            << LOG_KV("totalProcessed", m_processedActiveCount.load());
  }

  return result;
}

bool MVBACacheProcessor::processActiveEchoMessage(
    MVBAMessageInterface::Ptr _activeEchoMsg) {
  if (!isValidMessage(_activeEchoMsg)) {
    MVBA_LOG(WARNING) << LOG_DESC("processActiveEchoMessage: invalid message");
    return false;
  }

  auto result = processMessageInternal(_activeEchoMsg,
                                       [_activeEchoMsg](MVBACache::Ptr cache) {
    cache->addActiveEchoCache(_activeEchoMsg);
  });

  if (result) {
    m_processedActiveEchoCount++;
    /* MVBA_LOG(INFO) << LOG_DESC("processActiveEchoMessage success")
                   << LOG_KV("index", _activeEchoMsg->index())
                   << LOG_KV("from", _activeEchoMsg->generatedFrom())
                   << LOG_KV("totalProcessed",
       m_processedActiveEchoCount.load());*/
  }

  return result;
}

bool
MVBACacheProcessor::processLockMessage(MVBAMessageInterface::Ptr _lockMsg) {
  if (!isValidMessage(_lockMsg)) {
    MVBA_LOG(WARNING) << LOG_DESC("processLockMessage: invalid message");
    return false;
  }

  auto result = processMessageInternal(
      _lockMsg,
      [_lockMsg](MVBACache::Ptr cache) { cache->addLockCache(_lockMsg); });

  if (result) {
    m_processedLockCount++;
    /* MVBA_LOG(INFO) << LOG_DESC("processLockMessage success")
                   << LOG_KV("index", _lockMsg->index())
                   << LOG_KV("from", _lockMsg->generatedFrom())
                   << LOG_KV("totalProcessed", m_processedLockCount.load()); */
  }

  return result;
}

bool MVBACacheProcessor::processLockEchoMessage(
    MVBAMessageInterface::Ptr _lockEchoMsg) {
  if (!isValidMessage(_lockEchoMsg)) {
    MVBA_LOG(WARNING) << LOG_DESC("processLockEchoMessage: invalid message");
    return false;
  }

  auto result = processMessageInternal(_lockEchoMsg,
                                       [_lockEchoMsg](MVBACache::Ptr cache) {
    cache->addLockEchoCache(_lockEchoMsg);
  });

  if (result) {
    m_processedLockEchoCount++;
    /* MVBA_LOG(INFO) << LOG_DESC("processLockEchoMessage success")
                   << LOG_KV("index", _lockEchoMsg->index())
                   << LOG_KV("from", _lockEchoMsg->generatedFrom())
                   << LOG_KV("totalProcessed", m_processedLockEchoCount.load());
       */
  }

  return result;
}

bool
MVBACacheProcessor::processFinishMessage(MVBAMessageInterface::Ptr _finishMsg) {
  if (!isValidMessage(_finishMsg)) {
    MVBA_LOG(WARNING) << LOG_DESC("processFinishMessage: invalid message");
    return false;
  }

  auto result =
      processMessageInternal(_finishMsg, [_finishMsg](MVBACache::Ptr cache) {
        cache->addFinishCache(_finishMsg);
      });

  if (result) {
    m_processedFinishCount++;
    /* MVBA_LOG(INFO) << LOG_DESC("processFinishMessage success")
                   << LOG_KV("index", _finishMsg->index())
                   << LOG_KV("from", _finishMsg->generatedFrom())
                   << LOG_KV("totalProcessed", m_processedFinishCount.load());
       */
  }

  return result;
}

MVBACache::Ptr MVBACacheProcessor::getOrCreateCache(EpochIndexType _index) {
  std::unique_lock lock(m_cachesMutex);

  auto it = m_caches.find(_index);
  if (it != m_caches.end()) {
    return it->second;
  }

  //{
  //    std::shared_lock<std::shared_mutex> lock(m_cachesMutex);
  //    auto it = m_caches.find(_index);
  //    if (it != m_caches.end())
  //    {
  //        return it->second;
  //    }
  // }

  // 需要创建新缓存，使用写锁
  // std::unique_lock<std::shared_mutex> lock(m_cachesMutex);

  // 双重检查，防止在获取写锁期间其他线程已经创建了缓存
  // auto it = m_caches.find(_index);
  // if (it != m_caches.end())
  //{
  //    return it->second;
  //}

  // 创建新的缓存
  auto cache = createCache(_index);
  if (cache) {
    m_caches[_index] = cache;
    MVBA_LOG(INFO) << LOG_DESC("getOrCreateCache: created new cache")
                   << LOG_KV("index", _index)
                   << LOG_KV("totalCaches", m_caches.size());
  } else {
    MVBA_LOG(ERROR) << LOG_DESC("getOrCreateCache: failed to create cache")
                    << LOG_KV("index", _index);
  }

  return cache;
}

MVBACache::Ptr MVBACacheProcessor::getCache(EpochIndexType _index) const {
  std::shared_lock<std::shared_mutex> lock(m_cachesMutex);
  auto it = m_caches.find(_index);
  return (it != m_caches.end()) ? it->second : nullptr;
}

void MVBACacheProcessor::removeCache(EpochIndexType _index) {
  std::unique_lock<std::shared_mutex> lock(m_cachesMutex);
  auto it = m_caches.find(_index);
  if (it != m_caches.end()) {
    MVBA_LOG(INFO) << LOG_DESC("removeCache") << LOG_KV("index", _index)
                   << LOG_KV("remainingCaches", m_caches.size() - 1);
    m_caches.erase(it);
  }
}

void MVBACacheProcessor::clearExpiredCache(EpochIndexType _minIndex) {
  std::unique_lock<std::shared_mutex> lock(m_cachesMutex);

  size_t removedCount = 0;
  auto it = m_caches.begin();
  while (it != m_caches.end()) {
    if (it->first < _minIndex) {
      it = m_caches.erase(it);
      removedCount++;
    } else {
      ++it;
    }
  }

  if (removedCount > 0) {
    MVBA_LOG(INFO) << LOG_DESC("clearExpiredCache")
                   << LOG_KV("minIndex", _minIndex)
                   << LOG_KV("removedCount", removedCount)
                   << LOG_KV("remainingCaches", m_caches.size());
  }
}

void MVBACacheProcessor::checkAndAdvanceAll() {
  std::vector<EpochIndexType> indexes = getCacheIndexes();

  for (auto index : indexes) {
    checkAndAdvance(index);
  }
}

void MVBACacheProcessor::checkAndAdvance(EpochIndexType _index) {
  auto cache = getCache(_index);
  if (!cache) {
    return;
  }

  bool stateChanged = false;

  // 检查并推进Active阶段
  if (!cache->isActived() && cache->checkAndActived()) {
    // MVBA_LOG(INFO) << LOG_DESC("checkAndAdvance: cache actived")
    //               << LOG_KV("index", _index);
    stateChanged = true;
  }

  // 检查并推进Lock阶段
  if (!cache->isLocked() && cache->checkAndLocked()) {
    // MVBA_LOG(INFO) << LOG_DESC("checkAndAdvance: cache locked")
    //               << LOG_KV("index", _index);
    stateChanged = true;
  }

  // 检查并推进Finish阶段
  if (!cache->isFinished() && cache->checkAndFinished()) {
    // MVBA_LOG(INFO) << LOG_DESC("checkAndAdvance: cache finished")
    //                << LOG_KV("index", _index);
    stateChanged = true;
  }

  if (cache->isFinished()) {
    // 当cache已经是finished状态时，执行leader选举和消息查找逻辑
    handleFinishedCache(_index);
  }

  if (stateChanged) {
    printCacheStatus();
  }
}

void MVBACacheProcessor::updateFinishedState(
    MVBAMessageInterface::Ptr _notifyFinishedMsg) {
  // 获取消息的index
  auto index = _notifyFinishedMsg->index();

  // 根据index找到对应的cache
  auto cache = getCache(index);
  if (!cache) {
    MVBA_LOG(WARNING) << LOG_DESC(
                             "processNotifyFinishedMessage: cache has released")
                      << LOG_KV("index", index);
    return;
  }

  // 检查cache的isFinished标记是否为1
  if (cache->isFinished()) {
    // MVBA_LOG(INFO) << LOG_DESC("processNotifyFinishedMessage: cache already
    // finished")
    //                << LOG_KV("index", index);
  }

  // TODO：MVBA输出后更新区块链逻辑
  // 当前阶段仅转发NotifyFinished并清理对应cache
  auto encodedData = m_config->mvbaCodec()->encode(_notifyFinishedMsg);

  auto delaySeconds =
      std::chrono::seconds((m_config->observerNodeIndex() / 50) + 1);
  auto frontService = m_config->frontService();
  std::thread([frontService, encodedData, delaySeconds]() {
                std::this_thread::sleep_for(delaySeconds);
                if (frontService) {
                  frontService->asyncSendBroadcastMessage(
                      bcos::protocol::NodeType::OBSERVER_NODE, ModuleID::PBFT,
                      ref(*encodedData));
                }
              }).detach();

  // MVBA完成，删除历史cache
  for (auto i = m_currentIndex + 1; i <= index; i++) {
    auto cache = getCache(i);
    if (cache) {
      removeCache(i);
    }
  }
  m_currentIndex = index;
  MVBA_LOG(INFO) << LOG_DESC("updateFinishedState: remove cache")
                 << LOG_KV("currentIndex", m_currentIndex)
                 << LOG_KV("index", index);
}

void MVBACacheProcessor::handleFinishedCache(EpochIndexType _index) {
  auto cache = getCache(_index);
  if (!cache) {
    MVBA_LOG(ERROR) << LOG_DESC("handleFinishedCache: cache not found")
                    << LOG_KV("index", _index);
  }

  if (!cache->isFinished()) {
    MVBA_LOG(WARNING) << LOG_DESC("handleFinishedCache: cache not finished")
                      << LOG_KV("index", _index);
  }

  // 获取当前cache的proposal hash用于leader选举
  auto proposalHash = cache->getProposalHash();
  if (!proposalHash) {
    MVBA_LOG(ERROR) << LOG_DESC("handleFinishedCache: empty proposal hash")
                    << LOG_KV("index", _index);
  }

  // 计算elected leader
  auto electedLeader = calculateElectedLeader(proposalHash);

  /* MVBA_LOG(INFO) << LOG_DESC("handleFinishedCache: calculated elected
     leader")
                 << LOG_KV("index", _index)
                 << LOG_KV("proposalHash", proposalHash.abridged())
                 << LOG_KV("electedLeader", electedLeader); */

  // 查找elected leader的finish消息
  auto leaderFinishMsg = cache->getLeaderFinishMessage(electedLeader);
  if (leaderFinishMsg) {

    // TODO:解析proposal，回滚账本和链
    //

    //发送NotifyFinished消息
    leaderFinishMsg->setPacketType(NotifyFinishedPacket);
    auto encodedData = m_config->mvbaCodec()->encode(leaderFinishMsg);

    auto delaySeconds =
        std::chrono::seconds((m_config->observerNodeIndex() / 50) + 1);
    auto frontService = m_config->frontService();
    std::thread([frontService, encodedData, delaySeconds]() {
                  std::this_thread::sleep_for(delaySeconds);
                  if (frontService) {
                    frontService->asyncSendBroadcastMessage(
                        bcos::protocol::NodeType::OBSERVER_NODE, ModuleID::PBFT,
                        ref(*encodedData));
                  }
                }).detach();

    // 找到了leader的finish消息，处理完成，删除历史cache
    for (auto i = m_currentIndex + 1; i <= _index; i++) {
      auto cache = getCache(i);
      if (cache) {
        removeCache(i);
      }
    }
    m_currentIndex = _index;

    MVBA_LOG(INFO) << LOG_DESC(
                          "handleFinishedCache: found leader finish message, "
                          "completed MVBA;") << LOG_KV("index", _index)
                   << LOG_KV("electedLeader", electedLeader);
    return;
  }

  // TODO:没找到finish，进入prevote+vote阶段
  MVBA_LOG(ERROR) << LOG_DESC(
                         "handleFinishedCache: neither finish nor lock message "
                         "found for elected leader") << LOG_KV("index", _index)
                  << LOG_KV("electedLeader", electedLeader);
}

IndexType MVBACacheProcessor::calculateElectedLeader(
    const bcos::crypto::HashType &_proposalHash) const {
  if (!_proposalHash || m_config->observerNodeList().size() == 0) {
    MVBA_LOG(ERROR) << LOG_DESC("calculateElectedLeader: invalid parameters")
                    << LOG_KV("hashEmpty", !_proposalHash)
                    << LOG_KV("observerNodeSize",
                              m_config->observerNodeList().size());
    return 0;
  }

  // 将hash转换为大整数，然后对节点数量取模
  // 这里使用hash的前8字节作为uint64_t进行计算
  uint64_t hashValue = 0;
  const size_t bytesToUse =
      std::min(sizeof(uint64_t), static_cast<size_t>(_proposalHash.size()));

  for (size_t i = 0; i < bytesToUse; ++i) {
    hashValue = (hashValue << 8) | static_cast<uint8_t>(_proposalHash[i]);
  }

  auto electedLeader =
      static_cast<IndexType>(hashValue % m_config->observerNodeList().size());

  MVBA_LOG(TRACE) << LOG_DESC("calculateElectedLeader")
                  << LOG_KV("proposalHash", _proposalHash.abridged())
                  << LOG_KV("hashValue", hashValue)
                  << LOG_KV("observerNodeSize",
                            m_config->observerNodeList().size())
                  << LOG_KV("electedLeader", electedLeader);

  return electedLeader;
}

void MVBACacheProcessor::registerLockNotify(LockNotifierType _notifier) {
  m_lockNotifier = std::move(_notifier);
}

void MVBACacheProcessor::registerFinishNotify(FinishNotifierType _notifier) {
  m_finishNotifier = std::move(_notifier);
}

size_t MVBACacheProcessor::getCacheCount() const {
  std::shared_lock<std::shared_mutex> lock(m_cachesMutex);
  return m_caches.size();
}

std::vector<EpochIndexType> MVBACacheProcessor::getCacheIndexes() const {
  std::shared_lock<std::shared_mutex> lock(m_cachesMutex);
  std::vector<EpochIndexType> indexes;
  indexes.reserve(m_caches.size());

  for (const auto &pair : m_caches) {
    indexes.push_back(pair.first);
  }

  return indexes;
}

bool MVBACacheProcessor::isValidMessage(MVBAMessageInterface::Ptr _msg) const {
  if (!_msg) {
    return false;
  }

  // 基本的消息有效性检查
  if (_msg->generatedFrom() >= m_config->observerNodeList().size()) {
    MVBA_LOG(WARNING) << LOG_DESC("isValidMessage: invalid generatedFrom")
                      << LOG_KV("generatedFrom", _msg->generatedFrom())
                      << LOG_KV("observerNodeSize",
                                m_config->observerNodeList().size());
    return false;
  }

  return true;
}

MVBACache::Ptr MVBACacheProcessor::createCache(EpochIndexType _index) {
  auto cache = m_factory->createMVBACache(m_config, _index);

  if (cache) {
    // 注册回调函数
    // cache->registerLockNotify([this](EpochIndexType index) {
    //    onCacheLocked(index);
    //});

    // cache->registerFinishNotify([this](EpochIndexType index) {
    //    onCacheFinished(index);
    //});

    MVBA_LOG(INFO) << LOG_DESC("createCache success")
                   << LOG_KV("index", _index);
  } else {
    MVBA_LOG(ERROR) << LOG_DESC("createCache failed")
                    << LOG_KV("index", _index);
  }

  return cache;
}

bool MVBACacheProcessor::processMessageInternal(
    MVBAMessageInterface::Ptr _msg,
    std::function<void(MVBACache::Ptr)> _processor) {
  if (!_msg || !_processor) {
    return false;
  }

  auto cache = getOrCreateCache(_msg->index());
  if (!cache) {
    MVBA_LOG(ERROR) << LOG_DESC("processMessageInternal: failed to get cache")
                    << LOG_KV("index", _msg->index());
    return false;
  }

  // 处理消息
  _processor(cache);

  // 尝试推进状态
  checkAndAdvance(_msg->index());

  return true;
}

void MVBACacheProcessor::onCacheLocked(EpochIndexType _index) {
  MVBA_LOG(INFO) << LOG_DESC("onCacheLocked") << LOG_KV("index", _index);

  if (m_lockNotifier) {
    m_lockNotifier(_index);
  }
}

void MVBACacheProcessor::onCacheFinished(EpochIndexType _index) {
  MVBA_LOG(INFO) << LOG_DESC("onCacheFinished") << LOG_KV("index", _index);

  if (m_finishNotifier) {
    m_finishNotifier(_index);
  }
}

void MVBACacheProcessor::printCacheStatus() const {
  std::shared_lock<std::shared_mutex> lock(m_cachesMutex);
  MVBA_LOG(INFO) << LOG_DESC("=== Cache Status ===")
                 << LOG_KV("totalCaches", m_caches.size())
                 << LOG_KV("processedActive", m_processedActiveCount.load())
                 << LOG_KV("processedActiveEcho",
                           m_processedActiveEchoCount.load())
                 << LOG_KV("processedLock", m_processedLockCount.load())
                 << LOG_KV("processedLockEcho", m_processedLockEchoCount.load())
                 << LOG_KV("processedFinish", m_processedFinishCount.load());

  for (const auto &pair : m_caches) {
    auto cache = pair.second;
    if (cache) {
      MVBA_LOG(INFO) << LOG_DESC("Cache Status") << LOG_KV("index", pair.first)
                     << LOG_KV("actived", cache->isActived())
                     << LOG_KV("locked", cache->isLocked())
                     << LOG_KV("finished", cache->isFinished());
    }
  }
}
