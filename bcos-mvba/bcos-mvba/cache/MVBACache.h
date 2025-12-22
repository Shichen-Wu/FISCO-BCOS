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
 * @brief cache for the MVBA consensus state of the proposal
 * @file MVBACache.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "bcos-pbft/bcos-pbft/pbft/config/PBFTConfig.h"
#include "../interfaces/MVBAMessageInterface.h"
#include "../interfaces/MVBAProposalInterface.h"
#include "../interfaces/MVBAEchoInterface.h"
#include "../utilities/Common.h"
#include "bcos-framework/bcos-framework/protocol/Protocol.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <thread>

namespace bcos::consensus {
  class MVBACache : public std::enable_shared_from_this<MVBACache> {
public:
    using Ptr = std::shared_ptr<MVBACache>;

    using CollectionCacheType = std::map<IndexType, MVBAMessageInterface::Ptr>;

    MVBACache(PBFTConfig::Ptr _config, EpochIndexType _index);
    virtual ~MVBACache() = default;

    // 添加Active消息
    virtual void addActiveCache(MVBAMessageInterface::Ptr _activeMsg) {

      // 检查消息是否可以添加
      if (!canAddActiveMessage(_activeMsg)) {
        return;
      }

      auto messageHash = _activeMsg->hash();
      auto generatedFrom = _activeMsg->generatedFrom();

      // 记录active消息的generatedFrom和hash映射
      m_activeList[generatedFrom] = messageHash;

      MVBA_LOG(INFO) << LOG_DESC(
                            "addActiveCache: has received active message: ")
                     << LOG_KV("number", m_activeList.size())
                     << LOG_KV("index", m_index);

      // 如果是第一个active消息，保存proposal并创建自己的active消息
      if (!m_activeProposal) {
        m_activeProposal = _activeMsg->mvbaProposal();
        // 创建自己的active消息
        auto myActiveMsg = createActiveMessage();

        if (myActiveMsg) {
          m_myActive = myActiveMsg;
          m_myActiveHash = myActiveMsg->hash();

          // 将自己的active消息添加到activeList中
          m_activeList[m_config->observerNodeIndex()] = m_myActiveHash;

          // 广播自己的active消息
          MVBA_LOG(INFO) << LOG_DESC("addActiveCache: broadcast my activeMsg")
                         << LOG_KV("Idx", m_config->observerNodeIndex())
                         << LOG_KV("hash", m_myActiveHash.abridged())
                         << LOG_KV("PacketType", myActiveMsg->packetType())
                         << LOG_KV("index", myActiveMsg->index());

          auto encodedData = m_config->mvbaCodec()->encode(myActiveMsg);

          MVBA_LOG(INFO) << LOG_DESC("encodeActiveCache Success");
          // 异步延迟广播：每50个index分组递增1秒
          auto delaySeconds =
              std::chrono::seconds((m_config->observerNodeIndex() / 50) + 1);
          auto frontService = m_config->frontService();
          std::thread([frontService, encodedData, delaySeconds]() {
                        std::this_thread::sleep_for(delaySeconds);
                        if (frontService) {
                          frontService->asyncSendBroadcastMessage(
                              bcos::protocol::NodeType::OBSERVER_NODE, 1000,
                              ref(*encodedData));
                        }
                      }).detach();
          MVBA_LOG(INFO) << LOG_DESC("broadcast Active Message scheduled")
                         << LOG_KV("delaySec", delaySeconds.count());
        } else {
          MVBA_LOG(ERROR) << LOG_DESC(
                                 "addActiveCache: createActiveMessage failed")
                          << LOG_KV("index", m_index)
                          << m_config->printCurrentState();
        }
      }

      // 创建activeEcho消息
      auto activeEchoMsg = createActiveEchoMessage(_activeMsg, messageHash);

      if (activeEchoMsg) {
        if (generatedFrom == m_config->observerNodeIndex()) {
          // 如果是自己的消息，直接添加到本地activeEcho列表
          m_config->mvbaCodec()->encode(activeEchoMsg);

          m_myActive = _activeMsg;
          m_myActiveHash = messageHash;

          /* MVBA_LOG(INFO) << LOG_DESC("addActiveCache: add my activeEcho to
             local cache")
                      << LOG_KV("myNodeIndex", m_config->observerNodeIndex())
                      << LOG_KV("activeHash", messageHash.abridged())
                      << LOG_KV("index", m_index); */

          addActiveEchoCache(activeEchoMsg);
        } else {
          // 如果不是自己的消息，发送activeEcho给active的generatedFrom
          /* MVBA_LOG(INFO) << LOG_DESC("addActiveCache: send activeEcho to
             sealer")
                      << LOG_KV("toSealerId", generatedFrom)
                      << LOG_KV("myNodeIndex", m_config->observerNodeIndex())
                      << LOG_KV("activeHash", messageHash.abridged())
                      << LOG_KV("index", m_index);*/

          auto encodedData = m_config->mvbaCodec()->encode(activeEchoMsg);

          // 获取generatedFrom对应的nodeID
          auto nodeInfo = m_config->getObserverNodeByIndex(generatedFrom);
          if (nodeInfo) {
            // 发送activeEcho消息给active的generatedFrom
            // TODO: ModuleID暂时用1000
            // MVBA_LOG(INFO) << LOG_DESC("addActiveCache: send activeEcho to
            // sealer")
            // << LOG_KV("toSealerId", generatedFrom);

            m_config->frontService()->asyncSendMessageByNodeID(
                1000, nodeInfo->nodeID, ref(*encodedData), 0, // timeout
                nullptr);
          } else {
            MVBA_LOG(ERROR)
                << LOG_DESC(
                       "addActiveCache: can't find nodeInfo for generatedFrom")
                << LOG_KV("generatedFrom", generatedFrom)
                << LOG_KV("index", m_index);
          }
        }
      } else {
        MVBA_LOG(ERROR) << LOG_DESC(
                               "addActiveCache: createActiveEchoMessage failed")
                        << LOG_KV("index", m_index)
                        << m_config->printCurrentState();
      }

      /* MVBA_LOG(INFO) << LOG_DESC("addActiveCache") << LOG_KV("generatedFrom",
         generatedFrom)
                  << LOG_KV("hash", messageHash.abridged())
                  << LOG_KV("index", m_index) << m_config->printCurrentState();
         */
    }

    // 添加ActiveEcho消息
    virtual void addActiveEchoCache(MVBAMessageInterface::Ptr _activeEchoMsg) {
      if (!m_myActive) {
        return;
      }

      // 检查消息是否可以添加
      if (!canAddActiveEchoMessage(_activeEchoMsg)) {
        return;
      }

      // 检查payloadHash是否等于myActiveHash
      if (_activeEchoMsg->mvbaEcho()->payloadHash() != m_myActiveHash) {
        return;
      }

      auto generatedFrom = _activeEchoMsg->generatedFrom();
      m_activeEchoList[generatedFrom] = _activeEchoMsg;

      // 更新activeEchoWeight计数器
      auto nodeInfo = m_config->getObserverNodeByIndex(generatedFrom);
      if (!nodeInfo) {
        return;
      }

      m_activeEchoWeight++; // += nodeInfo->voteWeight;

      MVBA_LOG(INFO) << LOG_DESC("addActiveEchoCache")
                     << LOG_KV("from", generatedFrom)
                     << LOG_KV("activeEchoWeight", m_activeEchoWeight)
                     << LOG_KV("index", m_index);
      //               << m_config->printCurrentState();
    }

    // 添加Lock消息
    virtual void addLockCache(MVBAMessageInterface::Ptr _lockMsg) {

      // 检查消息是否可以添加
      if (!canAddLockMessage(_lockMsg)) {
        return;
      }

      auto messageHash = _lockMsg->hash();
      auto generatedFrom = _lockMsg->generatedFrom();

      // 记录lock消息
      m_lockList[generatedFrom] = _lockMsg;

      MVBA_LOG(INFO) << LOG_DESC("addLockCache: has received active message: ")
                     << LOG_KV("number", m_lockList.size());

      // 创建lockEcho消息
      auto lockEchoMsg = createLockEchoMessage(_lockMsg, messageHash);

      if (lockEchoMsg) {
        if (generatedFrom == m_config->observerNodeIndex()) {

          m_myLock = _lockMsg;
          m_myLockHash = messageHash;

          // 如果是自己的lock消息，直接添加到本地lockEcho列表
          m_config->mvbaCodec()->encode(lockEchoMsg);
          addLockEchoCache(lockEchoMsg);

          MVBA_LOG(INFO) << LOG_DESC(
                                "addLockCache: add my lockEcho to local cache")
                         << LOG_KV("myNodeIndex", m_config->observerNodeIndex())
                         << LOG_KV("lockHash", messageHash.abridged())
                         << LOG_KV("index", m_index);
        } else {
          // 如果不是自己的消息，发送lockEcho给lock的generatedFrom
          /* MVBA_LOG(INFO) << LOG_DESC("addLockCache: send lockEcho to sealer")
                      << LOG_KV("toSealerId", generatedFrom)
                      << LOG_KV("myNodeIndex", m_config->observerNodeIndex())
                      << LOG_KV("lockHash", messageHash.abridged())
                      << LOG_KV("index", m_index);*/

          auto encodedData = m_config->mvbaCodec()->encode(lockEchoMsg);

          // 获取generatedFrom对应的nodeID
          auto nodeInfo = m_config->getObserverNodeByIndex(generatedFrom);
          if (nodeInfo) {
            // 发送lockEcho消息给lock的generatedFrom

            m_config->frontService()->asyncSendMessageByNodeID(
                1000, nodeInfo->nodeID, ref(*encodedData), 0, // timeout
                nullptr);
          } else {
            MVBA_LOG(ERROR)
                << LOG_DESC(
                       "addLockCache: can't find nodeInfo for generatedFrom")
                << LOG_KV("generatedFrom", generatedFrom)
                << LOG_KV("index", m_index);
          }
        }
      } else {
        MVBA_LOG(ERROR) << LOG_DESC(
                               "addLockCache: createLockEchoMessage failed")
                        << LOG_KV("index", m_index)
                        << m_config->printCurrentState();
      }

      MVBA_LOG(INFO) << LOG_DESC("addLockCache")
                     << LOG_KV("generatedFrom", generatedFrom)
                     << LOG_KV("hash", messageHash.abridged());
      //            << LOG_KV("index", m_index) <<
      // m_config->printCurrentState();
    }

    // 添加LockEcho消息
    virtual void addLockEchoCache(MVBAMessageInterface::Ptr _lockEchoMsg) {
      if (!m_myLock) {
        return;
      }

      // 检查消息是否可以添加
      if (!canAddLockEchoMessage(_lockEchoMsg)) {
        return;
      }

      // 检查payloadHash是否等于myLockHash
      if (_lockEchoMsg->mvbaEcho()->payloadHash() != m_myLockHash) {
        return;
      }

      auto generatedFrom = _lockEchoMsg->generatedFrom();
      m_lockEchoList[generatedFrom] = _lockEchoMsg;

      // 更新lockEchoWeight计数器
      auto nodeInfo = m_config->getObserverNodeByIndex(generatedFrom);
      if (!nodeInfo) {
        return;
      }

      m_lockEchoWeight++; // += nodeInfo->voteWeight;

      MVBA_LOG(INFO) << LOG_DESC("addLockEchoCache")
                     << LOG_KV("from", generatedFrom)
                     << LOG_KV("lockEchoWeight", m_lockEchoWeight)
                     << LOG_KV("index", m_index);
      //               << m_config->printCurrentState();
    }

    // 添加Finish消息
    virtual void addFinishCache(MVBAMessageInterface::Ptr _finishMsg) {

      // 检查消息是否可以添加
      if (!canAddFinishMessage(_finishMsg)) {
        return;
      }

      auto generatedFrom = _finishMsg->generatedFrom();
      m_finishList[generatedFrom] = _finishMsg;

      auto nodeInfo = m_config->getObserverNodeByIndex(generatedFrom);
      if (!nodeInfo) {
        return;
      }

      m_finishWeight++; // += nodeInfo->voteWeight;

      // MVBA_LOG(INFO) << LOG_DESC("addFinishCache") << LOG_KV("from",
      // generatedFrom)
      //               << LOG_KV("index", m_index) <<
      // m_config->printCurrentState();
    }

    // 检查并尝试结束active阶段：当收到的activeEchoWeight超过了阈值，也即collectEnoughActiveEcho返回了true，则将m_actived设为1，create
    // lock消息，广播lock消息，并将lock存入mylock，然后返回true；
    virtual bool checkAndActived();

    // 检查并尝试结束lock阶段：当收到的lockEchoWeight超过了阈值，也即collectEnoughLockEcho返回true，则将m_locked设为1，create
    // finish消息，广播finish消息，并将finish存入myfinish，并返回true；
    virtual bool checkAndLocked();

    //检查并尝试结束finish阶段：当收到的finishWeight超过了阈值，也即collectEnoughFinish返回true，则将m_finished设为1，并返回true；
    virtual bool checkAndFinished();

    // 获取相关信息
    bcos::protocol::BlockNumber index() const { return m_index; }
    // virtual MVBAMessageInterface::Ptr lockMessage() { return m_lockMessage; }
    // virtual MVBAMessageInterface::Ptr finishMessage() { return
    // m_finishMessage; }

    bool isActived() const { return m_actived; }
    bool isLocked() const { return m_locked; }
    bool isFinished() const { return m_finished; }

    MVBAProposalInterface::Ptr activeProposal() const {
      return m_activeProposal;
    }
    bcos::crypto::HashType myActiveHash() const { return m_myActiveHash; }
    bcos::crypto::HashType myLockHash() const { return m_myLockHash; }

    virtual void setSignatureList(MVBAProposalInterface::Ptr _proposal,
                                  CollectionCacheType &_cache);

    // 重置缓存状态
    virtual void resetCache() {
      m_actived.store(false);
      m_locked.store(false);
      m_finished.store(false);
      m_activeEchoWeight = 0;
      m_lockEchoWeight = 0;
      m_finishWeight = 0;

      m_activeList.clear();
      m_activeEchoList.clear();
      m_lockList.clear();
      m_lockEchoList.clear();
      m_finishList.clear();

      m_activeProposal = nullptr;
      m_myActive = nullptr;
      m_myLock = nullptr;
      // m_lockMessage = nullptr;
      // m_finishMessage = nullptr;

      m_myActiveHash = bcos::crypto::HashType();
      m_myLockHash = bcos::crypto::HashType();
    }

    void registerLockNotify(
        std::function<void(bcos::protocol::BlockNumber)> _notifier) {
      m_lockNotifier = std::move(_notifier);
    }

    void registerFinishNotify(
        std::function<void(bcos::protocol::BlockNumber)> _notifier) {
      m_finishNotifier = std::move(_notifier);
    }

    bcos::crypto::HashType getProposalHash() const;

    MVBAMessageInterface::Ptr getLeaderFinishMessage(IndexType _leaderId) const;

protected:
    // 检查Active消息是否可以添加
    bool canAddActiveMessage(MVBAMessageInterface::Ptr _activeMsg) {
      if (!_activeMsg || !_activeMsg->mvbaProposal()) {
        return false;
      }

      auto sealerId = _activeMsg->mvbaProposal()->sealerId();

      // 检查sealerId是否已存在
      if (m_activeList.find(sealerId) != m_activeList.end()) {
        return false;
      }

      // 如果已有proposal，检查除sealerId外其他字段是否相同
      if (m_activeProposal) {
        auto currentProposal = _activeMsg->mvbaProposal();
        if (currentProposal->index() != m_activeProposal->index() ||
            currentProposal->round() != m_activeProposal->round() ||
            currentProposal->payloadHash() != m_activeProposal->payloadHash()) {
          return false;
        }
      }

      return true;
    }

    // 检查activeEcho消息是否可以添加
    bool canAddActiveEchoMessage(MVBAMessageInterface::Ptr _activeEchoMsg) {
      if (!_activeEchoMsg || !_activeEchoMsg->mvbaEcho()) {
        return false;
      }

      auto generatedFrom = _activeEchoMsg->generatedFrom();

      // 检查是否已存在该节点的activeEcho消息
      if (m_activeEchoList.find(generatedFrom) != m_activeEchoList.end()) {
        return false;
      }

      return true;
    }

    // 检查Lock消息是否可以添加
    bool canAddLockMessage(MVBAMessageInterface::Ptr _lockMsg) {
      if (!_lockMsg || !_lockMsg->mvbaProposal()) {
        return false;
      }

      auto generatedFrom = _lockMsg->generatedFrom();

      // 检查是否已存在该节点的lock消息
      if (m_lockList.find(generatedFrom) != m_lockList.end()) {
        return false;
      }

      return true;
    }

    // 检查lockEcho消息是否可以添加
    bool canAddLockEchoMessage(MVBAMessageInterface::Ptr _lockEchoMsg) {
      if (!_lockEchoMsg || !_lockEchoMsg->mvbaEcho()) {
        return false;
      }

      auto generatedFrom = _lockEchoMsg->generatedFrom();

      // 检查是否已存在该节点的lockEcho消息
      if (m_lockEchoList.find(generatedFrom) != m_lockEchoList.end()) {
        return false;
      }

      return true;
    }

    // 检查Finish消息是否可以添加
    bool canAddFinishMessage(MVBAMessageInterface::Ptr _finishMsg) {
      if (!_finishMsg || !_finishMsg->mvbaProposal()) {
        return false;
      }

      auto generatedFrom = _finishMsg->generatedFrom();

      // 检查是否已存在该节点的finish消息
      if (m_finishList.find(generatedFrom) != m_finishList.end()) {
        return false;
      }

      return true;
    }

    // 检查是否收集到足够的ActiveEcho
    bool collectEnoughActiveEcho() {
      return m_activeEchoWeight >= m_minRequiredQuorum;
    }

    // 检查是否收集到足够的LockEcho
    bool collectEnoughLockEcho() {
      return m_lockEchoWeight >= m_minRequiredQuorum;
    }

    // 检查是否收集到足够的finish消息
    bool collectEnoughFinish() { return m_finishWeight >= m_minRequiredQuorum; }

    // 根据收到的active创建自己的active消息，具体为将收到的active的值都赋予新的active消息，然后将sealerId替换为自己的，再签名与打包
    virtual MVBAMessageInterface::Ptr createActiveMessage();

    // 创建Lock消息（需要具体实现）根据myActive创建lock消息，具体为myActive的hash值设置为lock的payload，然后从activeEcholist里用每个节点的id和签名填入lock消息里
    virtual MVBAMessageInterface::Ptr createLockMessage();

    // 创建Finish消息（需要具体实现）根据myLock创建finish消息，具体为myLock的hash值设置为finish的payload，然后从lockEcholist里用每个节点的id和签名填入finish消息里
    virtual MVBAMessageInterface::Ptr createFinishMessage();

    // 根据收到的active创建activeEcho消息，具体计算active的hash值并放入activeEcho的payload，然后生成本节点的签名和完整消息
    virtual MVBAMessageInterface::Ptr
    createActiveEchoMessage(MVBAMessageInterface::Ptr, bcos::crypto::HashType);

    // 根据收到的lock创建lockEcho消息，具体计算lock的hash值并放入lockEcho的payload，然后生成本节点的签名和完整消息
    virtual MVBAMessageInterface::Ptr
    createLockEchoMessage(MVBAMessageInterface::Ptr, bcos::crypto::HashType);

protected:
    PBFTConfig::Ptr m_config;
    std::atomic<EpochIndexType> m_index;

    //当前MVBA实例的quorum
    std::atomic<uint64_t> m_minRequiredQuorum;

    // 状态标志
    std::atomic_bool m_actived = { false };
    std::atomic_bool m_locked = { false };
    std::atomic_bool m_finished = { false };

    // Active阶段：IndexType -> HashType 映射
    std::map<IndexType, bcos::crypto::HashType> m_activeList;
    MVBAProposalInterface::Ptr m_activeProposal = nullptr;
    MVBAMessageInterface::Ptr m_myActive = nullptr;
    bcos::crypto::HashType m_myActiveHash;

    // ActiveEcho阶段：IndexType -> MVBAMessageInterface::Ptr 映射
    CollectionCacheType m_activeEchoList;
    uint64_t m_activeEchoWeight = 0;

    // Lock阶段：IndexType -> MVBAMessageInterface::Ptr 映射
    CollectionCacheType m_lockList;
    MVBAMessageInterface::Ptr m_myLock = nullptr;
    bcos::crypto::HashType m_myLockHash;
    // MVBAMessageInterface::Ptr m_lockMessage = nullptr; //要删除

    // LockEcho阶段：IndexType -> MVBAMessageInterface::Ptr 映射
    CollectionCacheType m_lockEchoList;
    uint64_t m_lockEchoWeight = 0;

    // Finish阶段：IndexType -> MVBAMessageInterface::Ptr 映射
    CollectionCacheType m_finishList;
    // MVBAMessageInterface::Ptr m_myFinishMessage = nullptr;
    uint64_t m_finishWeight = 0;

    // 回调函数
    std::function<void(bcos::protocol::BlockNumber)> m_lockNotifier;
    std::function<void(bcos::protocol::BlockNumber)> m_finishNotifier;
  };
} // namespace bcos::consensus