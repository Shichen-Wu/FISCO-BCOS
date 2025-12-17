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
 * @file MVBACache.cpp
 * @author: yujiechen
 * @date 2024-12-15
 */
#include "MVBACache.h"
#include "../interfaces/MVBAMessageFactory.h"
#include <chrono>
#include <thread>

using namespace bcos;
using namespace bcos::consensus;
using namespace bcos::protocol;
using namespace bcos::crypto;

MVBACache::MVBACache(PBFTConfig::Ptr _config, EpochIndexType _index)
  : m_config(std::move(_config)), m_index(_index)
{
    m_minRequiredQuorum = m_config->observerNodesNum() - ((m_config->observerNodesNum() - 1)/3);
}

bool MVBACache::checkAndActived()
{
    // 如果已经actived或者finished，返回false
    if (m_actived)
    {
        return false;
    }

    // 检查是否收集到足够的ActiveEcho
    if (!collectEnoughActiveEcho())
    {
        return false;
    }
    
    MVBA_LOG(INFO) << LOG_DESC("checkAndActived: collectEnoughActiveEcho")
                   << LOG_KV("activeEchoWeight", m_activeEchoWeight)
                   << LOG_KV("minRequiredQuorum", m_minRequiredQuorum)
                   << LOG_KV("index", m_index) << m_config->printCurrentState();
    
    // 设置actived状态
    m_actived.store(true);

    MVBA_LOG(INFO) << LOG_DESC("checkAndActived: m_actived changing success");
    
    // 创建Lock消息
    auto lockMsg = createLockMessage();
    if (!lockMsg)
    {
        MVBA_LOG(ERROR) << LOG_DESC("checkAndActived: createLockMessage failed")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return false;
    }
    
    // 广播Lock消息
    MVBA_LOG(INFO) << LOG_DESC("checkAndActived: broadcast lockMsg")
                   << LOG_KV("Idx", m_config->observerNodeIndex())
                   << LOG_KV("hash", lockMsg->hash().abridged())
                   << LOG_KV("index", lockMsg->index());
    
    auto encodedData = m_config->mvbaCodec()->encode(lockMsg);
    // 异步延迟广播：每50个index分组递增1秒
    auto delaySeconds = std::chrono::seconds((m_config->observerNodeIndex() / 50) + 1);
    auto frontService = m_config->frontService();
    std::thread([frontService, encodedData, delaySeconds]() {
        std::this_thread::sleep_for(delaySeconds);
        if (frontService)
        {
            frontService->asyncSendBroadcastMessage(
                bcos::protocol::NodeType::OBSERVER_NODE, 1000, ref(*encodedData));
        }
    }).detach();

      // 将自己的Lock消息添加到缓存
    addLockCache(lockMsg);
    return true;
}

bool MVBACache::checkAndLocked()
{
    // 如果已经locked,返回false
    if (m_locked)
    {
        return false;
    }
    
    // 检查是否收集到足够的LockEcho
    if (!collectEnoughLockEcho())
    {
        return false;
    }
    
    MVBA_LOG(INFO) << LOG_DESC("checkAndLocked: collectEnoughLockEcho")
                   << LOG_KV("lockEchoWeight", m_lockEchoWeight)
                   << LOG_KV("minRequiredQuorum", m_minRequiredQuorum)
                   << LOG_KV("index", m_index) << m_config->printCurrentState();
    
    // 设置locked状态
    m_locked.store(true);
    
    // 创建Finish消息
    auto finishMsg = createFinishMessage();
    if (!finishMsg)
    {
        MVBA_LOG(ERROR) << LOG_DESC("checkAndLocked: createFinishMessage failed")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return false;
    }
    

    
    // 广播Finish消息
    MVBA_LOG(INFO) << LOG_DESC("checkAndLocked: broadcast finishMsg")
                   << LOG_KV("Idx", m_config->observerNodeIndex())
                   << LOG_KV("hash", finishMsg->hash().abridged())
                   << LOG_KV("index", finishMsg->index());
    
    auto encodedData = m_config->mvbaCodec()->encode(finishMsg);
    // 异步延迟广播：每50个index分组递增1秒
    auto delaySeconds = std::chrono::seconds((m_config->observerNodeIndex() / 50) + 1);
    auto frontService = m_config->frontService();
    std::thread([frontService, encodedData, delaySeconds]() {
        std::this_thread::sleep_for(delaySeconds);
        if (frontService)
        {
            frontService->asyncSendBroadcastMessage(
                bcos::protocol::NodeType::OBSERVER_NODE, 1000, ref(*encodedData));
        }
    }).detach();

    // 将自己的Finish消息添加到缓存
    addFinishCache(finishMsg);
    
    // 调用lock通知回调
    if (m_lockNotifier)
    {
        m_lockNotifier(m_index);
    }
    
    return true;
}

bool MVBACache::checkAndFinished()
{
    // 如果已经finished，返回false
    if (m_finished)
    {
        return false;
    }
    
    // 检查是否收集到足够的Finish消息
    if (!collectEnoughFinish())
    {
        return false;
    }
    
    MVBA_LOG(INFO) << LOG_DESC("checkAndFinished: collectEnoughFinish")
                   << LOG_KV("finishWeight", m_finishWeight)
                   << LOG_KV("minRequiredQuorum", m_minRequiredQuorum)
                   << LOG_KV("index", m_index) << m_config->printCurrentState();
    
    // 设置finished状态
    m_finished.store(true);
    
    // 调用finish通知回调
    if (m_finishNotifier)
    {
        m_finishNotifier(m_index);
    }
    
    return true;
}

MVBAMessageInterface::Ptr MVBACache::createActiveMessage()
{
    if (!m_activeProposal)
    {
        MVBA_LOG(ERROR) << LOG_DESC("createActiveMessage: no activeProposal")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return nullptr;
    }
    
    // 创建新的Active提案，将sealerId替换为自己的
    auto activeProposal = m_config->mvbaMessageFactory()->createMVBAProposal();
    activeProposal->setIndex(m_activeProposal->index());
    activeProposal->setRound(m_activeProposal->round());
    activeProposal->setSealerId(m_config->observerNodeIndex()); // 使用自己的sealerId
    activeProposal->setPayloadHash(m_activeProposal->payloadHash());
    activeProposal->setMvbaInput(m_activeProposal->mvbaInput());

        
    if (!activeProposal) {
            MVBA_LOG(ERROR) << LOG_DESC("Failed to create activeMsg");
            return nullptr;
        }

    // 创建Active消息
    auto activeMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::ActivePacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(), 
        utcTime(),
        m_config->observerNodeIndex(),
        activeProposal,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        true,  // active = true
        false  // needProof = false
    );


    if (!activeMsg) {
            MVBA_LOG(ERROR) << LOG_DESC("Failed to create activeMsg");
            return nullptr;
        }
    
    return activeMsg;
}

MVBAMessageInterface::Ptr MVBACache::createLockMessage()
{
    if (!m_myActive)
    {
        MVBA_LOG(ERROR) << LOG_DESC("createLockMessage: no myActive")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return nullptr;
    }
    
    // 创建Lock提案，payload为myActive的hash值
    auto lockProposal = m_config->mvbaMessageFactory()->createMVBAProposal();
    lockProposal->setIndex(m_myActive->index());
    lockProposal->setRound(m_myActive->round());
    lockProposal->setSealerId(m_config->observerNodeIndex());
    lockProposal->setPayloadHash(m_myActiveHash);
    
    // 从activeEchoList中收集签名证明
    setSignatureList(lockProposal, m_activeEchoList);

    
    // 创建Lock消息
    auto lockMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::LockPacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(),
        utcTime(),
        m_config->observerNodeIndex(),
        lockProposal,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        false, // active = false
        true   // needProof = true
    );
    
    return lockMsg;
}

MVBAMessageInterface::Ptr MVBACache::createFinishMessage()
{
    if (!m_myLock)
    {
        MVBA_LOG(ERROR) << LOG_DESC("createFinishMessage: no myLock")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return nullptr;
    }
    
    // 创建Finish提案，payload为myLock的hash值
    auto finishProposal = m_config->mvbaMessageFactory()->createMVBAProposal();
    finishProposal->setIndex(m_myLock->index());
    finishProposal->setRound(m_myLock->round());
    finishProposal->setSealerId(m_config->observerNodeIndex());
    finishProposal->setPayloadHash(m_myLockHash);
    
    // 从lockEchoList中收集签名证明
    setSignatureList(finishProposal, m_lockEchoList);
    

    // 创建Finish消息
    auto finishMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::FinishPacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(),
        utcTime(),
        m_config->observerNodeIndex(),
        finishProposal,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        false, // active = false
        true   // needProof = true
    );
    
    return finishMsg;
}

MVBAMessageInterface::Ptr MVBACache::createActiveEchoMessage(MVBAMessageInterface::Ptr _active, bcos::crypto::HashType _activeHash)
{
    if (!_active)
    {
        MVBA_LOG(ERROR) << LOG_DESC("createActiveEchoMessage: no myActiveHash")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return nullptr;
    }
    
    // 创建ActiveEcho
    auto activeEcho = m_config->mvbaMessageFactory()->createMVBAEcho();
    if (_active)
    {
        activeEcho->setIndex(_active->index());
        activeEcho->setRound(_active->round());
        activeEcho->setSealerId(_active->sealerId());
    }
    activeEcho->setPayloadHash(_activeHash);
    
    // 创建ActiveEcho消息
    auto activeEchoMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::ActiveEchoPacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(),
        utcTime(),
        m_config->observerNodeIndex(),
        activeEcho,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        true  // needSign = true
    );
    
    return activeEchoMsg;
}

MVBAMessageInterface::Ptr MVBACache::createLockEchoMessage(MVBAMessageInterface::Ptr _lock, bcos::crypto::HashType _lockHash)
{
    if (!_lock)
    {
        MVBA_LOG(ERROR) << LOG_DESC("createLockEchoMessage: no myLockHash")
                        << LOG_KV("index", m_index) << m_config->printCurrentState();
        return nullptr;
    }
    
    // 创建LockEcho
    auto lockEcho = m_config->mvbaMessageFactory()->createMVBAEcho();
    if (_lock)
    {
        lockEcho->setIndex(_lock->index());
        lockEcho->setRound(_lock->round());
        lockEcho->setSealerId(_lock->sealerId());
    }
    lockEcho->setPayloadHash(_lockHash);
    
    // 创建LockEcho消息
    auto lockEchoMsg = m_config->mvbaMessageFactory()->populateFrom(
        MVBAPacketType::LockEchoPacket,
        m_config->mvbaMsgDefaultVersion(),
        m_config->view(),
        utcTime(),
        m_config->observerNodeIndex(),
        lockEcho,
        m_config->cryptoSuite(),
        m_config->keyPair(),
        true  // needSign = true
    );
    
    return lockEchoMsg;
}

void MVBACache::setSignatureList(MVBAProposalInterface::Ptr _proposal, CollectionCacheType& _cache)
{
    if (!_proposal)
    {
        MVBA_LOG(WARNING) << LOG_DESC("setSignatureList: invalid proposal");
        return;
    }
    
    // 清空现有的签名证明
    _proposal->clearSignatureProof();
    
    // 遍历缓存中的消息，提取签名
    for (auto const& it : _cache)
    {
        auto observerNodeIndex = it.first;
        auto mvbaMessage = it.second;
        
        if (!mvbaMessage || !mvbaMessage->mvbaEcho())
        {
            MVBA_LOG(WARNING) << LOG_DESC("setSignatureList: invalid message or proposal")
                              << LOG_KV("observerNodeIndex", observerNodeIndex)
                              << LOG_KV("mvbaMessage", (void*)mvbaMessage.get())
                              << LOG_KV("mvbaMessage->mvbaProposal", (void*)mvbaMessage->mvbaEcho().get());
            continue;
        }
        
        // 获取节点的签名数据
        auto signature = mvbaMessage->signatureData();
        if (signature.empty())
        {
            MVBA_LOG(WARNING) << LOG_DESC("setSignatureList: empty signature")
                              << LOG_KV("observerNodeIndex", observerNodeIndex);
            continue;
        }
        
        // 将节点索引和签名添加到proposal中
        _proposal->appendSignatureProof(observerNodeIndex, signature);
        
        MVBA_LOG(TRACE) << LOG_DESC("setSignatureList: added signature")
                        << LOG_KV("observerNodeIndex", observerNodeIndex)
                        << LOG_KV("signatureSize", signature.size());
    }
    
    MVBA_LOG(INFO) << LOG_DESC("setSignatureList completed")
                   << LOG_KV("totalSignatures", _proposal->signatureProofSize())
                   << LOG_KV("index", _proposal->index())
                   << LOG_KV("round", _proposal->round())
                   << LOG_KV("sealerId", _proposal->sealerId());
}


bcos::crypto::HashType MVBACache::getProposalHash() const
{
    // 优先返回active proposal的hash
    if (m_activeProposal)
    {
        return m_activeProposal->payloadHash();
    }
    
    // 如果没有active proposal，尝试从myActive中获取
    if (m_myActive && m_myActive->mvbaProposal())
    {
        return m_myActive->mvbaProposal()->payloadHash();
    }
    
    // 如果都没有，返回空hash
    MVBA_LOG(WARNING) << LOG_DESC("getProposalHash: no proposal found")
                      << LOG_KV("index", m_index);
    
    return bcos::crypto::HashType();
}

MVBAMessageInterface::Ptr MVBACache::getLeaderFinishMessage(IndexType _leaderId) const
{
    // 在finish消息缓存中查找指定leader的消息
    auto it = m_finishList.find(_leaderId);
    if (it != m_finishList.end())
    {
        MVBA_LOG(INFO) << LOG_DESC("getLeaderFinishMessage: found leader finish message")
                       << LOG_KV("index", m_index)
                       << LOG_KV("leaderId", _leaderId);
        return it->second;
    }
    
    MVBA_LOG(INFO) << LOG_DESC("getLeaderFinishMessage: leader finish message not found")
                   << LOG_KV("index", m_index)
                   << LOG_KV("leaderId", _leaderId)
                   << LOG_KV("finishListSize", m_finishList.size());
    
    return nullptr;
}

