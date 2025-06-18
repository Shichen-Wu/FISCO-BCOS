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
 * @brief factory for MVBAMessage
 * @file MVBAMessageFactory.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "MVBAMessageInterface.h"
#include "MVBAProposalInterface.h"
#include "MVBAEchoInterface.h"
#include <bcos-crypto/interfaces/crypto/CryptoSuite.h>
#include <bcos-framework/protocol/ProtocolTypeDef.h>

namespace bcos
{
namespace consensus
{
class MVBAMessageFactory
{
public:
    using Ptr = std::shared_ptr<MVBAMessageFactory>;
    MVBAMessageFactory() = default;
    virtual ~MVBAMessageFactory() {}

    // 创建基础消息对象
    virtual MVBAMessageInterface::Ptr createMVBAMsg() = 0;
    virtual MVBAMessageInterface::Ptr createMVBAMsg(
        bcos::crypto::CryptoSuite::Ptr _cryptoSuite, bytesConstRef _data) = 0;

    // 创建MVBA提案对象
    virtual MVBAProposalInterface::Ptr createMVBAProposal() = 0;
    virtual MVBAProposalInterface::Ptr createMVBAProposal(bytesConstRef _data) = 0;

    // 创建MVBA Echo对象
    virtual MVBAEchoInterface::Ptr createMVBAEcho() = 0;
    virtual MVBAEchoInterface::Ptr createMVBAEcho(bytesConstRef _data) = 0;

    // 从现有Proposal创建新的Proposal（用于复制和过滤字段）
    virtual MVBAProposalInterface::Ptr populateFrom(
        MVBAProposalInterface::Ptr _proposal, bool _withInput = true, bool _withProof = true)
    {
        auto proposal = createMVBAProposal();
        proposal->setIndex(_proposal->index());
        proposal->setRound(_proposal->round());
        proposal->setSealerId(_proposal->sealerId());
        proposal->setPayloadHash(_proposal->payloadHash());
        
        // 根据参数决定是否包含input
        if (_withInput && _proposal->mvbaInput())
        {
            proposal->setMvbaInput(_proposal->mvbaInput());
        }
        
        // 根据参数决定是否包含signature proof
        if (_withProof)
        {
            auto signatureSize = _proposal->signatureProofSize();
            for (size_t i = 0; i < signatureSize; i++)
            {
                auto proof = _proposal->signatureProof(i);
                proposal->appendSignatureProof(proof.first, proof.second);
            }
        }
        
        return proposal;
    }

    // 从Proposal创建MVBA消息（用于active, lock等消息类型）
    virtual MVBAMessageInterface::Ptr populateFrom(MVBAPacketType _packetType, int32_t _version,
        ViewType _view, int64_t _timestamp, IndexType _generatedFrom,
        MVBAProposalInterface::Ptr _proposal, bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
        bcos::crypto::KeyPairInterface::Ptr _keyPair, bool _active = true, bool _needProof = true)
    {
        auto mvbaMessage = createMVBAMsg();
        mvbaMessage->setPacketType(_packetType);
        mvbaMessage->setVersion(_version);
        mvbaMessage->setView(_view);
        mvbaMessage->setTimestamp(_timestamp);
        mvbaMessage->setGeneratedFrom(_generatedFrom);
        mvbaMessage->setHash(_proposal->payloadHash());
        mvbaMessage->setIndex(_proposal->index());
        mvbaMessage->setRound(_proposal->round());
        mvbaMessage->setSealerId(_proposal->sealerId());
        
        // 创建签名的proposal
        auto signedProposal = createMVBAProposal();
        signedProposal->setIndex(_proposal->index());
        signedProposal->setRound(_proposal->round());
        signedProposal->setSealerId(_proposal->sealerId());
        signedProposal->setPayloadHash(_proposal->payloadHash());
        
        if (_active && _proposal->mvbaInput())
        {
            signedProposal->setMvbaInput(_proposal->mvbaInput());
        }
        

        if (_needProof)
        {
             auto signatureSize = _proposal->signatureProofSize();
        for (size_t i = 0; i < signatureSize; i++)
        {
            auto proof = _proposal->signatureProof(i);
            signedProposal->appendSignatureProof(proof.first, proof.second);
        }
        }
        
        mvbaMessage->setMvbaProposal(signedProposal);
        return mvbaMessage;
    }

    // 从Echo创建MVBA消息（用于echo等响应消息类型）
    virtual MVBAMessageInterface::Ptr populateFrom(MVBAPacketType _packetType, int32_t _version,
        ViewType _view, int64_t _timestamp, IndexType _generatedFrom,
        MVBAEchoInterface::Ptr _echo, bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
        bcos::crypto::KeyPairInterface::Ptr _keyPair, bool _needSign = true)
    {
        auto mvbaMessage = createMVBAMsg();
        mvbaMessage->setPacketType(_packetType);
        mvbaMessage->setVersion(_version);
        mvbaMessage->setView(_view);
        mvbaMessage->setTimestamp(_timestamp);
        mvbaMessage->setGeneratedFrom(_generatedFrom);
        mvbaMessage->setHash(_echo->payloadHash());
        mvbaMessage->setIndex(_echo->index());
        mvbaMessage->setRound(_echo->round());
        mvbaMessage->setSealerId(_echo->sealerId());
        
        // 创建签名的echo
        auto signedEcho = createMVBAEcho();
        signedEcho->setIndex(_echo->index());
        signedEcho->setRound(_echo->round());
        signedEcho->setSealerId(_echo->sealerId());
        signedEcho->setPayloadHash(_echo->payloadHash());
        
        mvbaMessage->setMvbaEcho(signedEcho);
        return mvbaMessage;
    }

    // 从Proposal直接创建MVBA消息（无需签名处理）
    virtual MVBAMessageInterface::Ptr populateFrom(MVBAPacketType _packetType,
        MVBAProposalInterface::Ptr _proposal, int32_t _version, ViewType _view, int64_t _timestamp,
        IndexType _generatedFrom)
    {
        auto mvbaMessage = createMVBAMsg();
        mvbaMessage->setPacketType(_packetType);
        mvbaMessage->setVersion(_version);
        mvbaMessage->setView(_view);
        mvbaMessage->setTimestamp(_timestamp);
        mvbaMessage->setGeneratedFrom(_generatedFrom);
        mvbaMessage->setHash(_proposal->payloadHash());
        mvbaMessage->setIndex(_proposal->index());
        mvbaMessage->setRound(_proposal->round());
        mvbaMessage->setSealerId(_proposal->sealerId());
        mvbaMessage->setMvbaProposal(_proposal);
        return mvbaMessage;
    }

    // 从Echo直接创建MVBA消息（无需签名处理）
    virtual MVBAMessageInterface::Ptr populateFrom(MVBAPacketType _packetType,
        MVBAEchoInterface::Ptr _echo, int32_t _version, ViewType _view, int64_t _timestamp,
        IndexType _generatedFrom)
    {
        auto mvbaMessage = createMVBAMsg();
        mvbaMessage->setPacketType(_packetType);
        mvbaMessage->setVersion(_version);
        mvbaMessage->setView(_view);
        mvbaMessage->setTimestamp(_timestamp);
        mvbaMessage->setGeneratedFrom(_generatedFrom);
        mvbaMessage->setHash(_echo->payloadHash());
        mvbaMessage->setIndex(_echo->index());
        mvbaMessage->setRound(_echo->round());
        mvbaMessage->setSealerId(_echo->sealerId());
        mvbaMessage->setMvbaEcho(_echo);
        return mvbaMessage;
    }
};
}  // namespace consensus
}  // namespace bcos