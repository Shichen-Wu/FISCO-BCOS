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
 * @brief MVBA implementation for MVBA Message
 * @file MVBAMessage.cpp
 * @author: yujiechen
 * @date 2021-04-13
 */
#include "MVBAMessage.h"
#include "MVBAProposal.h"
#include "MVBAEcho.h"
#include "bcos-mvba/core/Proposal.h"
#include <utility>

using namespace bcos;
using namespace bcos::consensus;
using namespace bcos::crypto;
using namespace bcos::protocol;

bytesPointer MVBAMessage::encode(
    CryptoSuite::Ptr _cryptoSuite, KeyPairInterface::Ptr _keyPair) const
{
    // encode the MVBABaseMessage
    encodeHashFields();
    generateAndSetSignatureData(_cryptoSuite, _keyPair);
    return encodePBObject(m_mvbaRawMessage);
}

void MVBAMessage::encodeHashFields() const
{
    auto hashFieldsData = MVBABaseMessage::encode();
    m_mvbaRawMessage->set_hashfieldsdata(hashFieldsData->data(), hashFieldsData->size());
}

void MVBAMessage::decode(bytesConstRef _data)
{
    decodePBObject(m_mvbaRawMessage, _data);
    MVBAMessage::deserializeToObject();
}

void MVBAMessage::deserializeToObject()
{
    auto const& hashFieldsData = m_mvbaRawMessage->hashfieldsdata();
    auto baseMessageData =
        bytesConstRef((byte const*)hashFieldsData.c_str(), hashFieldsData.size());
    MVBABaseMessage::decode(baseMessageData);

    // decode the proposals
    m_proposals->clear();
    
    // decode the mvba proposal
    if (m_mvbaRawMessage->has_mvbaproposal())
    {
        auto* mvbaProposal = m_mvbaRawMessage->mutable_mvbaproposal();
        std::shared_ptr<MVBARawProposal> rawMvbaProposal(mvbaProposal);
        m_mvbaProposal = std::make_shared<MVBAProposal>(rawMvbaProposal);
    }
    
    // decode the mvba response
    if (m_mvbaRawMessage->has_mvbaecho())
    {
        auto* mvbaEcho = m_mvbaRawMessage->mutable_mvbaecho();
        std::shared_ptr<MVBARawEcho> rawMvbaEcho(mvbaEcho);
        m_mvbaEcho = std::make_shared<MVBAEcho>(rawMvbaEcho);
    }
    
    // decode the proposal list
    for (int i = 0; i < m_mvbaRawMessage->proposals_size(); i++)
    {
        std::shared_ptr<MVBARawProposal> rawProposal(m_mvbaRawMessage->mutable_proposals(i));
        m_proposals->push_back(std::make_shared<MVBAProposal>(rawProposal));
    }
}

void MVBAMessage::decodeAndSetSignature(CryptoSuite::Ptr _cryptoSuite, bytesConstRef _data)
{
    decode(_data);
    m_signatureDataHash = getHashFieldsDataHash(std::move(_cryptoSuite));
}

void MVBAMessage::setMvbaProposal(MVBAProposalInterface::Ptr _mvbaProposal)
{
    m_mvbaProposal = _mvbaProposal;
    auto mvbaProposal = std::dynamic_pointer_cast<MVBAProposal>(_mvbaProposal);
    // set mvba proposal
    if (m_mvbaRawMessage->has_mvbaproposal())
    {
        m_mvbaRawMessage->unsafe_arena_release_mvbaproposal();
    }
    m_mvbaRawMessage->unsafe_arena_set_allocated_mvbaproposal(
        mvbaProposal->mvbaRawProposal().get());
}

void MVBAMessage::setMvbaEcho(MVBAEchoInterface::Ptr _mvbaEcho)
{
    m_mvbaEcho = _mvbaEcho;
    auto mvbaEcho = std::dynamic_pointer_cast<MVBAEcho>(_mvbaEcho);
    // set mvba response
    if (m_mvbaRawMessage->has_mvbaecho())
    {
        m_mvbaRawMessage->unsafe_arena_release_mvbaecho();
    }
    m_mvbaRawMessage->unsafe_arena_set_allocated_mvbaecho(
        mvbaEcho->MVBARawEcho().get());
}

HashType MVBAMessage::getHashFieldsDataHash(CryptoSuite::Ptr _cryptoSuite) const
{
    auto const& hashFieldsData = m_mvbaRawMessage->hashfieldsdata();
    auto hashFieldsDataRef =
        bytesConstRef((byte const*)hashFieldsData.data(), hashFieldsData.size());
    return _cryptoSuite->hash(hashFieldsDataRef);
}

void MVBAMessage::generateAndSetSignatureData(
    CryptoSuite::Ptr _cryptoSuite, KeyPairInterface::Ptr _keyPair) const
{
    m_signatureDataHash = getHashFieldsDataHash(_cryptoSuite);
    auto signature = _cryptoSuite->signatureImpl()->sign(*_keyPair, m_signatureDataHash, false);
    // set the signature data
    m_mvbaRawMessage->set_signaturedata(signature->data(), signature->size());
}

void MVBAMessage::setProposals(MVBAProposalList const& _proposals)
{
    *m_proposals = _proposals;
    m_mvbaRawMessage->clear_proposals();
    for (const auto& proposal : _proposals)
    {
        auto proposalImpl = std::dynamic_pointer_cast<MVBAProposal>(proposal);
        assert(proposalImpl);
        m_mvbaRawMessage->mutable_proposals()->UnsafeArenaAddAllocated(
            proposalImpl->mvbaRawProposal().get());
    }
}

bool MVBAMessage::operator==(MVBAMessage const& _mvbaMessage) const
{
    if (!MVBABaseMessage::operator==(_mvbaMessage))
    {
        return false;
    }
    
    // check mvba proposal
    if (m_mvbaProposal && _mvbaMessage.m_mvbaProposal)
    {
        auto proposal = std::dynamic_pointer_cast<MVBAProposal>(m_mvbaProposal);
        auto comparedProposal = std::dynamic_pointer_cast<MVBAProposal>(_mvbaMessage.m_mvbaProposal);
        if (*proposal != *comparedProposal)
        {
            return false;
        }
    }
    else if (m_mvbaProposal || _mvbaMessage.m_mvbaProposal)
    {
        return false;
    }
    
    // check mvba response
    if (m_mvbaEcho && _mvbaMessage.m_mvbaEcho)
    {
        auto response = std::dynamic_pointer_cast<MVBAEcho>(m_mvbaEcho);
        auto comparedResponse = std::dynamic_pointer_cast<MVBAEcho>(_mvbaMessage.m_mvbaEcho);
        if (*response != *comparedResponse)
        {
            return false;
        }
    }
    else if (m_mvbaEcho || _mvbaMessage.m_mvbaEcho)
    {
        return false;
    }
    
    // check proposal list
    if (m_proposals->size() != _mvbaMessage.proposals().size())
    {
        return false;
    }
    
    for (size_t i = 0; i < _mvbaMessage.proposals().size(); i++)
    {
        auto proposal = std::dynamic_pointer_cast<MVBAProposal>((*m_proposals)[i]);
        auto comparedProposal =
            std::dynamic_pointer_cast<MVBAProposal>((_mvbaMessage.proposals())[i]);
        if (*proposal != *comparedProposal)
        {
            return false;
        }
    }
    return true;
}