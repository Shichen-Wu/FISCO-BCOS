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
 * @file MVBAMessage.h
 * @author: yujiechen
 * @date 2021-04-13
 */
#pragma once
#include "../interfaces/MVBAMessageInterface.h"
#include "MVBABaseMessage.h"
#include "bcos-mvba/protocol/MVBA.pb.h"

namespace bcos::consensus
{
/**
 * This class is thread-unsafe, should never be writen in multi-thread
 */
class MVBAMessage : public MVBABaseMessage, public MVBAMessageInterface
{
public:
    using Ptr = std::shared_ptr<MVBAMessage>;
    MVBAMessage()
      : MVBABaseMessage(),
        m_mvbaRawMessage(std::make_shared<MVBARawMessage>()),
        m_proposals(std::make_shared<MVBAProposalList>())
    {}

    explicit MVBAMessage(std::shared_ptr<MVBARawMessage> _mvbaRawMessage) : MVBABaseMessage()
    {
        m_mvbaRawMessage = std::move(_mvbaRawMessage);
        m_proposals = std::make_shared<MVBAProposalList>();
        MVBAMessage::deserializeToObject();
    }

    MVBAMessage(bcos::crypto::CryptoSuite::Ptr _cryptoSuite, bytesConstRef _data) : MVBAMessage()
    {
        decodeAndSetSignature(std::move(_cryptoSuite), _data);
    }

    ~MVBAMessage() override
    {
        // return back the ownership to m_mvbaProposal
        if (m_mvbaRawMessage->has_mvbaproposal())
        {
            m_mvbaRawMessage->unsafe_arena_release_mvbaproposal();
        }
        // return the ownership of rawProposal to the passed-in proposal
        auto allocatedProposalSize = m_mvbaRawMessage->proposals_size();
        for (int i = 0; i < allocatedProposalSize; i++)
        {
            m_mvbaRawMessage->mutable_proposals()->UnsafeArenaReleaseLast();
        }
        // return back the ownership to m_mvbaEcho
        if (m_mvbaRawMessage->has_mvbaecho())
        {
            m_mvbaRawMessage->unsafe_arena_release_mvbaecho();
        }
    }

    std::shared_ptr<MVBARawMessage> mvbaRawMessage() { return m_mvbaRawMessage; }
    bytesPointer encode(bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
        bcos::crypto::KeyPairInterface::Ptr _keyPair) const override;
    void decode(bytesConstRef _data) override;

    void setProposals(MVBAProposalList const& _proposals) override;
    MVBAProposalList const& proposals() const override { return *m_proposals; }

    void setMvbaProposal(MVBAProposalInterface::Ptr _mvbaProposal) override;
    MVBAProposalInterface::Ptr mvbaProposal() override { return m_mvbaProposal; }

    void setMvbaEcho(MVBAEchoInterface::Ptr _mvbaEcho) override;
    MVBAEchoInterface::Ptr mvbaEcho() override { return m_mvbaEcho; }

    virtual void decodeAndSetSignature(
        bcos::crypto::CryptoSuite::Ptr _mvbaConfig, bytesConstRef _data);

    bool operator==(MVBAMessage const& _mvbaMessage) const;

    bytesConstRef signatureData() override
    {
        auto const& signatureData = m_mvbaRawMessage->signaturedata();
        return bytesConstRef((byte const*)signatureData.data(), signatureData.size());
    }

    bcos::crypto::HashType const& signatureDataHash() override { return m_signatureDataHash; }

    void setSignatureDataHash(bcos::crypto::HashType const& _hash) override
    {
        m_signatureDataHash = _hash;
    }

    MVBAMessageInterface::Ptr populateWithoutInput() override
    {
        auto mvbaMessage = std::make_shared<MVBAMessage>();
        encodeHashFields();
        auto const& hashFieldData = m_mvbaRawMessage->hashfieldsdata();
        mvbaMessage->mvbaRawMessage()->set_hashfieldsdata(
            hashFieldData.data(), hashFieldData.size());
        mvbaMessage->deserializeToObject();
        return mvbaMessage;
    }

    void encodeHashFields() const;
    void deserializeToObject() override;

    std::string toDebugString() const override
    {
        std::stringstream stringstream;
        stringstream << LOG_KV("type", m_packetType)
                     << LOG_KV("fromNode", m_from ? m_from->shortHex() : "null")
                     << LOG_KV("rawMsgProposalsSize",
                            m_mvbaRawMessage ? m_mvbaRawMessage->proposals_size() : 0)
                     << LOG_KV("mvbaProposal",
                            m_mvbaProposal ? printMVBAProposal(m_mvbaProposal) : "null")
                     << LOG_KV("mvbaEcho",
                            m_mvbaEcho ? printMVBAEcho(m_mvbaEcho) : "null");

        return stringstream.str();
    }

protected:
    virtual bcos::crypto::HashType getHashFieldsDataHash(
        bcos::crypto::CryptoSuite::Ptr _cryptoSuite) const;
    virtual void generateAndSetSignatureData(bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
        bcos::crypto::KeyPairInterface::Ptr _keyPair) const;

private:
    std::shared_ptr<MVBARawMessage> m_mvbaRawMessage;
    MVBAProposalInterface::Ptr m_mvbaProposal;
    MVBAEchoInterface::Ptr m_mvbaEcho;
    MVBAProposalListPtr m_proposals;

    mutable bcos::crypto::HashType m_signatureDataHash;
};
}  // namespace bcos::consensus