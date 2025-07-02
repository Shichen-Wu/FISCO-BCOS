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
 * @brief implementation for MVBAProposal
 * @file MVBAProposal.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/MVBAProposalInterface.h"
#include "bcos-mvba/protocol/MVBA.pb.h"
#include "EquivocationProof.h"
#include <bcos-protocol/Common.h>

namespace bcos
{
namespace consensus
{
class MVBAProposal : public MVBAProposalInterface
{
public:
    using Ptr = std::shared_ptr<MVBAProposal>;
    MVBAProposal()
    {
        m_mvbaRawProposal = std::make_shared<MVBARawProposal>();
    }
    explicit MVBAProposal(bytesConstRef _data)
    {
        m_mvbaRawProposal = std::make_shared<MVBARawProposal>();
        decode(_data);
    }
    explicit MVBAProposal(std::shared_ptr<MVBARawProposal> _mvbaRawProposal)
      : m_mvbaRawProposal(_mvbaRawProposal)
    {
        deserializeToObject();
    }

    ~MVBAProposal() override = default;

    std::shared_ptr<MVBARawProposal> mvbaRawProposal() { return m_mvbaRawProposal; }

    // MVBAProposalInterface implementation
    int64_t index() const override { return m_mvbaRawProposal->index(); }
    void setIndex(int64_t _index) override { m_mvbaRawProposal->set_index(_index); }
    int32_t round() const override { return m_mvbaRawProposal->round(); }
    void setRound(int32_t _round) override { m_mvbaRawProposal->set_round(_round); }

    int64_t sealerId() const override { return m_mvbaRawProposal->sealerid(); }
    void setSealerId(int64_t _sealerId) override { m_mvbaRawProposal->set_sealerid(_sealerId); }

    EquivocationProofInterface::Ptr mvbaInput() const override { return m_mvbaInput; }
    //void setMvbaInput(EquivocationProofInterface::Ptr _mvbaInput) override 
    //{
    //    m_mvbaInput = _mvbaInput;
    //    auto equivocationProof = std::dynamic_pointer_cast<EquivocationProof>(_mvbaInput);
        //set mvbainput, i.e. equivocation proof
    //    if (m_mvbaRawProposal->has_mvbainput())
    //    {
    //        m_mvbaRawProposal->unsafe_arena_release_mvbainput();
    //    }
    //    m_mvbaRawProposal->unsafe_arena_set_allocated_mvbainput(
    //        equivocationProof->rawEquivocationProof().get());
    //}

    void setMvbaInput(EquivocationProofInterface::Ptr _mvbaInput) override
    {
        m_mvbaInput = _mvbaInput;
        auto equivocationProof = std::dynamic_pointer_cast<EquivocationProof>(_mvbaInput);
    
        if (equivocationProof && equivocationProof->rawEquivocationProof()) {
            // 使用 mutable_mvbainput() 获取可修改的指针，然后拷贝内容
            m_mvbaRawProposal->mutable_mvbainput()->CopyFrom(
                *equivocationProof->rawEquivocationProof());
        }
    }



    bcos::crypto::HashType const& payloadHash() const override { return m_payloadHash; }
    void setPayloadHash(bcos::crypto::HashType const& _payloadHash) override
    {
        m_payloadHash = _payloadHash;
        m_mvbaRawProposal->set_payloadhash(m_payloadHash.data(), bcos::crypto::HashType::SIZE);
    }

    size_t signatureProofSize() const override { return m_mvbaRawProposal->signaturelist_size(); }

    std::pair<int64_t, bytesConstRef> signatureProof(size_t _index) const override
    {
        auto const& signatureData = m_mvbaRawProposal->signaturelist(_index);
        auto signatureDataRef =
            bytesConstRef((byte const*)signatureData.c_str(), signatureData.size());
        return std::make_pair(m_mvbaRawProposal->nodelist(_index), signatureDataRef);
    }

    void appendSignatureProof(int64_t _nodeIdx, bytesConstRef _signatureData) override
    {
        m_mvbaRawProposal->add_nodelist(_nodeIdx);
        m_mvbaRawProposal->add_signaturelist(_signatureData.data(), _signatureData.size());
    }

    void clearSignatureProof() override
    {
        m_mvbaRawProposal->clear_nodelist();
        m_mvbaRawProposal->clear_signaturelist();
    }

    bool operator==(MVBAProposal const& _proposal) const
    {
        if (index() != _proposal.index() || 
            round() != _proposal.round() ||
            sealerId() != _proposal.sealerId() ||
            payloadHash() != _proposal.payloadHash())
        {
            return false;
        }
        
        // check the signatureProof
        if (_proposal.signatureProofSize() != signatureProofSize())
        {
            return false;
        }
        size_t proofSize = signatureProofSize();
        for (size_t i = 0; i < proofSize; i++)
        {
            auto proof = _proposal.signatureProof(i);
            auto comparedProof = signatureProof(i);
            if (proof.first != comparedProof.first ||
                proof.second.toBytes() != comparedProof.second.toBytes())
            {
                return false;
            }
        }
        return true;
    }

    bool operator!=(MVBAProposal const& _proposal) const { return !(operator==(_proposal)); }

    bytesPointer encode() const override
    {
        return bcos::protocol::encodePBObject(m_mvbaRawProposal);
    }

    void decode(bytesConstRef _data) override
    {
        bcos::protocol::decodePBObject(m_mvbaRawProposal, _data);
        deserializeToObject();
    }

protected:
    virtual void deserializeToObject()
    {
        // deserialize mvbaInput
        if (m_mvbaRawProposal->has_mvbainput())
        {
            auto rawEquivocationProof = std::make_shared<RawEquivocationProof>();
    
            rawEquivocationProof->CopyFrom(m_mvbaRawProposal->mvbainput());
            m_mvbaInput = std::make_shared<EquivocationProof>(rawEquivocationProof);

            //auto rawEquivocationProof = std::make_shared<RawEquivocationProof>(
            //    m_mvbaRawProposal->mutable_mvbainput());
            //m_mvbaInput = std::make_shared<EquivocationProof>(rawEquivocationProof);
        }

        // deserialize payloadHash
        auto const& payloadHashData = m_mvbaRawProposal->payloadhash();
        if (payloadHashData.size() >= bcos::crypto::HashType::SIZE)
        {
            m_payloadHash = bcos::crypto::HashType(
                (byte const*)payloadHashData.c_str(), bcos::crypto::HashType::SIZE);
        }
    }

private:
    std::shared_ptr<MVBARawProposal> m_mvbaRawProposal;
    bcos::crypto::HashType m_payloadHash;
    EquivocationProofInterface::Ptr m_mvbaInput;
};
}  // namespace consensus
}  // namespace bcos