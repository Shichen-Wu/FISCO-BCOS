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
 * @brief interface for MVBAProposal
 * @file MVBAProposalInterface.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/EquivocationProofInterface.h"
#include "../utilities/Common.h"
#include <bcos-crypto/interfaces/crypto/CommonType.h>
#include <bcos-utilities/Common.h>

namespace bcos
{
namespace consensus
{
class MVBAProposalInterface
{
public:
    using Ptr = std::shared_ptr<MVBAProposalInterface>;
    MVBAProposalInterface() = default;
    virtual ~MVBAProposalInterface() = default;

    virtual bytesPointer encode() const = 0;
    virtual void decode(bytesConstRef _data) = 0;

    virtual int64_t index() const = 0;
    virtual void setIndex(int64_t _index) = 0;

    virtual int32_t round() const = 0;
    virtual void setRound(int32_t _round) = 0;

    virtual int64_t sealerId() const = 0;
    virtual void setSealerId(int64_t _sealerId) = 0;

    virtual EquivocationProofInterface::Ptr mvbaInput() const = 0;
    virtual void setMvbaInput(EquivocationProofInterface::Ptr _mvbaInput) = 0;

    virtual bcos::crypto::HashType const& payloadHash() const = 0;
    virtual void setPayloadHash(bcos::crypto::HashType const& _payloadHash) = 0;

    virtual size_t signatureProofSize() const = 0;
    virtual std::pair<int64_t, bytesConstRef> signatureProof(size_t _index) const = 0;
    virtual void appendSignatureProof(int64_t _nodeIdx, bytesConstRef _signatureData) = 0;
    virtual void clearSignatureProof() = 0;
};
using MVBAProposalList = std::vector<MVBAProposalInterface::Ptr>;
using MVBAProposalListPtr = std::shared_ptr<MVBAProposalList>;

template <typename T>
inline std::string printMVBAProposal(T _proposal)
{
    std::ostringstream stringstream;
    stringstream << LOG_KV("propIndex", _proposal->index())
                 << LOG_KV("round", _proposal->round())
                 << LOG_KV("sealerId", _proposal->sealerId())
                 << LOG_KV("payloadHash", _proposal->payloadHash().abridged());
    return stringstream.str();
}
}  // namespace consensus
}  // namespace bcos