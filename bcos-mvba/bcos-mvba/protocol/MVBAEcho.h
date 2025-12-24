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
 * @brief implementation for MVBAEcho
 * @file MVBAEcho.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/MVBAEchoInterface.h"
#include "bcos-mvba/protocol/MVBA.pb.h"
#include <bcos-protocol/Common.h>

namespace bcos
{
namespace consensus
{
class MVBAEcho : public MVBAEchoInterface
{
public:
    using Ptr = std::shared_ptr<MVBAEcho>;
    MVBAEcho()
    {
        m_MVBARawEcho = std::make_shared<::bcos::consensus::MVBARawEcho>();
    }
    explicit MVBAEcho(bytesConstRef _data)
    {
        m_MVBARawEcho = std::make_shared<::bcos::consensus::MVBARawEcho>();
        decode(_data);
    }
    explicit MVBAEcho(std::shared_ptr<::bcos::consensus::MVBARawEcho> _MVBARawEcho)
      : m_MVBARawEcho(_MVBARawEcho)
    {
        deserializeToObject();
    }

    ~MVBAEcho() override = default;

    std::shared_ptr<::bcos::consensus::MVBARawEcho> MVBARawEcho() { return m_MVBARawEcho; }

    // MVBARawEchoInterface implementation
    int64_t index() const override { return m_MVBARawEcho->index(); }
    void setIndex(int64_t _index) override { m_MVBARawEcho->set_index(_index); }

    int32_t round() const override { return m_MVBARawEcho->round(); }
    void setRound(int32_t _round) override { m_MVBARawEcho->set_round(_round); }

    int64_t sealerId() const override { return m_MVBARawEcho->sealerid(); }
    void setSealerId(int64_t _sealerId) override { m_MVBARawEcho->set_sealerid(_sealerId); }

    bcos::crypto::HashType const& payloadHash() const override { return m_payloadHash; }
    void setPayloadHash(bcos::crypto::HashType const& _payloadHash) override
    {
        m_payloadHash = _payloadHash;
        m_MVBARawEcho->set_payloadhash(m_payloadHash.data(), bcos::crypto::HashType::SIZE);
    }

    bool operator==(MVBAEcho const& _rep) const
    {
        return (index() == _rep.index()) && 
               (round() == _rep.round()) &&
               (sealerId() == _rep.sealerId()) &&
               (payloadHash() == _rep.payloadHash());
    }

    bool operator!=(MVBAEcho const& _rep) const { return !(operator==(_rep)); }

    bytesPointer encode() const override
    {
        return bcos::protocol::encodePBObject(m_MVBARawEcho);
    }

    void decode(bytesConstRef _data) override
    {
        bcos::protocol::decodePBObject(m_MVBARawEcho, _data);
        deserializeToObject();
    }

protected:
    virtual void deserializeToObject()
    {
        // deserialize payloadHash
        auto const& payloadHashData = m_MVBARawEcho->payloadhash();
        if (payloadHashData.size() >= bcos::crypto::HashType::SIZE)
        {
            m_payloadHash = bcos::crypto::HashType(
                (byte const*)payloadHashData.c_str(), bcos::crypto::HashType::SIZE);
        }
    }

private:
    std::shared_ptr<::bcos::consensus::MVBARawEcho> m_MVBARawEcho;
    bcos::crypto::HashType m_payloadHash;
};
}  // namespace consensus
}  // namespace bcos