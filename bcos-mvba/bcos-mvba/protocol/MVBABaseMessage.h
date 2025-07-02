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
 * @brief PB implementation for MVBABaseMessage
 * @file MVBABaseMessage.h
 * @author: your_name
 * @date 2024-01-01
 */
#pragma once
#include "../interfaces/MVBABaseMessageInterface.h"
#include "bcos-mvba/protocol/MVBA.pb.h"
#include "bcos-utilities/Common.h"
#include <bcos-protocol/Common.h>

namespace bcos
{
namespace consensus
{
class MVBABaseMessage : virtual public MVBABaseMessageInterface
{
public:
    using Ptr = std::shared_ptr<MVBABaseMessage>;
    MVBABaseMessage()
      : m_baseMessage(std::make_shared<MVBARawBaseMessage>()),
        m_signatureData(std::make_shared<bytes>()),
        m_createTime(bcos::utcTime())
    {}

    explicit MVBABaseMessage(std::shared_ptr<MVBARawBaseMessage> _baseMessage)
      : m_baseMessage(std::move(_baseMessage)),
        m_signatureData(std::make_shared<bytes>()),
        m_createTime(bcos::utcTime())
    {
        MVBABaseMessage::deserializeToObject();
    }

    ~MVBABaseMessage() override {}

    // 基础消息字段实现
    int64_t timestamp() const override { return m_baseMessage->timestamp(); }
    int32_t version() const override { return m_baseMessage->version(); }
    ViewType view() const override { return m_baseMessage->view(); }
    IndexType generatedFrom() const override { return m_baseMessage->generatedfrom(); }
    bcos::crypto::HashType const& hash() const override { return m_hash; }

    void setTimestamp(int64_t _timestamp) override { m_baseMessage->set_timestamp(_timestamp); }
    void setVersion(int32_t _version) override { m_baseMessage->set_version(_version); }
    void setView(ViewType _view) override { m_baseMessage->set_view(_view); }
    void setGeneratedFrom(IndexType _generatedFrom) override
    {
        m_baseMessage->set_generatedfrom(_generatedFrom);
    }

    void setHash(bcos::crypto::HashType const& _hash) override
    {
        m_hash = _hash;
        m_baseMessage->set_hash(m_hash.data(), bcos::crypto::HashType::SIZE);
    }

    MVBAPacketType packetType() const override { return m_packetType; }
    void setPacketType(MVBAPacketType _packetType) override { m_packetType = _packetType; }

    // MVBA特有字段实现
    int32_t round() const override { return m_round; }
    void setRound(int32_t _round) override { m_round = _round; }
    
    int64_t sealerId() const override { return m_sealerId; }
    void setSealerId(int64_t _sealerId) override { m_sealerId = _sealerId; }

    // 序列化和反序列化
    bytesPointer encode(
        bcos::crypto::CryptoSuite::Ptr, bcos::crypto::KeyPairInterface::Ptr) const override
    {
        return bcos::protocol::encodePBObject(m_baseMessage);
    }

    bytesPointer encode() const { return bcos::protocol::encodePBObject(m_baseMessage); }

    void decode(bytesConstRef _data) override
    {
        bcos::protocol::decodePBObject(m_baseMessage, _data);
        MVBABaseMessage::deserializeToObject();
    }

    // 签名相关实现
    bytesConstRef signatureData() override
    {
        auto const& signatureData = m_baseMessage->signaturedata();
        return bytesConstRef((byte const*)signatureData.data(), signatureData.size());
    }

    bcos::crypto::HashType const& signatureDataHash() override { return m_dataHash; }
    
    void setSignatureData(bytes&& _signatureData) override
    {
        auto size = _signatureData.size();
        m_baseMessage->set_signaturedata((std::move(_signatureData)).data(), size);
    }
    
    void setSignatureData(bytes const& _signatureData) override
    {
        m_baseMessage->set_signaturedata(_signatureData.data(), _signatureData.size());
    }
    
    void setSignatureDataHash(bcos::crypto::HashType const& _hash) override
    {
        m_dataHash = _hash;
        m_baseMessage->set_signaturehash(_hash.data(), bcos::crypto::HashType::SIZE);
    }
    
    bool verifySignature(
        bcos::crypto::CryptoSuite::Ptr _cryptoSuite, bcos::crypto::PublicPtr _pubKey) override
    {
        return _cryptoSuite->signatureImpl()->verify(_pubKey, signatureDataHash(), signatureData());
    }

    int64_t index() const override { return m_baseMessage->index(); }
    void setIndex(int64_t _index) override { m_baseMessage->set_index(_index); }

    bool operator==(MVBABaseMessage const& _mvbaMessage) const
    {
        return (timestamp() == _mvbaMessage.timestamp()) && 
               (version() == _mvbaMessage.version()) &&
               (generatedFrom() == _mvbaMessage.generatedFrom()) &&
               (view() == _mvbaMessage.view()) && 
               (hash() == _mvbaMessage.hash()) &&
               (round() == _mvbaMessage.round()) &&
               (sealerId() == _mvbaMessage.sealerId());
    }

    void setFrom(bcos::crypto::PublicPtr _from) override { m_from = _from; }
    bcos::crypto::PublicPtr from() const override { return m_from; }
    uint64_t liveTimeInMilliseconds() const override { return bcos::utcTime() - m_createTime; }
    
    std::string toDebugString() const override
    {
        std::stringstream stringstream;
        stringstream << LOG_KV("type", m_packetType)
                     << LOG_KV("round", m_round)
                     << LOG_KV("sealerId", m_sealerId)
                     << LOG_KV("fromNode", m_from ? m_from->shortHex() : "null");
        return stringstream.str();
    }

protected:
    virtual void deserializeToObject()
    {
        auto const& hashData = m_baseMessage->hash();
        if (hashData.size() >= bcos::crypto::HashType::SIZE)
        {
            m_hash =
                bcos::crypto::HashType((byte const*)hashData.c_str(), bcos::crypto::HashType::SIZE);
        }

        auto const& signatureDataHash = m_baseMessage->signaturehash();
        if (signatureDataHash.size() >= bcos::crypto::HashType::SIZE)
        {
            m_dataHash = bcos::crypto::HashType(
                (byte const*)signatureDataHash.c_str(), bcos::crypto::HashType::SIZE);
        }
    }

    std::shared_ptr<MVBARawBaseMessage> baseMessage() { return m_baseMessage; }
    void setBaseMessage(std::shared_ptr<MVBARawBaseMessage> _baseMessage) { m_baseMessage = _baseMessage; }

    std::shared_ptr<MVBARawBaseMessage> m_baseMessage;
    bcos::crypto::HashType m_hash;
    MVBAPacketType m_packetType = MVBAPacketType::ActivePacket;

    bcos::crypto::HashType m_dataHash;
    bytesPointer m_signatureData;

    bcos::crypto::PublicPtr m_from;
    uint64_t m_createTime = 0;

    // MVBA特有字段
    int32_t m_round = 0;
    int64_t m_sealerId = 0;
};
}  // namespace consensus
}  // namespace bcos