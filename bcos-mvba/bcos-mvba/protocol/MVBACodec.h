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
 * @brief implementation for MVBACodec
 * @file MVBACodec.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/MVBACodecInterface.h"
#include "../interfaces/MVBAMessageFactory.h"
#include <bcos-crypto/interfaces/crypto/CryptoSuite.h>
#include <bcos-crypto/interfaces/crypto/KeyPairInterface.h>

namespace bcos::consensus
{
class MVBACodec : public MVBACodecInterface
{
public:
    using Ptr = std::shared_ptr<MVBACodec>;
    MVBACodec(bcos::crypto::KeyPairInterface::Ptr _keyPair,
        bcos::crypto::CryptoSuite::Ptr _cryptoSuite, MVBAMessageFactory::Ptr _mvbaMessageFactory)
      : m_keyPair(std::move(_keyPair)),
        m_cryptoSuite(std::move(_cryptoSuite)),
        m_mvbaMessageFactory(std::move(_mvbaMessageFactory))
    {}
    MVBACodec(MVBACodec const&) = delete;
    MVBACodec& operator=(MVBACodec const&) = delete;
    MVBACodec(MVBACodec&&) = delete;
    MVBACodec& operator=(MVBACodec&&) = delete;

    ~MVBACodec() override = default;

    bytesPointer encode(
        MVBABaseMessageInterface::Ptr _mvbaMessage, int32_t _version = 0) const override;

    MVBABaseMessageInterface::Ptr decode(bytesConstRef _data) const override;

    MVBAMessageInterface::Ptr decodeToMVBAMessage(bytesConstRef _data) const override;

protected:
    virtual bool shouldHandleSignature(MVBAPacketType _packetType) const
    {
        // 对于MVBA协议，所有消息类型都需要签名验证
        return (_packetType == MVBAPacketType::ActivePacket ||
                _packetType == MVBAPacketType::ActiveEchoPacket ||
                _packetType == MVBAPacketType::LockPacket ||
                _packetType == MVBAPacketType::LockEchoPacket ||
                _packetType == MVBAPacketType::FinishPacket ||
                _packetType == MVBAPacketType::PrevotePacket ||
                _packetType == MVBAPacketType::VotePacket ||
                _packetType == MVBAPacketType::NotifyFinishedPacket);
    }

private:
    bcos::crypto::KeyPairInterface::Ptr m_keyPair;
    bcos::crypto::CryptoSuite::Ptr m_cryptoSuite;
    MVBAMessageFactory::Ptr m_mvbaMessageFactory;
};
}  // namespace bcos::consensus