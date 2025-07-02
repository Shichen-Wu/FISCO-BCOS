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
 * @file MVBACodec.cpp
 * @author: yujiechen
 * @date 2024-12-15
 */
#include "MVBACodec.h"
#include "bcos-mvba/protocol/MVBA.pb.h"
#include <bcos-protocol/Common.h>

using namespace bcos;
using namespace bcos::consensus;
using namespace bcos::crypto;

bytesPointer MVBACodec::encode(MVBABaseMessageInterface::Ptr _mvbaMessage, int32_t _version) const
{
    auto pbMessage = std::make_shared<RawMessageMVBA>(); //TODO：暂时标记，后续统一RawMessage

    // set packetType
    auto packetType = _mvbaMessage->packetType();
    pbMessage->set_type((int32_t)packetType);
    bytesPointer payLoad = {};
    
    // set payLoad
    {
        payLoad = _mvbaMessage->encode(m_cryptoSuite, m_keyPair);
    }
    pbMessage->set_payload(payLoad->data(), payLoad->size());

    // set signature
    if (shouldHandleSignature(packetType))
    {
        // get hash of the payLoad
        auto hash = m_cryptoSuite->hashImpl()->hash(*payLoad);
        // sign for the payload
        auto signatureData = m_cryptoSuite->signatureImpl()->sign(*m_keyPair, hash, false);
        pbMessage->set_signaturedata(signatureData->data(), signatureData->size());
        {
            _mvbaMessage->setSignatureDataHash(hash);
            _mvbaMessage->setSignatureData(*signatureData);
        }
    }
    
    // set version
    pbMessage->set_version(_version);
    return bcos::protocol::encodePBObject(pbMessage);
}

MVBABaseMessageInterface::Ptr MVBACodec::decode(bytesConstRef _data) const
{
    auto pbMessage = std::make_shared<RawMessageMVBA>(); //TODO：暂时标记，后续统一RawMessage
    bcos::protocol::decodePBObject(pbMessage, _data);
    
    // get packetType
    MVBAPacketType packetType = (MVBAPacketType)(pbMessage->type());
    
    // get payLoad
    auto const& payLoad = pbMessage->payload();
    auto payLoadRefData = bytesConstRef((byte const*)payLoad.c_str(), payLoad.size());
    
    // decode the packet according to the packetType
    MVBABaseMessageInterface::Ptr decodedMsg = nullptr;
    
    switch (packetType)
    {
    case MVBAPacketType::ActivePacket:
    case MVBAPacketType::LockPacket:
    case MVBAPacketType::FinishPacket:
    case MVBAPacketType::NotifyFinishedPacket:
        // 这些消息类型包含MVBA提案
        decodedMsg = m_mvbaMessageFactory->createMVBAMsg(m_cryptoSuite, payLoadRefData);
        break;
    case MVBAPacketType::ActiveEchoPacket:
    case MVBAPacketType::LockEchoPacket:
    case MVBAPacketType::PrevotePacket:
    case MVBAPacketType::VotePacket:
        // 这些消息类型包含MVBA响应/投票
        decodedMsg = m_mvbaMessageFactory->createMVBAMsg(m_cryptoSuite, payLoadRefData);
        break;
    default:
        BOOST_THROW_EXCEPTION(UnknownMVBAMsgType() << errinfo_comment(
                                  "unknown mvba packetType: " + std::to_string(packetType)));
    }
    
    if (shouldHandleSignature(packetType))
    {
        // set signature data for the message
        auto hash = m_cryptoSuite->hashImpl()->hash(payLoadRefData);
        decodedMsg->setSignatureDataHash(hash);

        auto const& signatureData = pbMessage->signaturedata();
        bytes signatureBytes(signatureData.begin(), signatureData.end());
        decodedMsg->setSignatureData(std::move(signatureBytes));
    }
    
    decodedMsg->setPacketType(packetType);
    return decodedMsg;
}


MVBAMessageInterface::Ptr MVBACodec::decodeToMVBAMessage(bytesConstRef _data) const
{
    auto baseMsg = decode(_data);
        
        // 向下转型为派生类指针
        auto derivedMsg = std::dynamic_pointer_cast<MVBAMessageInterface>(baseMsg);
        
        if (!derivedMsg) {
            BOOST_THROW_EXCEPTION(UnknownMVBAMsgType() << 
            errinfo_comment("Failed to cast to MVBAMessageInterface"));
        }
        
        return derivedMsg;
}


