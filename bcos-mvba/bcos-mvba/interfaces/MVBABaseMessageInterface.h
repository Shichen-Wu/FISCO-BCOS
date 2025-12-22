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
 * @brief interface for MVBABaseMessage
 * @file MVBABaseMessageInterface.h
 * @author: your_name
 * @date 2024-01-01
 */
#pragma once
#include "../utilities/Common.h"
#include <bcos-crypto/interfaces/crypto/CommonType.h>
#include <bcos-crypto/interfaces/crypto/CryptoSuite.h>
#include <bcos-crypto/interfaces/crypto/KeyPairInterface.h>
#include <bcos-framework/consensus/ConsensusTypeDef.h>
#include <memory>

namespace bcos::consensus {
  class MVBABaseMessageInterface {
public:
    using Ptr = std::shared_ptr<MVBABaseMessageInterface>;
    MVBABaseMessageInterface() = default;
    virtual ~MVBABaseMessageInterface() = default;

    // 基础消息字段
    virtual int64_t timestamp() const = 0;
    virtual int32_t version() const = 0;
    virtual ViewType view() const = 0;
    virtual IndexType generatedFrom() const = 0;
    virtual uint64_t index() const = 0;
    virtual void setIndex(int64_t _index) = 0;

    virtual bcos::crypto::HashType const &hash() const = 0;
    virtual MVBAPacketType packetType() const = 0;

    virtual void setTimestamp(int64_t _timestamp) = 0;
    virtual void setVersion(int32_t _version) = 0;
    virtual void setView(ViewType _view) = 0;
    virtual void setGeneratedFrom(IndexType _generatedFrom) = 0;
    virtual void setHash(bcos::crypto::HashType const &_hash) = 0;
    virtual void setPacketType(MVBAPacketType _packetType) = 0;

    // MVBA特有字段
    virtual int32_t round() const = 0;
    virtual void setRound(int32_t _round) = 0;

    virtual int64_t sealerId() const = 0;
    virtual void setSealerId(int64_t _sealerId) = 0;

    // 序列化和反序列化
    virtual bytesPointer
    encode(bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
           bcos::crypto::KeyPairInterface::Ptr _keyPair) const = 0;
    virtual void decode(bytesConstRef _data) = 0;

    // 签名相关
    virtual bytesConstRef signatureData() = 0;
    virtual bcos::crypto::HashType const &signatureDataHash() = 0;

    virtual void setSignatureData(bytes &&_signatureData) = 0;
    virtual void setSignatureData(bytes const &_signatureData) = 0;
    virtual void setSignatureDataHash(bcos::crypto::HashType const &_hash) = 0;
    virtual bool verifySignature(bcos::crypto::CryptoSuite::Ptr _cryptoSuite,
                                 bcos::crypto::PublicPtr _pubKey) = 0;

    // 发送方信息
    virtual void setFrom(bcos::crypto::PublicPtr _from) = 0;
    virtual bcos::crypto::PublicPtr from() const = 0;
    virtual uint64_t liveTimeInMilliseconds() const = 0;
    virtual std::string toDebugString() const = 0;
  };

  inline std::string printMVBAMsgInfo(MVBABaseMessageInterface::Ptr _mvbaMsg) {
    std::ostringstream stringstream;
    stringstream << LOG_KV("reqHash", _mvbaMsg->hash().abridged())
                 << LOG_KV("reqIndex", _mvbaMsg->index())
                 << LOG_KV("reqV", _mvbaMsg->view())
                 << LOG_KV("reqRound", _mvbaMsg->round())
                 << LOG_KV("fromIdx", _mvbaMsg->generatedFrom())
                 << LOG_KV("sealerId", _mvbaMsg->sealerId())
                 << LOG_KV("wait(ms)", _mvbaMsg->liveTimeInMilliseconds());
    if (c_fileLogLevel <= DEBUG) {
      stringstream << _mvbaMsg->toDebugString();
    }
    return stringstream.str();
  }
} // namespace bcos::consensus