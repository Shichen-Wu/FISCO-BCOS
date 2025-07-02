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
 * @brief interface for MVBAEcho
 * @file MVBAEchoInterface.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../utilities/Common.h"
#include <bcos-crypto/interfaces/crypto/CommonType.h>
#include <bcos-utilities/Common.h>

namespace bcos
{
namespace consensus
{
class MVBAEchoInterface
{
public:
    using Ptr = std::shared_ptr<MVBAEchoInterface>;
    MVBAEchoInterface() = default;
    virtual ~MVBAEchoInterface() = default;

    virtual bytesPointer encode() const = 0;
    virtual void decode(bytesConstRef _data) = 0;

    virtual int64_t index() const = 0;
    virtual void setIndex(int64_t _index) = 0;

    virtual int32_t round() const = 0;
    virtual void setRound(int32_t _round) = 0;

    virtual int64_t sealerId() const = 0;
    virtual void setSealerId(int64_t _sealerId) = 0;

    virtual bcos::crypto::HashType const& payloadHash() const = 0;
    virtual void setPayloadHash(bcos::crypto::HashType const& _payloadHash) = 0;
};

template <typename T>
inline std::string printMVBAEcho(T _rep)
{
    std::ostringstream stringstream;
    stringstream << LOG_KV("repIndex", _rep->index())
                 << LOG_KV("round", _rep->round())
                 << LOG_KV("sealerId", _rep->sealerId())
                 << LOG_KV("payloadHash", _rep->payloadHash().abridged());
    return stringstream.str();
}
}  // namespace consensus
}  // namespace bcos