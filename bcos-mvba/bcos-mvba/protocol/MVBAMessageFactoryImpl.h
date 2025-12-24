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
 * @brief implementation for MVBAMessageFactory
 * @file MVBAMessageFactoryImpl.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/MVBAMessageFactory.h"
#include "MVBAMessage.h"
#include "MVBAProposal.h"
#include "MVBAEcho.h"

namespace bcos
{
namespace consensus
{
class MVBAMessageFactoryImpl : public MVBAMessageFactory
{
public:
    using Ptr = std::shared_ptr<MVBAMessageFactoryImpl>;
    MVBAMessageFactoryImpl() = default;
    ~MVBAMessageFactoryImpl() override {}

    // 创建基础消息对象
    MVBAMessageInterface::Ptr createMVBAMsg() override 
    { 
        return std::make_shared<MVBAMessage>(); 
    }

    MVBAMessageInterface::Ptr createMVBAMsg(
        bcos::crypto::CryptoSuite::Ptr _cryptoSuite, bytesConstRef _data) override
    {
        return std::make_shared<MVBAMessage>(_cryptoSuite, _data);
    }

    // 创建MVBA提案对象
    MVBAProposalInterface::Ptr createMVBAProposal() override
    {
        return std::make_shared<MVBAProposal>();
    }

    MVBAProposalInterface::Ptr createMVBAProposal(bytesConstRef _data) override
    {
        return std::make_shared<MVBAProposal>(_data);
    }

    // 创建MVBA Echo对象
    MVBAEchoInterface::Ptr createMVBAEcho() override
    {
        return std::make_shared<MVBAEcho>();
    }

    MVBAEchoInterface::Ptr createMVBAEcho(bytesConstRef _data) override
    {
        return std::make_shared<MVBAEcho>(_data);
    }
};
}  // namespace consensus
}  // namespace bcos