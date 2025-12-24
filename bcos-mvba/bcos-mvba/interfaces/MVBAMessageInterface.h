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
 * @brief interface for MVBA Message
 * @file MVBAMessageInterface.h
 * @author: yujiechen
 * @date 2021-04-13
 */
#pragma once
#include "MVBABaseMessageInterface.h"
#include "MVBAProposalInterface.h"
#include "MVBAEchoInterface.h"

namespace bcos
{
namespace consensus
{
class MVBAMessageInterface : virtual public MVBABaseMessageInterface
{
public:
    using Ptr = std::shared_ptr<MVBAMessageInterface>;
    MVBAMessageInterface() = default;
    virtual ~MVBAMessageInterface() {}

    virtual void setMvbaProposal(MVBAProposalInterface::Ptr _mvbaProposal) = 0;
    virtual MVBAProposalInterface::Ptr mvbaProposal() = 0;

    virtual void setMvbaEcho(MVBAEchoInterface::Ptr _mvbaEcho) = 0;
    virtual MVBAEchoInterface::Ptr mvbaEcho() = 0;

    virtual void setProposals(MVBAProposalList const& _proposals) = 0;
    virtual MVBAProposalList const& proposals() const = 0;

    virtual MVBAMessageInterface::Ptr populateWithoutInput() = 0;
};
using MVBAMessageList = std::vector<MVBAMessageInterface::Ptr>;
using MVBAMessageListPtr = std::shared_ptr<MVBAMessageList>;
}  // namespace consensus
}  // namespace bcos