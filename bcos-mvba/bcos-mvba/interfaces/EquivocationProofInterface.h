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
 * @brief the equivocation proof information interface
 * @file EquivocationProofInterface.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../protocol/ProtocolTypeDef.h"
#include <vector>

namespace bcos::consensus
{
class EquivocationProofInterface
{
public:
    using Ptr = std::shared_ptr<EquivocationProofInterface>;
    using ConstPtr = std::shared_ptr<EquivocationProofInterface const>;
    EquivocationProofInterface() = default;
    virtual ~EquivocationProofInterface() = default;

    virtual bytesPointer encode() const = 0;
    virtual void decode(bytesConstRef _data) = 0;

    // version
    virtual int32_t version() const = 0;
    virtual void setVersion(int32_t _version) = 0;

    // malicious node indexes
    virtual std::vector<int64_t> const& maliciousNodeIndexes() const = 0;
    virtual void setMaliciousNodeIndexes(std::vector<int64_t> const& _indexes) = 0;
    virtual void addMaliciousNodeIndex(int64_t _index) = 0;

    // main chain signatures
    virtual std::vector<bytes> const& mainChainSignatures() const = 0;
    virtual void setMainChainSignatures(std::vector<bytes> const& _signatures) = 0;
    virtual void addMainChainSignature(bytes const& _signature) = 0;

    // conflict signatures
    virtual std::vector<bytes> const& conflictSignatures() const = 0;
    virtual void setConflictSignatures(std::vector<bytes> const& _signatures) = 0;
    virtual void addConflictSignature(bytes const& _signature) = 0;

    // conflict block number
    virtual int64_t conflictBlockNumber() const = 0;
    virtual void setConflictBlockNumber(int64_t _blockNumber) = 0;

    // rollback block number
    virtual int64_t rollbackBlockNumber() const = 0;
    virtual void setRollbackBlockNumber(int64_t _blockNumber) = 0;

    // sequential epoch
    virtual int64_t sequentialEpoch() const = 0;
    virtual void setSequentialEpoch(int64_t _epoch) = 0;

    // additional data
    virtual bcos::bytesConstRef additionalData() const = 0;
    virtual void setAdditionalData(bytes const& _data) = 0;
    virtual void setAdditionalData(bytes&& _data) = 0;
    virtual void setAdditionalData(bcos::bytesConstRef _data) = 0;
};
}  // namespace bcos::consensus