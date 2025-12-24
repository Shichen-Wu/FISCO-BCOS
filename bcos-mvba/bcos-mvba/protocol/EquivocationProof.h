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
 * @brief implementation of EquivocationProof
 * @file EquivocationProof.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include "../interfaces/EquivocationProofInterface.h"
#include "bcos-mvba/protocol/MVBA.pb.h"
#include <bcos-protocol/Common.h>

namespace bcos::consensus
{
class EquivocationProof : virtual public EquivocationProofInterface
{
public:
    using Ptr = std::shared_ptr<EquivocationProof>;
    EquivocationProof() : m_rawEquivocationProof(std::make_shared<RawEquivocationProof>()) {}
    explicit EquivocationProof(bytesConstRef _data) : EquivocationProof() { decode(_data); }
    explicit EquivocationProof(std::shared_ptr<RawEquivocationProof> _rawEquivocationProof) 
        : m_rawEquivocationProof(_rawEquivocationProof)
    {
        deserializeObject();
    }
    ~EquivocationProof() override = default;

    // version
    int32_t version() const override { return m_rawEquivocationProof->version(); }
    void setVersion(int32_t _version) override { m_rawEquivocationProof->set_version(_version); }

    // malicious node indexes
    std::vector<int64_t> const& maliciousNodeIndexes() const override { return m_maliciousNodeIndexes; }
    void setMaliciousNodeIndexes(std::vector<int64_t> const& _indexes) override
    {
        m_maliciousNodeIndexes = _indexes;
        m_rawEquivocationProof->clear_maliciousnodeindexes();
        for (auto index : _indexes)
        {
            m_rawEquivocationProof->add_maliciousnodeindexes(index);
        }
    }
    void addMaliciousNodeIndex(int64_t _index) override
    {
        m_maliciousNodeIndexes.push_back(_index);
        m_rawEquivocationProof->add_maliciousnodeindexes(_index);
    }

    // main chain signatures
    std::vector<bytes> const& mainChainSignatures() const override { return m_mainChainSignatures; }
    void setMainChainSignatures(std::vector<bytes> const& _signatures) override
    {
        m_mainChainSignatures = _signatures;
        m_rawEquivocationProof->clear_mainchainsignatures();
        for (auto const& sig : _signatures)
        {
            m_rawEquivocationProof->add_mainchainsignatures(sig.data(), sig.size());
        }
    }
    void addMainChainSignature(bytes const& _signature) override
    {
        m_mainChainSignatures.push_back(_signature);
        m_rawEquivocationProof->add_mainchainsignatures(_signature.data(), _signature.size());
    }

    // conflict signatures
    std::vector<bytes> const& conflictSignatures() const override { return m_conflictSignatures; }
    void setConflictSignatures(std::vector<bytes> const& _signatures) override
    {
        m_conflictSignatures = _signatures;
        m_rawEquivocationProof->clear_conflictsignatures();
        for (auto const& sig : _signatures)
        {
            m_rawEquivocationProof->add_conflictsignatures(sig.data(), sig.size());
        }
    }
    void addConflictSignature(bytes const& _signature) override
    {
        m_conflictSignatures.push_back(_signature);
        m_rawEquivocationProof->add_conflictsignatures(_signature.data(), _signature.size());
    }

    // conflict block number
    int64_t conflictBlockNumber() const override { return m_rawEquivocationProof->conflictblocknumber(); }
    void setConflictBlockNumber(int64_t _blockNumber) override 
    { 
        m_rawEquivocationProof->set_conflictblocknumber(_blockNumber); 
    }

    // rollback block number
    int64_t rollbackBlockNumber() const override { return m_rawEquivocationProof->rollbackblocknumber(); }
    void setRollbackBlockNumber(int64_t _blockNumber) override 
    { 
        m_rawEquivocationProof->set_rollbackblocknumber(_blockNumber); 
    }

    // sequential epoch
    int64_t sequentialEpoch() const override { return m_rawEquivocationProof->sequentialepoch(); }
    void setSequentialEpoch(int64_t _epoch) override 
    { 
        m_rawEquivocationProof->set_sequentialepoch(_epoch); 
    }

    // additional data
    bcos::bytesConstRef additionalData() const override
    {
        auto const& data = m_rawEquivocationProof->additionaldata();
        return bcos::bytesConstRef((byte const*)data.c_str(), data.size());
    }
    void setAdditionalData(bytes const& _data) override
    {
        m_rawEquivocationProof->set_additionaldata(_data.data(), _data.size());
    }
    void setAdditionalData(bytes&& _data) override
    {
        auto size = _data.size();
        m_rawEquivocationProof->set_additionaldata(std::move(_data).data(), size);
    }
    void setAdditionalData(bcos::bytesConstRef _data) override
    {
        m_rawEquivocationProof->set_additionaldata(_data.data(), _data.size());
    }

    bool operator==(EquivocationProof const& _proof) const
    {
        return _proof.version() == version() && 
               _proof.conflictBlockNumber() == conflictBlockNumber() &&
               _proof.rollbackBlockNumber() == rollbackBlockNumber() &&
               _proof.sequentialEpoch() == sequentialEpoch() &&
               _proof.maliciousNodeIndexes() == maliciousNodeIndexes();
    }
    bool operator!=(EquivocationProof const& _proof) const { return !(operator==(_proof)); }

    std::shared_ptr<RawEquivocationProof> rawEquivocationProof() { return m_rawEquivocationProof; }

    bytesPointer encode() const override { return bcos::protocol::encodePBObject(m_rawEquivocationProof); }
    void decode(bytesConstRef _data) override
    {
        bcos::protocol::decodePBObject(m_rawEquivocationProof, _data);
        deserializeObject();
    }

protected:
    void setRawEquivocationProof(std::shared_ptr<RawEquivocationProof> _rawEquivocationProof)
    {
        m_rawEquivocationProof = _rawEquivocationProof;
        deserializeObject();
    }
    
    virtual void deserializeObject()
    {
        // deserialize malicious node indexes
        m_maliciousNodeIndexes.clear();
        for (int i = 0; i < m_rawEquivocationProof->maliciousnodeindexes_size(); ++i)
        {
            m_maliciousNodeIndexes.push_back(m_rawEquivocationProof->maliciousnodeindexes(i));
        }

        // deserialize main chain signatures
        m_mainChainSignatures.clear();
        for (int i = 0; i < m_rawEquivocationProof->mainchainsignatures_size(); ++i)
        {
            auto const& sig = m_rawEquivocationProof->mainchainsignatures(i);
            m_mainChainSignatures.emplace_back(sig.begin(), sig.end());
        }

        // deserialize conflict signatures
        m_conflictSignatures.clear();
        for (int i = 0; i < m_rawEquivocationProof->conflictsignatures_size(); ++i)
        {
            auto const& sig = m_rawEquivocationProof->conflictsignatures(i);
            m_conflictSignatures.emplace_back(sig.begin(), sig.end());
        }
    }

protected:
    std::shared_ptr<RawEquivocationProof> m_rawEquivocationProof;
    std::vector<int64_t> m_maliciousNodeIndexes;
    std::vector<bytes> m_mainChainSignatures;
    std::vector<bytes> m_conflictSignatures;
};
}  // namespace bcos::consensus