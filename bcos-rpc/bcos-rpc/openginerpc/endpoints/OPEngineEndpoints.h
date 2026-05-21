/**
 *  Copyright (C) 2026 FISCO BCOS.
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
 * @file OPEngineEndpoints.h
 * @date 2026/5/20
 */

#pragma once

#include "../model/ForkchoiceUpdatedV3.h"
#include "../model/GetPayloadV3.h"
#include "../model/NewPayloadV3.h"
#include "bcos-rpc/groupmgr/NodeService.h"
#include "bcos-task/Task.h"
#include <atomic>
#include <cstdint>
#include <json/json.h>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace bcos::rpc
{
class OPEngineEndpoints
{
public:
    explicit OPEngineEndpoints(NodeService::Ptr _nodeService);
    virtual ~OPEngineEndpoints() = default;

    task::Task<void> exchangeCapabilities(const Json::Value&, Json::Value&);
    task::Task<void> forkchoiceUpdatedV1(const Json::Value&, Json::Value&);
    task::Task<void> forkchoiceUpdatedV2(const Json::Value&, Json::Value&);
    task::Task<void> forkchoiceUpdatedV3(const Json::Value&, Json::Value&);
    task::Task<void> getPayloadV1(const Json::Value&, Json::Value&);
    task::Task<void> getPayloadV2(const Json::Value&, Json::Value&);
    task::Task<void> getPayloadV3(const Json::Value&, Json::Value&);
    task::Task<void> newPayloadV1(const Json::Value&, Json::Value&);
    task::Task<void> newPayloadV2(const Json::Value&, Json::Value&);
    task::Task<void> newPayloadV3(const Json::Value&, Json::Value&);

private:
    task::Task<void> handleForkchoiceUpdated(
        std::uint32_t _version, const Json::Value& _request, Json::Value& _response);
    task::Task<void> handleGetPayload(
        std::uint32_t _version, const Json::Value& _request, Json::Value& _response);
    task::Task<void> handleNewPayload(
        std::uint32_t _version, const Json::Value& _request, Json::Value& _response);

    struct MockPayloadRecord
    {
        std::string payloadId;
        std::string blockHash;
        GetPayloadV3Response payloadResponse;
    };

    [[nodiscard]] std::string generateMockPayloadId();
    [[nodiscard]] MockPayloadRecord buildMockPayloadRecord(
        std::string const& _payloadId, ForkchoiceUpdatedV3Request const& _request);
    [[nodiscard]] std::optional<MockPayloadRecord> findMockPayloadRecord(
        std::string const& _payloadId);
    void storeMockPayloadRecord(MockPayloadRecord _record);

private:
    NodeService::Ptr m_nodeService;
    std::atomic_uint64_t m_mockSequence{0};
    std::mutex x_mockPayloads;
    std::unordered_map<std::string, MockPayloadRecord> m_mockPayloads;
};
}  // namespace bcos::rpc
