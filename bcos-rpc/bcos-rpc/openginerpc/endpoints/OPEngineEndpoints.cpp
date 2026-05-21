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
 * @file OPEngineEndpoints.cpp
 * @date 2026/5/20
 */

#include "OPEngineEndpoints.h"

#include "../Common.h"
#include "../model/EngineTypes.h"
#include <bcos-crypto/hash/Keccak256.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/DataConvertUtility.h>
#include <array>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace bcos::rpc
{
namespace
{
std::string fixedHex(std::size_t _hexSize, char _fill = '0')
{
    return "0x" + std::string(_hexSize, _fill);
}

std::string padQuantity(uint64_t _value, std::size_t _hexSize)
{
    std::stringstream stream;
    stream << std::hex << _value;
    auto out = stream.str();
    if (out.size() < _hexSize)
    {
        out = std::string(_hexSize - out.size(), '0') + out;
    }
    return "0x" + out;
}

std::string quantity(uint64_t _value)
{
    return bcos::toQuantity(_value);
}

std::string keccakHex(std::string const& _input)
{
    auto hash = bcos::crypto::keccak256Hash(bcos::bytesConstRef(
        reinterpret_cast<bcos::byte const*>(_input.data()), _input.size()));
    return hash.hexPrefixed();
}

std::string normalizeHash(std::string const& _candidate, std::string_view _fallbackSeed)
{
    if (_candidate.size() == 66 && _candidate.rfind("0x", 0) == 0)
    {
        return _candidate;
    }
    return keccakHex(std::string(_fallbackSeed));
}

std::string normalizeAddress(std::string const& _candidate, std::string_view _fallbackSeed)
{
    if (_candidate.size() == 42 && _candidate.rfind("0x", 0) == 0)
    {
        return _candidate;
    }
    auto hash = keccakHex(std::string(_fallbackSeed));
    return "0x" + hash.substr(hash.size() - 40);
}

std::string logsBloomZeros()
{
    return fixedHex(512, '0');
}

Withdrawal buildWithdrawal(uint64_t _index)
{
    Withdrawal withdrawal;
    withdrawal.index = quantity(_index);
    withdrawal.validatorIndex = quantity(_index);
    std::stringstream address;
    address << "0x" << std::setw(40) << std::setfill('0') << std::hex << (0x10f0 + _index);
    withdrawal.address = address.str();
    withdrawal.amount = quantity(1);
    return withdrawal;
}
}  // namespace

OPEngineEndpoints::OPEngineEndpoints(NodeService::Ptr _nodeService)
  : m_nodeService(std::move(_nodeService))
{}

task::Task<void> OPEngineEndpoints::exchangeCapabilities(const Json::Value&, Json::Value& _response)
{
    Json::Value result = Json::arrayValue;
    result.append("engine_forkchoiceUpdatedV1");
    result.append("engine_forkchoiceUpdatedV2");
    result.append("engine_forkchoiceUpdatedV3");
    result.append("engine_getPayloadV1");
    result.append("engine_getPayloadV2");
    result.append("engine_getPayloadV3");
    result.append("engine_newPayloadV1");
    result.append("engine_newPayloadV2");
    result.append("engine_newPayloadV3");
    _response = std::move(result);
    co_return;
}

task::Task<void> OPEngineEndpoints::forkchoiceUpdatedV1(
    const Json::Value& _request, Json::Value& _response)
{
    co_await handleForkchoiceUpdated(1, _request, _response);
}

task::Task<void> OPEngineEndpoints::forkchoiceUpdatedV2(
    const Json::Value& _request, Json::Value& _response)
{
    co_await handleForkchoiceUpdated(2, _request, _response);
}

task::Task<void> OPEngineEndpoints::forkchoiceUpdatedV3(
    const Json::Value& _request, Json::Value& _response)
{
    co_await handleForkchoiceUpdated(3, _request, _response);
}

task::Task<void> OPEngineEndpoints::getPayloadV1(const Json::Value& _request, Json::Value& _response)
{
    co_await handleGetPayload(1, _request, _response);
}

task::Task<void> OPEngineEndpoints::getPayloadV2(const Json::Value& _request, Json::Value& _response)
{
    co_await handleGetPayload(2, _request, _response);
}

task::Task<void> OPEngineEndpoints::getPayloadV3(const Json::Value& _request, Json::Value& _response)
{
    co_await handleGetPayload(3, _request, _response);
}

task::Task<void> OPEngineEndpoints::newPayloadV1(const Json::Value& _request, Json::Value& _response)
{
    co_await handleNewPayload(1, _request, _response);
}

task::Task<void> OPEngineEndpoints::newPayloadV2(const Json::Value& _request, Json::Value& _response)
{
    co_await handleNewPayload(2, _request, _response);
}

task::Task<void> OPEngineEndpoints::newPayloadV3(const Json::Value& _request, Json::Value& _response)
{
    co_await handleNewPayload(3, _request, _response);
}

task::Task<void> OPEngineEndpoints::handleForkchoiceUpdated(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== MOCK BEGIN: forkchoiceUpdated mock state machine =====
    // This mock path exists only for early OP Stack integration testing.
    // It generates a dynamic payloadId and caches a corresponding payload record so that:
    // 1. op-node can call forkchoiceUpdated multiple times,
    // 2. getPayload can later return a matching, non-constant payload,
    // 3. the overall interaction is closer to the real engine API sequence.
    //
    // TODO: replace this mock path with real bcos-engine integration.
    // Real implementation should:
    // 1. call bcos-engine forkchoice update logic with head/safe/finalized block hashes,
    // 2. ask bcos-engine to start or resume payload building,
    // 3. obtain a real payloadId from the execution engine,
    // 4. persist the payload build context in bcos-engine rather than local RPC memory.
    ForkchoiceUpdatedV3Request decodedRequest;
    auto const& params = _request;
    if (auto [ok, request] = decodeForkchoiceUpdatedV3Request(params); ok)
    {
        decodedRequest = std::move(request);
    }

    auto payloadId = generateMockPayloadId();
    auto payloadRecord = buildMockPayloadRecord(payloadId, decodedRequest);
    storeMockPayloadRecord(payloadRecord);

    ForkchoiceUpdatedV3Response decodedResponse;
    decodedResponse.payloadStatus.status = "VALID";
    decodedResponse.payloadStatus.latestValidHash =
        decodedRequest.forkchoiceState.headBlockHash.empty() ? std::nullopt
                                                            : std::make_optional(
                                                                  decodedRequest.forkchoiceState.headBlockHash);
    decodedResponse.payloadStatus.validationError = std::nullopt;
    decodedResponse.payloadId = payloadId;

    Json::Value result(Json::objectValue);
    combineForkchoiceUpdatedV3Response(result, decodedResponse);
    _response = std::move(result);
    // ===== MOCK END: forkchoiceUpdated mock state machine =====
    co_return;
}

task::Task<void> OPEngineEndpoints::handleGetPayload(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== MOCK BEGIN: getPayload mock payload retrieval =====
    // This mock path returns a cached payload record generated earlier by forkchoiceUpdated.
    // The response is intentionally dynamic per payloadId so that repeated op-node tests do not
    // observe a single constant block template.
    //
    // TODO: replace this mock path with real bcos-engine integration.
    // Real implementation should:
    // 1. call bcos-engine with payloadId to fetch the in-progress build result,
    // 2. read the real execution payload fields from bcos-engine,
    // 3. fetch the real block value / blob bundle / builder override flag from bcos-engine,
    // 4. remove local mock cache usage and rely on engine-managed payload lifecycle.
    GetPayloadV3Response decodedResponse;
    if (auto [ok, request] = decodeGetPayloadV3Request(_request); ok)
    {
        if (auto record = findMockPayloadRecord(request.payloadId); record.has_value())
        {
            decodedResponse = std::move(record->payloadResponse);
        }
        else
        {
            ForkchoiceUpdatedV3Request fallbackRequest;
            fallbackRequest.forkchoiceState.headBlockHash = normalizeHash("", "fallback-head");
            auto fallback = buildMockPayloadRecord(request.payloadId, fallbackRequest);
            decodedResponse = std::move(fallback.payloadResponse);
        }
    }

    Json::Value result(Json::objectValue);
    combineGetPayloadV3Response(result, decodedResponse);
    _response = std::move(result);
    // ===== MOCK END: getPayload mock payload retrieval =====
    co_return;
}

task::Task<void> OPEngineEndpoints::handleNewPayload(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== MOCK BEGIN: newPayload mock validation =====
    // This mock path accepts the submitted payload and echoes its blockHash as latestValidHash.
    // It is meant only to keep op-node moving while the real execution pipeline is not wired in.
    //
    // TODO: replace this mock path with real bcos-engine integration.
    // Real implementation should:
    // 1. decode the execution payload and pass it into bcos-engine validation/import logic,
    // 2. verify withdrawals / blob hashes / parent beacon block root in bcos-engine,
    // 3. import or stage the payload in bcos-engine state,
    // 4. return VALID / INVALID / SYNCING / ACCEPTED based on real execution result.

    NewPayloadV3Response decodedResponse;
    decodedResponse.payloadStatus.status = "VALID";
    if (auto [ok, request] = decodeNewPayloadV3Request(_request); ok)
    {
        decodedResponse.payloadStatus.latestValidHash = request.executionPayload.blockHash;
    }
    else
    {
        decodedResponse.payloadStatus.latestValidHash =
            "0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858";
    }
    decodedResponse.payloadStatus.validationError = std::nullopt;

    Json::Value result(Json::objectValue);
    combineNewPayloadV3Response(result, decodedResponse);
    _response = std::move(result);
    // ===== MOCK END: newPayload mock validation =====
    co_return;
}

std::string OPEngineEndpoints::generateMockPayloadId()
{
    auto sequence = m_mockSequence.fetch_add(1, std::memory_order_relaxed) + 1;
    std::stringstream stream;
    stream << "0x" << std::setw(16) << std::setfill('0') << std::hex << sequence;
    return stream.str();
}

OPEngineEndpoints::MockPayloadRecord OPEngineEndpoints::buildMockPayloadRecord(
    std::string const& _payloadId, ForkchoiceUpdatedV3Request const& _request)
{
    auto sequence = m_mockSequence.load(std::memory_order_relaxed);
    auto seed = _payloadId + "|" + _request.forkchoiceState.headBlockHash + "|" +
                std::to_string(sequence) + "|" + std::to_string(utcTime());

    MockPayloadRecord record;
    record.payloadId = _payloadId;
    record.blockHash = keccakHex(seed + "|blockHash");

    auto& payload = record.payloadResponse.executionPayload;
    payload.parentHash = normalizeHash(_request.forkchoiceState.headBlockHash, seed + "|parentHash");
    payload.feeRecipient = normalizeAddress(
        _request.payloadAttributes ? _request.payloadAttributes->suggestedFeeRecipient : "",
        seed + "|feeRecipient");
    payload.stateRoot = keccakHex(seed + "|stateRoot");
    payload.receiptsRoot = keccakHex(seed + "|receiptsRoot");
    payload.logsBloom = logsBloomZeros();
    payload.prevRandao = normalizeHash(
        _request.payloadAttributes ? _request.payloadAttributes->prevRandao : "", seed + "|prevRandao");
    payload.blockNumber = quantity(sequence);
    payload.gasLimit = quantity(30000000);
    payload.gasUsed = quantity(0);
    payload.timestamp = _request.payloadAttributes ? _request.payloadAttributes->timestamp :
                                                    quantity(utcTime() / 1000);
    payload.extraData = "0x";
    payload.baseFeePerGas = quantity(7);
    payload.blockHash = record.blockHash;
    payload.transactions.clear();
    payload.withdrawals = _request.payloadAttributes ? _request.payloadAttributes->withdrawals :
                                                      std::vector<Withdrawal>{buildWithdrawal(0), buildWithdrawal(1)};
    payload.blobGasUsed = quantity(0);
    payload.excessBlobGas = quantity(0);

    record.payloadResponse.blockValue = quantity(0);
    record.payloadResponse.blobsBundle.commitments = {};
    record.payloadResponse.blobsBundle.proofs = {};
    record.payloadResponse.blobsBundle.blobs = {};
    record.payloadResponse.shouldOverrideBuilder = false;
    return record;
}

std::optional<OPEngineEndpoints::MockPayloadRecord> OPEngineEndpoints::findMockPayloadRecord(
    std::string const& _payloadId)
{
    std::lock_guard<std::mutex> lock(x_mockPayloads);
    auto it = m_mockPayloads.find(_payloadId);
    if (it == m_mockPayloads.end())
    {
        return std::nullopt;
    }
    return it->second;
}

void OPEngineEndpoints::storeMockPayloadRecord(MockPayloadRecord _record)
{
    std::lock_guard<std::mutex> lock(x_mockPayloads);
    m_mockPayloads[_record.payloadId] = std::move(_record);
}
}  // namespace bcos::rpc
