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
#include "engine/bcos-engine/EngineService.h"
#include "bcos-framework/protocol/TransactionFactory.h"
#include <bcos-rpc/web3jsonrpc/utils/util.h>
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

bcos::Bloom toBloom(std::string const& _hexBloom)
{
    auto bytes = bcos::fromHex(_hexBloom);
    bcos::Bloom bloom{};
    auto const copySize = std::min(bytes.size(), bloom.size());
    std::copy_n(bytes.begin(), copySize, bloom.begin());
    return bloom;
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

std::vector<std::string> defaultMockTransactions()
{
    return {
        "0x03f88f0780843b9aca008506fc23ac00830186a09400000000000000000000000000000000000001008080c001e1a0010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c44401401a0840650aa8f74d2b07f40067dc33b715078d73422f01da17abdbd11e02bbdfda9a04b2260f6022bf53eadb337b3e59514936f7317d872defb891a708ee279bdca90"};
}

std::tuple<bool, ForkchoiceUpdatedV3Request> decodeForkchoiceUpdatedRequestForVersion(
    std::uint32_t _version, Json::Value const& _params)
{
    if (_version <= 3)
    {
        return decodeForkchoiceUpdatedV3Request(_params);
    }

    ForkchoiceUpdatedV3Request request;
    if (!_params.isArray() || _params.size() < 1 || _params.size() > 3)
    {
        return {false, request};
    }

    if (!decodeForkchoiceState(_params[0], request.forkchoiceState))
    {
        return {false, request};
    }

    if (_params.size() > 1 && !_params[1].isNull())
    {
        PayloadAttributesV3 payloadAttributes;
        if (!decodePayloadAttributesV3(_params[1], payloadAttributes))
        {
            return {false, request};
        }
        request.payloadAttributes = std::move(payloadAttributes);
    }

    if (_params.size() > 2 && !_params[2].isNull() && !_params[2].isString())
    {
        return {false, request};
    }

    return {true, std::move(request)};
}

std::tuple<bool, NewPayloadV3Request> decodeNewPayloadRequestForVersion(
    std::uint32_t _version, Json::Value const& _params)
{
    if (_version <= 3)
    {
        return decodeNewPayloadV3Request(_params);
    }

    NewPayloadV3Request request;
    if (!_params.isArray() || _params.size() != 4)
    {
        return {false, request};
    }

    if (!decodeExecutionPayloadV3(_params[0], request.executionPayload))
    {
        return {false, request};
    }
    if (!_params[1].isArray())
    {
        return {false, request};
    }
    request.expectedBlobVersionedHashes.reserve(_params[1].size());
    for (auto const& item : _params[1])
    {
        if (!item.isString())
        {
            return {false, request};
        }
        request.expectedBlobVersionedHashes.emplace_back(item.asString());
    }
    if (!_params[2].isString())
    {
        return {false, request};
    }
    request.parentBeaconBlockRoot = _params[2].asString();

    if (!_params[3].isArray())
    {
        return {false, request};
    }
    for (auto const& item : _params[3])
    {
        if (!item.isString())
        {
            return {false, request};
        }
    }

    return {true, std::move(request)};
}
}  // namespace

OPEngineEndpoints::OPEngineEndpoints(NodeService::Ptr _nodeService)
  : m_nodeService(std::move(_nodeService))
{}

void OPEngineEndpoints::setEngineService(bcos::engine::EngineServiceInterface::Ptr _engineService)
{
    m_engineService = std::move(_engineService);
}

task::Task<void> OPEngineEndpoints::exchangeCapabilities(const Json::Value&, Json::Value& _response)
{
    Json::Value result = Json::arrayValue;
    result.append("engine_forkchoiceUpdatedV1");
    result.append("engine_forkchoiceUpdatedV2");
    result.append("engine_forkchoiceUpdatedV3");
    result.append("engine_forkchoiceUpdatedV4");
    result.append("engine_getPayloadV1");
    result.append("engine_getPayloadV2");
    result.append("engine_getPayloadV3");
    result.append("engine_getPayloadV4");
    result.append("engine_newPayloadV1");
    result.append("engine_newPayloadV2");
    result.append("engine_newPayloadV3");
    result.append("engine_newPayloadV4");
    _response = std::move(result);
    OPENGINE_LOG(INFO) << LOG_BADGE("exchangeCapabilities")
                       << LOG_DESC("engine_exchangeCapabilities handled")
                       << LOG_KV("response", printJson(_response));
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

task::Task<void> OPEngineEndpoints::forkchoiceUpdatedV4(
    const Json::Value& _request, Json::Value& _response)
{
    co_await handleForkchoiceUpdated(4, _request, _response);
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

task::Task<void> OPEngineEndpoints::getPayloadV4(const Json::Value& _request, Json::Value& _response)
{
    co_await handleGetPayload(4, _request, _response);
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

task::Task<void> OPEngineEndpoints::newPayloadV4(const Json::Value& _request, Json::Value& _response)
{
    co_await handleNewPayload(4, _request, _response);
}

task::Task<void> OPEngineEndpoints::handleForkchoiceUpdated(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== ENGINE BEGIN: forkchoiceUpdated engine call skeleton =====
    // TODO: once the real engine service is fully wired, convert the request into
    // bcos::engine::ForkchoiceState / bcos::engine::PayloadAttributes and call:
    //   auto result = co_await m_engineService->updateForkchoice(engineForkchoiceState, ...);
    // Then map the returned ForkchoiceUpdatedResult into the JSON response.
    // ===== ENGINE END: forkchoiceUpdated engine call skeleton =====

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
    if (auto [ok, request] = decodeForkchoiceUpdatedRequestForVersion(_version, params); ok)
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
    OPENGINE_LOG(INFO) << LOG_BADGE("handleForkchoiceUpdated")
                       << LOG_DESC("engine_forkchoiceUpdated handled")
                       << LOG_KV("version", _version)
                       << LOG_KV("response", printJson(_response));
    // ===== MOCK END: forkchoiceUpdated mock state machine =====
    
    co_return;
}

task::Task<void> OPEngineEndpoints::handleGetPayload(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== ENGINE BEGIN: getPayload engine call skeleton =====
    // TODO: once the real engine service is fully wired, convert the payloadId into
    // bcos::engine::PayloadID and call:
    //   auto result = co_await m_engineService->getPayload(enginePayloadId, version);
    // Then map the returned GetPayloadResult into the JSON response.
    // ===== ENGINE END: getPayload engine call skeleton =====

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
    if (_version >= 4)
    {
        result["executionRequests"] = buildMockExecutionRequests(
            decodedResponse.executionPayload.blockHash.empty() ?
                "0x0000000000000000000000000000000000000000000000000000000000000000" :
                decodedResponse.executionPayload.blockHash);
    }
    _response = std::move(result);
    OPENGINE_LOG(INFO) << LOG_BADGE("handleGetPayload") << LOG_DESC("engine_getPayload handled")
                       << LOG_KV("version", _version)
                       << LOG_KV("response", printJson(_response));
    // ===== MOCK END: getPayload mock payload retrieval =====
    co_return;
}

task::Task<void> OPEngineEndpoints::handleNewPayload(
    std::uint32_t _version, const Json::Value& _request, Json::Value& _response)
{
    boost::ignore_unused(_version);

    // ===== ENGINE BEGIN: newPayload engine call skeleton =====
    // TODO: once the real engine service is fully wired, convert the request into
    // bcos::engine::NewPayloadRequest and call:
    //   auto result = co_await m_engineService->newPayload(engineRequest, version);
    // Then map the returned PayloadStatus into the JSON response.
    // ===== ENGINE END: newPayload engine call skeleton =====

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
    if (auto [ok, request] = decodeNewPayloadRequestForVersion(_version, _request); ok)
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
    OPENGINE_LOG(INFO) << LOG_BADGE("handleNewPayload") << LOG_DESC("engine_newPayload handled")
                       << LOG_KV("version", _version)
                       << LOG_KV("response", printJson(_response));
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
    payload.gasLimit = (_request.payloadAttributes && !_request.payloadAttributes->gasLimit.empty()) ?
                           _request.payloadAttributes->gasLimit :
                           quantity(30000000);
    payload.timestamp = _request.payloadAttributes ? _request.payloadAttributes->timestamp :
                                                    quantity(utcTime() / 1000);
    payload.extraData = "0x";
    payload.baseFeePerGas =
        (_request.payloadAttributes && !_request.payloadAttributes->minBaseFee.empty()) ?
            _request.payloadAttributes->minBaseFee :
            quantity(7);
    payload.blockHash = record.blockHash;
    payload.transactions =
        (_request.payloadAttributes && !_request.payloadAttributes->transactions.empty()) ?
            _request.payloadAttributes->transactions :
            defaultMockTransactions();
    payload.gasUsed = quantity(std::max<std::size_t>(1, payload.transactions.size()) * 21000);
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

Json::Value OPEngineEndpoints::buildMockExecutionRequests(std::string const& _payloadId)
{
    Json::Value executionRequests(Json::arrayValue);
    executionRequests.append("0x");
    executionRequests.append(keccakHex(_payloadId + "|executionRequest").substr(0, 66));
    return executionRequests;
}

bcos::engine::EngineApiVersion OPEngineEndpoints::toEngineApiVersion(std::uint32_t _version)
{
    return static_cast<bcos::engine::EngineApiVersion>(_version);
}

bcos::engine::ForkchoiceState OPEngineEndpoints::toEngineForkchoiceState(
    ForkchoiceState const& _forkchoiceState)
{
    return bcos::engine::ForkchoiceState{
        .headBlockHash = bcos::h256(bcos::fromHex(_forkchoiceState.headBlockHash)),
        .safeBlockHash = bcos::h256(bcos::fromHex(_forkchoiceState.safeBlockHash)),
        .finalizedBlockHash = bcos::h256(bcos::fromHex(_forkchoiceState.finalizedBlockHash)),
    };
}

bcos::engine::PayloadAttributes OPEngineEndpoints::toEnginePayloadAttributes(
    PayloadAttributesV3 const& _payloadAttributes)
{
    bcos::engine::PayloadAttributes payloadAttributes;
    payloadAttributes.timestamp = std::stoull(_payloadAttributes.timestamp.substr(2), nullptr, 16);
    payloadAttributes.prevRandao = bcos::h256(bcos::fromHex(_payloadAttributes.prevRandao));
    payloadAttributes.suggestedFeeRecipient =
        bcos::Address(bcos::fromHex(_payloadAttributes.suggestedFeeRecipient));
    if (!_payloadAttributes.withdrawals.empty())
    {
        std::vector<bcos::engine::WithdrawalV1> withdrawals;
        withdrawals.reserve(_payloadAttributes.withdrawals.size());
        for (auto const& withdrawal : _payloadAttributes.withdrawals)
        {
            withdrawals.emplace_back(bcos::engine::WithdrawalV1{
                .index = u256(bcos::fromHex(withdrawal.index)),
                .validatorIndex = u256(bcos::fromHex(withdrawal.validatorIndex)),
                .address = bcos::Address(bcos::fromHex(withdrawal.address)),
                .amount = u256(bcos::fromHex(withdrawal.amount)),
            });
        }
        payloadAttributes.withdrawals = std::move(withdrawals);
    }
    if (!_payloadAttributes.parentBeaconBlockRoot.empty())
    {
        payloadAttributes.parentBeaconBlockRoot =
            bcos::h256(bcos::fromHex(_payloadAttributes.parentBeaconBlockRoot));
    }
    return payloadAttributes;
}

bcos::engine::NewPayloadRequest OPEngineEndpoints::toEngineNewPayloadRequest(
    NewPayloadV3Request const& _request)
{
    auto const& payload = _request.executionPayload;
    bcos::engine::ExecutionPayload executionPayload{
        .parentHash = bcos::h256(bcos::fromHex(payload.parentHash)),
        .feeRecipient = bcos::Address(bcos::fromHex(payload.feeRecipient)),
        .stateRoot = bcos::h256(bcos::fromHex(payload.stateRoot)),
        .receiptsRoot = bcos::h256(bcos::fromHex(payload.receiptsRoot)),
        .logsBloom = toBloom(payload.logsBloom),
        .prevRandao = bcos::h256(bcos::fromHex(payload.prevRandao)),
        .blockNumber = static_cast<bcos::protocol::BlockNumber>(std::stoull(
            payload.blockNumber.substr(2), nullptr, 16)),
        .gasLimit = u256(bcos::fromHex(payload.gasLimit)),
        .gasUsed = u256(bcos::fromHex(payload.gasUsed)),
        .timestamp = std::stoull(payload.timestamp.substr(2), nullptr, 16),
        .extraData = bcos::fromHex(payload.extraData),
        .baseFeePerGas = u256(bcos::fromHex(payload.baseFeePerGas)),
        .blockHash = bcos::h256(bcos::fromHex(payload.blockHash)),
        .transactions = {},
        .withdrawals = std::nullopt,
        .blobGasUsed = std::nullopt,
        .excessBlobGas = std::nullopt,
    };
    // NOTE: bcos::engine::ExecutionPayload stores decoded Transaction::Ptr objects.
    // The mock path does not need them yet, so keep the list empty here.
    // The real implementation should decode each raw payload transaction through
    // NodeService::blockFactory()->transactionFactory()->decodeTransaction(...).
    if (!payload.withdrawals.empty())
    {
        std::vector<bcos::engine::WithdrawalV1> withdrawals;
        withdrawals.reserve(payload.withdrawals.size());
        for (auto const& withdrawal : payload.withdrawals)
        {
            withdrawals.emplace_back(bcos::engine::WithdrawalV1{
                .index = u256(bcos::fromHex(withdrawal.index)),
                .validatorIndex = u256(bcos::fromHex(withdrawal.validatorIndex)),
                .address = bcos::Address(bcos::fromHex(withdrawal.address)),
                .amount = u256(bcos::fromHex(withdrawal.amount)),
            });
        }
        executionPayload.withdrawals = std::move(withdrawals);
    }
    if (!payload.blobGasUsed.empty())
    {
        executionPayload.blobGasUsed = u256(bcos::fromHex(payload.blobGasUsed));
    }
    if (!payload.excessBlobGas.empty())
    {
        executionPayload.excessBlobGas = u256(bcos::fromHex(payload.excessBlobGas));
    }

    bcos::engine::NewPayloadRequest request;
    request.executionPayload = std::move(executionPayload);
    for (auto const& hash : _request.expectedBlobVersionedHashes)
    {
        request.expectedBlobVersionedHashes.emplace_back(bcos::h256(bcos::fromHex(hash)));
    }
    if (!_request.parentBeaconBlockRoot.empty())
    {
        request.parentBeaconBlockRoot =
            bcos::h256(bcos::fromHex(_request.parentBeaconBlockRoot));
    }
    return request;
}

bcos::engine::PayloadID OPEngineEndpoints::toEnginePayloadId(std::string const& _payloadId)
{
    return _payloadId;
}
}  // namespace bcos::rpc
