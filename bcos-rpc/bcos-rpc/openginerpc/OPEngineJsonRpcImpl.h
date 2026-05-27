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
 * @file OPEngineJsonRpcImpl.h
 * @date 2026/5/20
 */

#pragma once

#include "endpoints/OPEngineEndpoints.h"
#include "endpoints/OPEngineEndpointsMapping.h"
#include "engine/bcos-engine/EngineService.h"
#include "bcos-framework/gateway/GatewayInterface.h"
#include <bcos-rpc/filter/FilterSystem.h>
#include <bcos-rpc/groupmgr/GroupManager.h>
#include <bcos-rpc/web3jsonrpc/endpoints/Endpoints.h>
#include <bcos-rpc/web3jsonrpc/endpoints/EndpointsMapping.h>
#include <bcos-boostssl/websocket/WsService.h>
#include <json/json.h>

namespace bcos::rpc
{
class OPEngineJsonRpcImpl : public std::enable_shared_from_this<OPEngineJsonRpcImpl>
{
public:
    using Ptr = std::shared_ptr<OPEngineJsonRpcImpl>;
    using Sender = std::function<void(bcos::bytes)>;

    OPEngineJsonRpcImpl(std::string _groupId, uint32_t _batchRequestSizeLimit,
        GroupManager::Ptr _groupManager, bcos::gateway::GatewayInterface::Ptr _gatewayInterface,
        std::shared_ptr<boostssl::ws::WsService> _wsService, FilterSystem::Ptr _filterSystem,
        bool _syncTransaction);
    ~OPEngineJsonRpcImpl() = default;

    void setEngineService(bcos::engine::EngineServiceInterface::Ptr _engineService);

    void onRPCRequest(std::string_view _requestBody, const Sender& _sender);

    OPEngineEndpoints& endpoints() { return m_endpoints; }

private:
    void handleRequest(Json::Value _request, const std::function<void(Json::Value)>& _callback);
    void handleBatchRequest(Json::Value _request, const Sender& _sender);

private:
    std::string m_groupId;
    uint32_t m_batchRequestSizeLimit;
    GroupManager::Ptr m_groupManager;
    bcos::gateway::GatewayInterface::Ptr m_gatewayInterface;
    std::shared_ptr<boostssl::ws::WsService> m_wsService;
    bcos::engine::EngineServiceInterface::Ptr m_engineService;
    OPEngineEndpoints m_endpoints;
    OPEngineEndpointsMapping m_endpointsMapping;
    Endpoints m_web3Endpoints;
    EndpointsMapping m_web3EndpointsMapping;
};
}  // namespace bcos::rpc
