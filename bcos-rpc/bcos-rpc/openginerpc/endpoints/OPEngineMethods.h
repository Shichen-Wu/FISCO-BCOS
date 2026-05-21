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
 * @file OPEngineMethods.h
 * @date 2026/5/20
 */

#pragma once

#include <string_view>

namespace bcos::rpc
{
enum class OPEngineMethod
{
    engine_exchangeCapabilities,
    engine_forkchoiceUpdatedV1,
    engine_forkchoiceUpdatedV2,
    engine_forkchoiceUpdatedV3,
    engine_getPayloadV1,
    engine_getPayloadV2,
    engine_getPayloadV3,
    engine_newPayloadV1,
    engine_newPayloadV2,
    engine_newPayloadV3,
};

inline std::string_view methodString(OPEngineMethod _method)
{
    switch (_method)
    {
    case OPEngineMethod::engine_exchangeCapabilities:
        return "engine_exchangeCapabilities";
    case OPEngineMethod::engine_forkchoiceUpdatedV1:
        return "engine_forkchoiceUpdatedV1";
    case OPEngineMethod::engine_forkchoiceUpdatedV2:
        return "engine_forkchoiceUpdatedV2";
    case OPEngineMethod::engine_forkchoiceUpdatedV3:
        return "engine_forkchoiceUpdatedV3";
    case OPEngineMethod::engine_getPayloadV1:
        return "engine_getPayloadV1";
    case OPEngineMethod::engine_getPayloadV2:
        return "engine_getPayloadV2";
    case OPEngineMethod::engine_getPayloadV3:
        return "engine_getPayloadV3";
    case OPEngineMethod::engine_newPayloadV1:
        return "engine_newPayloadV1";
    case OPEngineMethod::engine_newPayloadV2:
        return "engine_newPayloadV2";
    case OPEngineMethod::engine_newPayloadV3:
        return "engine_newPayloadV3";
    }
    return {};
}
}  // namespace bcos::rpc
