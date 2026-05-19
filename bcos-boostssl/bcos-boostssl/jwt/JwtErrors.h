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
 * @brief jwt error codes
 * @file JwtErrors.h
 * @date 2026.05.19
 */

#pragma once

#include <string_view>

namespace bcos::boostssl::jwt
{
enum class JwtError
{
    Ok = 0,
    MissingAuthorization,
    InvalidBearerFormat,
    InvalidTokenFormat,
    InvalidBase64Url,
    InvalidJson,
    UnsupportedAlgorithm,
    InvalidSignature,
    InvalidIssuedAt,
    Expired,
    SecretReadFailed
};

std::string_view toString(JwtError error);
}  // namespace bcos::boostssl::jwt
