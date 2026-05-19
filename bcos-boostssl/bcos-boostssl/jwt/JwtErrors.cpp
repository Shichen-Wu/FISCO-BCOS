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
 * @file JwtErrors.cpp
 * @date 2026.05.19
 */

#include "JwtErrors.h"

namespace bcos::boostssl::jwt
{
std::string_view toString(JwtError error)
{
    switch (error)
    {
    case JwtError::Ok:
        return "ok";
    case JwtError::MissingAuthorization:
        return "missing_authorization";
    case JwtError::InvalidBearerFormat:
        return "invalid_bearer_format";
    case JwtError::InvalidTokenFormat:
        return "invalid_token_format";
    case JwtError::InvalidBase64Url:
        return "invalid_base64url";
    case JwtError::InvalidJson:
        return "invalid_json";
    case JwtError::UnsupportedAlgorithm:
        return "unsupported_algorithm";
    case JwtError::InvalidSignature:
        return "invalid_signature";
    case JwtError::InvalidIssuedAt:
        return "invalid_issued_at";
    case JwtError::Expired:
        return "expired";
    case JwtError::SecretReadFailed:
        return "secret_read_failed";
    }
    return "unknown";
}
}  // namespace bcos::boostssl::jwt
