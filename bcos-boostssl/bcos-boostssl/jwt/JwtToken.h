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
 * @brief jwt token structure
 * @file JwtToken.h
 * @date 2026.05.19
 */

#pragma once

#include <bcos-utilities/Common.h>
#include <json/json.h>
#include <optional>
#include <string>
#include <string_view>

namespace bcos::boostssl::jwt
{
struct JwtHeader
{
    std::string alg;
    std::string typ;
};

struct JwtClaims
{
    std::optional<int64_t> iat;
    std::optional<std::string> id;
    std::optional<std::string> clv;
};

class JwtToken
{
public:
    using Ptr = std::shared_ptr<JwtToken>;

    JwtToken() = default;
    JwtToken(JwtHeader _header, JwtClaims _claims, std::string _signature);

    const JwtHeader& header() const;
    const JwtClaims& claims() const;
    const std::string& signature() const;

    bool isValid() const;

private:
    JwtHeader m_header;
    JwtClaims m_claims;
    std::string m_signature;
};
}  // namespace bcos::boostssl::jwt
