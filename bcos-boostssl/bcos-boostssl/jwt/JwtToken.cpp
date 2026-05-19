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
 * @file JwtToken.cpp
 * @date 2026.05.19
 */

#include "JwtToken.h"

namespace bcos::boostssl::jwt
{
JwtToken::JwtToken(JwtHeader _header, JwtClaims _claims, std::string _signature)
  : m_header(std::move(_header)), m_claims(std::move(_claims)), m_signature(std::move(_signature))
{}

const JwtHeader& JwtToken::header() const
{
    return m_header;
}

const JwtClaims& JwtToken::claims() const
{
    return m_claims;
}

const std::string& JwtToken::signature() const
{
    return m_signature;
}

bool JwtToken::isValid() const
{
    return !m_header.alg.empty() && !m_signature.empty();
}
}  // namespace bcos::boostssl::jwt
