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
#include <bcos-utilities/Base64.h>
#include <algorithm>
#include <cctype>
#include <json/json.h>
#include <memory>

namespace bcos::boostssl::jwt
{
namespace
{
std::string toBase64(std::string_view _input)
{
    auto base64 = std::string(_input);
    auto padding = (4 - (base64.size() % 4)) % 4;
    base64.append(padding, '=');
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
    return base64;
}

bool parseJson(std::string const& _jsonString, Json::Value& _value, std::string& _errorMessage)
{
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    std::string errors;
    auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
    if (!reader->parse(
            _jsonString.data(), _jsonString.data() + _jsonString.size(), &_value, &errors))
    {
        _errorMessage = errors;
        return false;
    }
    return true;
}

std::optional<int64_t> parseIat(Json::Value const& _claims)
{
    auto iat = _claims["iat"];
    if (iat.isNull())
    {
        return std::nullopt;
    }
    if (iat.isInt64())
    {
        return iat.asInt64();
    }
    if (iat.isUInt64())
    {
        return static_cast<int64_t>(iat.asUInt64());
    }
    if (iat.isString())
    {
        auto iatString = iat.asString();
        if (iatString.empty())
        {
            return std::nullopt;
        }
        if (std::all_of(iatString.begin(), iatString.end(),
                [](unsigned char ch) { return std::isdigit(ch) != 0; }))
        {
            return std::stoll(iatString);
        }
    }
    return std::nullopt;
}
}  // namespace

JwtToken::JwtToken(JwtHeader _header, JwtClaims _claims, std::string _signature)
  : m_header(std::move(_header)), m_claims(std::move(_claims)), m_signature(std::move(_signature))
{}

std::optional<JwtToken> JwtToken::decode(std::string_view _jwtCompact, std::string& _errorMessage)
{
    auto firstDot = _jwtCompact.find('.');
    if (firstDot == std::string_view::npos)
    {
        _errorMessage = "invalid jwt token format";
        return std::nullopt;
    }

    auto secondDot = _jwtCompact.find('.', firstDot + 1);
    if (secondDot == std::string_view::npos || secondDot + 1 >= _jwtCompact.size())
    {
        _errorMessage = "invalid jwt token format";
        return std::nullopt;
    }

    auto headerPart = _jwtCompact.substr(0, firstDot);
    auto claimsPart = _jwtCompact.substr(firstDot + 1, secondDot - firstDot - 1);
    auto signaturePart = _jwtCompact.substr(secondDot + 1);

    auto headerJson = bcos::base64Decode(toBase64(headerPart));
    auto claimsJson = bcos::base64Decode(toBase64(claimsPart));
    if (headerJson.empty() || claimsJson.empty())
    {
        _errorMessage = "invalid jwt base64url content";
        return std::nullopt;
    }

    Json::Value headerValue;
    Json::Value claimsValue;
    if (!parseJson(headerJson, headerValue, _errorMessage))
    {
        return std::nullopt;
    }
    if (!parseJson(claimsJson, claimsValue, _errorMessage))
    {
        return std::nullopt;
    }

    JwtHeader header;
    if (headerValue.isMember("alg"))
    {
        header.alg = headerValue["alg"].asString();
    }
    if (headerValue.isMember("typ"))
    {
        header.typ = headerValue["typ"].asString();
    }

    JwtClaims claims;
    claims.iat = parseIat(claimsValue);
    if (claimsValue.isMember("id"))
    {
        claims.id = claimsValue["id"].asString();
    }
    if (claimsValue.isMember("clv"))
    {
        claims.clv = claimsValue["clv"].asString();
    }

    auto token = JwtToken(std::move(header), std::move(claims), std::string(signaturePart));
    if (!token.isValid())
    {
        _errorMessage = "invalid jwt token";
        return std::nullopt;
    }
    return token;
}

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
