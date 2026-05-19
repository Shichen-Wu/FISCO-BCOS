/**
 *  Copyright (C) 2026 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 */

#include "JwtToken.h"

namespace bcos::boostssl::jwt
{
JwtToken::JwtToken(JwtHeader _header, JwtClaims _claims, std::string _signature)
  : m_header(std::move(_header)), m_claims(std::move(_claims)), m_signature(std::move(_signature))
{}

JwtToken JwtToken::parse(std::string_view jwtCompact)
{
    (void)jwtCompact;
    return {};
}

JwtHeader JwtToken::parseHeader(const Json::Value& json)
{
    (void)json;
    return {};
}

JwtClaims JwtToken::parseClaims(const Json::Value& json)
{
    (void)json;
    return {};
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

bool JwtToken::valid() const
{
    return !m_header.alg.empty() && !m_signature.empty();
}

std::string JwtToken::toCompact() const
{
    return {};
}
}  // namespace bcos::boostssl::jwt
