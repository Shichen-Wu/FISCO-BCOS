/**
 *  Copyright (C) 2026 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 */

#include "JwtVerifier.h"

namespace bcos::boostssl::jwt
{
JwtVerifier::JwtVerifier(JwtVerifyConfig _config) : m_config(std::move(_config)) {}

const JwtVerifyConfig& JwtVerifier::config() const
{
    return m_config;
}

JwtVerifyResult JwtVerifier::verify(std::string_view authorizationHeader) const
{
    (void)authorizationHeader;
    return {};
}

JwtVerifyResult JwtVerifier::verifyToken(std::string_view jwtCompact) const
{
    (void)jwtCompact;
    return {};
}

bool JwtVerifier::verifyAlgorithm(std::string_view alg) const
{
    (void)alg;
    return true;
}

bool JwtVerifier::verifyIat(std::optional<int64_t> iat) const
{
    (void)iat;
    return true;
}

std::string JwtVerifier::readSecret() const
{
    return {};
}
}  // namespace bcos::boostssl::jwt
