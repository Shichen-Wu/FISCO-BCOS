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
 * @brief jwt verifier
 * @file JwtVerifier.cpp
 * @date 2026.05.19
 */

#include "JwtVerifier.h"
#include <bcos-utilities/Base64.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/FileUtility.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <cctype>
#include <vector>

namespace bcos::boostssl::jwt
{
namespace
{
std::string toBase64Url(std::string_view _input)
{
    auto base64url = std::string(_input);
    while (!base64url.empty() && base64url.back() == '=')
    {
        base64url.pop_back();
    }
    std::replace(base64url.begin(), base64url.end(), '+', '-');
    std::replace(base64url.begin(), base64url.end(), '/', '_');
    return base64url;
}

JwtVerifyResult makeError(JwtError _error, std::string _message)
{
    return JwtVerifyResult{false, _error, std::move(_message), {}};
}

}  // namespace


JwtVerifier::JwtVerifier(JwtConfig::Ptr _config) : m_config(std::move(_config)) {}

const JwtConfig& JwtVerifier::config() const
{
    return *m_config;
}

JwtVerifyResult JwtVerifier::verify(std::string_view _authorizationHeader) const
{
    if (_authorizationHeader.empty())
    {
        return makeError(JwtError::MissingAuthorization, "missing authorization header");
    }

    if (!boost::istarts_with(_authorizationHeader, "Bearer "))
    {
        return makeError(JwtError::InvalidBearerFormat, "invalid bearer format");
    }

    auto jwtCompact = _authorizationHeader.substr(std::string_view("Bearer ").size());
    return verifyToken(jwtCompact);
}

JwtVerifyResult JwtVerifier::verifyToken(std::string_view _jwtCompact) const
{
    std::string parseError;
    auto token = JwtToken::decode(_jwtCompact, parseError);
    if (!token)
    {
        return makeError(JwtError::InvalidTokenFormat, std::move(parseError));
    }

    if (!verifyAlgorithm(token->header().alg))
    {
        return makeError(JwtError::UnsupportedAlgorithm, "unsupported algorithm");
    }

    if (!verifyIat(token->claims().iat))
    {
        return makeError(JwtError::InvalidIssuedAt, "invalid issued-at");
    }

    auto secret = readSecretRaw();
    if (secret.empty())
    {
        return makeError(JwtError::SecretReadFailed, "secret read failed");
    }

    auto firstDot = _jwtCompact.find('.');
    auto secondDot = _jwtCompact.find('.', firstDot + 1);
    auto signingInput = std::string(_jwtCompact.substr(0, secondDot));

    unsigned int macLength = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    auto macResult = HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
        reinterpret_cast<const unsigned char*>(signingInput.data()), signingInput.size(), mac,
        &macLength);
    if (!macResult || macLength == 0)
    {
        return makeError(JwtError::InvalidSignature, "invalid signature");
    }

    auto expectedSignature =
        toBase64Url(bcos::base64Encode(reinterpret_cast<const bcos::byte*>(mac), macLength));
    if (expectedSignature != token->signature())
    {
        return makeError(JwtError::InvalidSignature, "invalid signature");
    }

    JwtVerifyResult result;
    result.ok = true;
    result.error = JwtError::Ok;
    result.token = std::move(*token);
    return result;
}

bool JwtVerifier::verifyAlgorithm(std::string_view _alg) const
{
    if (_alg.empty())
    {
        return false;
    }

    auto allowedAlgorithms = m_config ? m_config->allowedAlgorithms() : std::string();
    if (allowedAlgorithms.empty())
    {
        return true;
    }

    std::vector<std::string> algorithms;
    boost::split(algorithms, allowedAlgorithms, boost::is_any_of(","));
    for (auto& algorithm : algorithms)
    {
        boost::algorithm::trim(algorithm);
        if (algorithm.empty())
        {
            continue;
        }
        if (algorithm == "*" || algorithm == _alg)
        {
            return true;
        }
    }
    return false;
}

bool JwtVerifier::verifyIat(std::optional<int64_t> _iat) const
{
    if (!_iat.has_value())
    {
        return true;
    }

    auto now = static_cast<int64_t>(utcTime());
    auto skew = m_config ? m_config->clockSkewSecs() : 0;
    return (*_iat >= (now - skew)) && (*_iat <= (now + skew));
}

std::string JwtVerifier::readSecret() const
{
    return readSecretRaw();
}

bool JwtVerifier::validateSecret(std::string_view _secret) const
{
    if (_secret.size() != 64)
    {
        return false;
    }

    return std::all_of(_secret.begin(), _secret.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

std::string JwtVerifier::readSecretRaw() const
{
    if (!m_config || m_config->secretFile().empty())
    {
        return {};
    }

    auto secretContent = readContentsToString(m_config->secretFile());
    if (!secretContent || secretContent->empty())
    {
        return {};
    }

    auto secret = boost::algorithm::trim_copy(*secretContent);
    if (secret.empty())
    {
        return {};
    }

    if (boost::algorithm::starts_with(secret, "0x") || boost::algorithm::starts_with(secret, "0X"))
    {
        secret = secret.substr(2);
    }

    if (!validateSecret(secret))
    {
        return {};
    }

    std::string decoded;
    decoded.resize(secret.size() / 2);
    try
    {
        boost::algorithm::unhex(secret.begin(), secret.end(), decoded.begin());
    }
    catch (...)
    {
        return {};
    }
    return decoded;
}
}  // namespace bcos::boostssl::jwt
