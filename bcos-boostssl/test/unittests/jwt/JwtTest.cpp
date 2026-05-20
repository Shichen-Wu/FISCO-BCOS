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
 * @brief jwt tests
 * @file JwtTest.cpp
 * @date 2026.05.20
 */

#include <bcos-boostssl/jwt/Jwt.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/Base64.h>
#include <bcos-utilities/DataConvertUtility.h>
#include <bcos-utilities/FileUtility.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

using namespace bcos;
using namespace bcos::boostssl::jwt;

namespace
{
std::string toBase64Url(std::string_view _input)
{
    auto encoded = base64Encode(reinterpret_cast<const byte*>(_input.data()), _input.size());
    while (!encoded.empty() && encoded.back() == '=')
    {
        encoded.pop_back();
    }
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return encoded;
}

std::string buildJwt(std::string_view _headerJson, std::string_view _claimsJson,
    std::string_view _secretHex)
{
    auto header = toBase64Url(_headerJson);
    auto claims = toBase64Url(_claimsJson);
    auto signingInput = header + "." + claims;
    auto secret = fromHex(std::string(_secretHex));

    unsigned int macLength = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
        reinterpret_cast<const unsigned char*>(signingInput.data()), signingInput.size(), mac,
        &macLength);
    auto signature = toBase64Url(
        std::string_view(reinterpret_cast<const char*>(mac), static_cast<size_t>(macLength)));
    return signingInput + "." + signature;
}

std::string writeSecretFile(std::string const& _hexSecret)
{
    auto tempDir = std::filesystem::temp_directory_path();
    auto path = tempDir / ("fisco-bcos-jwt-secret-" + std::to_string(utcTime()) + ".hex");
    std::ofstream ofs(path);
    ofs << _hexSecret;
    ofs.close();
    return path.string();
}
}  // namespace

BOOST_AUTO_TEST_SUITE(JwtTest)

BOOST_AUTO_TEST_CASE(testJwtTokenDecode)
{
    auto jwt = buildJwt(R"({"alg":"HS256","typ":"JWT"})",
        R"({"iat":1710000000,"id":"client1","clv":"1.0"})",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    std::string error;
    auto token = JwtToken::decode(jwt, error);
    BOOST_REQUIRE(token.has_value());
    BOOST_CHECK_EQUAL(token->header().alg, "HS256");
    BOOST_CHECK_EQUAL(token->header().typ, "JWT");
    BOOST_CHECK(token->claims().iat.has_value());
    BOOST_CHECK_EQUAL(token->claims().iat.value(), 1710000000);
    BOOST_CHECK(token->claims().id.has_value());
    BOOST_CHECK_EQUAL(token->claims().id.value(), "client1");
    BOOST_CHECK(token->claims().clv.has_value());
    BOOST_CHECK_EQUAL(token->claims().clv.value(), "1.0");
}

BOOST_AUTO_TEST_CASE(testJwtVerifierSuccess)
{
    auto secretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    auto secretFile = writeSecretFile(secretHex);

    auto config = std::make_shared<JwtConfig>();
    config->setEnableJWT(true);
    config->setSecretFile(secretFile);
    config->setClockSkewSecs(60);
    config->setAllowedAlgorithms("HS256");

    JwtVerifier verifier(config);
    auto jwt = buildJwt(R"({"alg":"HS256","typ":"JWT"})",
        std::string("{\"iat\":") + std::to_string(static_cast<int64_t>(utcTime())) +
            R"(,"id":"client1","clv":"1.0"})",
        secretHex);

    auto result = verifier.verify("Bearer " + jwt);
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(result.error, JwtError::Ok);
    BOOST_CHECK(result.token.claims().iat.has_value());
    BOOST_CHECK_EQUAL(result.token.header().alg, "HS256");
}

BOOST_AUTO_TEST_CASE(testJwtVerifierBadBearer)
{
    auto config = std::make_shared<JwtConfig>();
    config->setEnableJWT(true);

    JwtVerifier verifier(config);
    auto result = verifier.verify("Basic abc");
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(result.error, JwtError::InvalidBearerFormat);
}

BOOST_AUTO_TEST_CASE(testJwtVerifierUnsupportedAlg)
{
    auto secretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    auto secretFile = writeSecretFile(secretHex);

    auto config = std::make_shared<JwtConfig>();
    config->setEnableJWT(true);
    config->setSecretFile(secretFile);
    config->setAllowedAlgorithms("HS256");

    JwtVerifier verifier(config);
    auto jwt = buildJwt(R"({"alg":"HS512","typ":"JWT"})",
        std::string("{\"iat\":") + std::to_string(static_cast<int64_t>(utcTime())) + "}",
        secretHex);

    auto result = verifier.verify("Bearer " + jwt);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(result.error, JwtError::UnsupportedAlgorithm);
}

BOOST_AUTO_TEST_CASE(testJwtVerifierInvalidSignature)
{
    auto secretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    auto secretFile = writeSecretFile(secretHex);

    auto config = std::make_shared<JwtConfig>();
    config->setEnableJWT(true);
    config->setSecretFile(secretFile);
    config->setAllowedAlgorithms("HS256");

    JwtVerifier verifier(config);
    auto jwt = buildJwt(R"({"alg":"HS256","typ":"JWT"})",
        std::string("{\"iat\":") + std::to_string(static_cast<int64_t>(utcTime())) + "}",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto result = verifier.verify("Bearer " + jwt);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(result.error, JwtError::InvalidSignature);
}

BOOST_AUTO_TEST_CASE(testJwtVerifierExpiredIat)
{
    auto secretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    auto secretFile = writeSecretFile(secretHex);

    auto config = std::make_shared<JwtConfig>();
    config->setEnableJWT(true);
    config->setSecretFile(secretFile);
    config->setClockSkewSecs(1);
    config->setAllowedAlgorithms("HS256");

    JwtVerifier verifier(config);
    auto jwt = buildJwt(R"({"alg":"HS256","typ":"JWT"})",
        R"({"iat":1})", secretHex);

    auto result = verifier.verify("Bearer " + jwt);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(result.error, JwtError::InvalidIssuedAt);
}

BOOST_AUTO_TEST_SUITE_END()
