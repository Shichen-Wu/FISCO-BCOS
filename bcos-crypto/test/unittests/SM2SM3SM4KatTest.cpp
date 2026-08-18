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
 * @brief Known-answer tests (KAT) for the Chinese commercial cryptography
 *        algorithms SM3 (GM/T 0004-2012), SM4 (GM/T 0002-2012) and
 *        SM2 (GM/T 0003-2012) against the official standard test vectors.
 * @file SM2SM3SM4KatTest.cpp
 */

#include <bcos-crypto/encrypt/SM4Crypto.h>
#include <bcos-crypto/hash/SM3.h>
#include <bcos-crypto/signature/key/KeyImpl.h>
#include <bcos-crypto/signature/sm2.h>
#include <bcos-crypto/signature/sm2/SM2Crypto.h>
#include <bcos-utilities/DataConvertUtility.h>
#include <bcos-utilities/testutils/TestPromptFixture.h>
#include <boost/test/unit_test.hpp>

using namespace bcos;
using namespace bcos::crypto;

namespace bcos::test
{
BOOST_FIXTURE_TEST_SUITE(SM2SM3SM4KatTest, TestPromptFixture)

// GM/T 0004-2012 Appendix A test vectors for SM3.
BOOST_AUTO_TEST_CASE(testSM3KnownAnswer)
{
    auto sm3 = std::make_shared<SM3>();

    // A.1: SM3("abc").
    std::string abc = "abc";
    BOOST_CHECK_EQUAL(sm3->hash(bytesConstRef(abc)).hex(),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    // A.2: SM3 of the 64-byte message "abcd" repeated 16 times.
    std::string abcd64 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    BOOST_CHECK_EQUAL(sm3->hash(bytesConstRef(abcd64)).hex(),
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
}

// GM/T 0002-2012 Appendix A.1: single-block SM4 encryption/decryption.
// The WeDPR SM4 backend runs in CBC mode with PKCS7 padding; with a zero IV the
// first ciphertext block equals the raw SM4 block cipher output, which is what
// the standard vector specifies.
BOOST_AUTO_TEST_CASE(testSM4KnownAnswer)
{
    SM4Crypto sm4;
    bytes key = fromHex("0123456789abcdeffedcba9876543210");
    bytes plain = fromHex("0123456789abcdeffedcba9876543210");
    bytes iv(16, 0);

    auto cipher = sm4.symmetricEncrypt(
        plain.data(), plain.size(), key.data(), key.size(), iv.data(), iv.size());
    // The ciphertext is padded to two blocks; only the first block is the raw
    // SM4 encryption of the standard plaintext.
    bytes firstBlock(cipher->begin(), cipher->begin() + 16);
    BOOST_CHECK_EQUAL(toHex(firstBlock), "681edf34d206965e86b3e94f536e4246");

    // Decryption must round-trip back to the original 16-byte plaintext.
    auto decrypted = sm4.symmetricDecrypt(
        cipher->data(), cipher->size(), key.data(), key.size(), iv.data(), iv.size());
    BOOST_CHECK_EQUAL(toHex(*decrypted), "0123456789abcdeffedcba9876543210");
}

// GM/T 0002-2012 Appendix A.2: iteratively encrypt the plaintext one million
// times; the final output must match the standard vector.
BOOST_AUTO_TEST_CASE(testSM4KnownAnswerOneMillionIterations)
{
    SM4Crypto sm4;
    bytes key = fromHex("0123456789abcdeffedcba9876543210");
    bytes block = fromHex("0123456789abcdeffedcba9876543210");
    bytes iv(16, 0);

    for (int i = 0; i < 1000000; ++i)
    {
        auto cipher = sm4.symmetricEncrypt(
            block.data(), block.size(), key.data(), key.size(), iv.data(), iv.size());
        // Keep only the first block, i.e. the raw SM4 output of the previous block.
        block.assign(cipher->begin(), cipher->begin() + 16);
    }
    BOOST_CHECK_EQUAL(toHex(block), "595298c7c6fd271f0402f804c33d3f66");
}

// GM/T 0003.5-2012 Appendix B: derive the public key from the example private
// key on the sm2p256v1 recommended curve.
BOOST_AUTO_TEST_CASE(testSM2PublicKeyDerivation)
{
    auto secret = std::make_shared<KeyImpl>(
        fromHex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"));
    auto publicKey = sm2PriToPub(secret);
    BOOST_CHECK_EQUAL(publicKey->hex(),
        "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
        "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13");
}

// GM/T 0003.2-2012: verify a signature over the sm2p256v1 recommended curve.
// The backend computes e = SM3(ZA || msg) internally with the fixed user id
// "1234567812345678" (libsm's SM2_STANDARD_ID). The signature below was
// produced independently: ZA and e were computed with OpenSSL SM3, and e was
// then signed with OpenSSL SM2, so verify() must recover the same e and accept it.
BOOST_AUTO_TEST_CASE(testSM2SignatureKnownAnswer)
{
    SM2Crypto sm2Crypto;
    auto secret = std::make_shared<KeyImpl>(
        fromHex("69daa49028dfd6ca7845341ec059f8dcdf325eb9eed12412746a3eeb565d52a6"));
    auto publicKey = sm2PriToPub(secret);

    // Cross-check the derived public key (x || y) against the OpenSSL keypair.
    BOOST_CHECK_EQUAL(publicKey->hex(),
        "b899e0b2486b39aa848179c0386d70060bea1b5625ca2a849fbe318020519c1e"
        "a0616a0859c4526ea202f1e949517f0e15496d4b05e4d08ea193c6a9e1d03b4f");

    h256 message(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto signature = fromHex(
        "4a1f2139918b83ae66868162505b5e403c1498035aeb35b9096fa6c3fdc20213"
        "90ede8083c6bd8eafcef48a82c00ab4e1ad5d7b53082af9987faabea3a638f8a");

    bool result = sm2Crypto.verify(
        publicKey, message, bytesConstRef(signature.data(), signature.size()));
    BOOST_CHECK(result == true);

    // A tampered signature must fail verification.
    signature[0] ^= 0x01;
    result = sm2Crypto.verify(
        publicKey, message, bytesConstRef(signature.data(), signature.size()));
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_SUITE_END()
}  // namespace bcos::test
