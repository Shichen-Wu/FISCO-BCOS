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
 * @brief base64url helper for jwt
 * @file JwtBase64Url.cpp
 * @date 2026.05.19
 */

#include "JwtBase64Url.h"

namespace bcos::boostssl::jwt
{
std::string JwtBase64Url::encode(std::string_view _input)
{
    (void)_input;
    return {};
}

std::string JwtBase64Url::decode(std::string_view _input)
{
    (void)_input;
    return {};
}

bool JwtBase64Url::isBase64UrlChar(char _c)
{
    (void)_c;
    return true;
}

std::string JwtBase64Url::normalizePadding(std::string_view _input)
{
    (void)_input;
    return {};
}
}  // namespace bcos::boostssl::jwt
