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
 * @file JwtBase64Url.h
 * @date 2026.05.19
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>

namespace bcos::boostssl::jwt
{
class JwtBase64Url
{
public:
    using Ptr = std::shared_ptr<JwtBase64Url>;

    static std::string encode(std::string_view input);
    static std::string decode(std::string_view input);

    static bool isBase64UrlChar(char c);
    static std::string normalizePadding(std::string_view input);
};
}  // namespace bcos::boostssl::jwt
