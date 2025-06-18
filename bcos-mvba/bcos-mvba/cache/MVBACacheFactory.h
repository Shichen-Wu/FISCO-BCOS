/**
 *  Copyright (C) 2021 FISCO BCOS.
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
 * @brief factory for MVBACache
 * @file MVBACacheFactory.h
 * @author: yujiechen
 * @date 2021-06-01
 */
#pragma once
#include "MVBACache.h"
namespace bcos::consensus
{
class MVBACacheFactory
{
public:
    using Ptr = std::shared_ptr<MVBACacheFactory>;
    MVBACacheFactory() = default;
    virtual ~MVBACacheFactory() = default;

    virtual MVBACache::Ptr createMVBACache(PBFTConfig::Ptr _config,
        bcos::protocol::EpochIndexType _index)
    {
        auto cache = std::make_shared<MVBACache>(_config, _index);
        //cache->registerCommittedIndexNotify(_committedIndexNotifier);
        return cache;
    }
};
}  // namespace bcos::consensus