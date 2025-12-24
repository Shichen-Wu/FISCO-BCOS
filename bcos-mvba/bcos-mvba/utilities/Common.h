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
 * @file Common.h
 * @author: yujiechen
 * @date 2024-12-15
 */
#pragma once
#include <bcos-framework/Common.h>
#include <bcos-utilities/Exceptions.h>
#include <stdint.h>

#define MVBA_LOG(LEVEL) BCOS_LOG(LEVEL) << LOG_BADGE("CONSENSUS") << LOG_BADGE("MVBA")
#define MVBA_STORAGE_LOG(LEVEL) \
    BCOS_LOG(LEVEL) << LOG_BADGE("CONSENSUS") << LOG_BADGE("MVBA") << LOG_BADGE("STORAGE")

namespace bcos::consensus
{
enum MVBAPacketType : uint32_t
{
    ActivePacket = 0x10,
    ActiveEchoPacket = 0x11,
    LockPacket = 0x12,
    LockEchoPacket = 0x13,
    FinishPacket = 0x14,
    NotifyFinishedPacket = 0x15,
    PrevotePacket = 0x16,
    VotePacket = 0x17,
};

DERIVE_BCOS_EXCEPTION(UnknownMVBAMsgType);
DERIVE_BCOS_EXCEPTION(InitMVBAException);
}  // namespace bcos::consensus