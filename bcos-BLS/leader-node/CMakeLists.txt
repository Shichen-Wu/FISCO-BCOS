cmake_minimum_required(VERSION 3.16)
project(leader-node VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# BLS 库配置 (herumi/bls, 与 group-simulator 共享)
# ============================================================================
set(BLS_ROOT "${CMAKE_SOURCE_DIR}/../deps/bls" CACHE PATH "herumi/bls root directory")
set(MCL_INCLUDE_DIR "${BLS_ROOT}/mcl/include")
set(BLS_INCLUDE_DIR "${BLS_ROOT}/include")
set(MCL_LIB "${BLS_ROOT}/mcl/lib/libmcl.a")
set(BLS_LIB "${BLS_ROOT}/lib/libbls384_256.a")

# ============================================================================
# 源文件
# ============================================================================
set(SOURCES
    src/main.cpp
    src/common/config.cpp
    src/crypto/bls_wrapper.cpp
    src/aggregation/bls_aggregator.cpp
    src/leader/signature_collector.cpp
    src/leader/leader_core.cpp
    src/contract/contract_client.cpp
    src/contract/abi_codec.cpp
)

set(HEADERS
    src/common/types.h
    src/common/config.h
    src/crypto/bls_wrapper.h
    src/aggregation/bls_aggregator.h
    src/leader/signature_collector.h
    src/leader/leader_core.h
    src/contract/contract_client.h
    src/contract/abi_codec.h
)

# ============================================================================
# 可执行文件
# ============================================================================
add_executable(leader_node ${SOURCES} ${HEADERS})

target_include_directories(leader_node PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/../common
    ${MCL_INCLUDE_DIR}
    ${BLS_INCLUDE_DIR}
)

target_link_libraries(leader_node PRIVATE
    ${BLS_LIB}
    ${MCL_LIB}
    pthread
)

target_compile_options(leader_node PRIVATE -Wall -Wextra -O2)

# BLS12-381: Fp=381bit→6 uint64, Fr=256bit→4 uint64
add_definitions(-DMCLBN_FP_UNIT_SIZE=6)
add_definitions(-DMCLBN_FR_UNIT_SIZE=4)
