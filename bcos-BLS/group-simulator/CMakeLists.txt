cmake_minimum_required(VERSION 3.16)
project(group-simulator VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# BLS 库配置 (herumi/bls)
# ============================================================================
# 安装方法:
#   git clone --recursive https://github.com/herumi/bls
#   cd bls
#   make -C mcl lib/libmcl.a
#   make lib/libbls384_256.a
#
# 设置以下路径:
#   - BLS_ROOT: herumi/bls 仓库根目录
# ============================================================================
set(BLS_ROOT "${CMAKE_SOURCE_DIR}/../deps/bls" CACHE PATH "herumi/bls root directory")

# mcl 头文件路径
set(MCL_INCLUDE_DIR "${BLS_ROOT}/mcl/include")
# bls 头文件路径
set(BLS_INCLUDE_DIR "${BLS_ROOT}/include")

# 静态库路径
set(MCL_LIB "${BLS_ROOT}/mcl/lib/libmcl.a")
set(BLS_LIB "${BLS_ROOT}/lib/libbls384_256.a")

# ============================================================================
# 源文件
# ============================================================================
set(SOURCES
    src/main.cpp
    src/common/config.cpp
    src/crypto/bls_wrapper.cpp
    src/dkg/polynomial.cpp
    src/dkg/dkg_node.cpp
    src/node/signer_node.cpp
    src/node/node_manager.cpp
    src/aggregator/aggregator.cpp
    src/aggregator/threshold.cpp
    src/network/simulator.cpp
)

set(HEADERS
    src/common/types.h
    src/common/config.h
    src/crypto/bls_wrapper.h
    src/dkg/polynomial.h
    src/dkg/dkg_node.h
    src/node/signer_node.h
    src/node/node_manager.h
    src/aggregator/aggregator.h
    src/aggregator/threshold.h
    src/network/simulator.h
)

# ============================================================================
# 可执行文件
# ============================================================================
add_executable(group_simulator ${SOURCES} ${HEADERS})

target_include_directories(group_simulator PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/../common
    ${MCL_INCLUDE_DIR}
    ${BLS_INCLUDE_DIR}
)

target_link_libraries(group_simulator PRIVATE
    ${BLS_LIB}
    ${MCL_LIB}
    pthread
)

# 编译选项
target_compile_options(group_simulator PRIVATE
    -Wall -Wextra -O2
)

# 不使用 BLS_ETH 模式，即默认模式: 公钥在G2，签名在G1 (小签名大公钥)
# 这与FISCO-BCOS的BN254预编译兼容方向一致
# BLS12-381: Fp=381bit→6 uint64, Fr=256bit→4 uint64
add_definitions(-DMCLBN_FP_UNIT_SIZE=6)
add_definitions(-DMCLBN_FR_UNIT_SIZE=4)
