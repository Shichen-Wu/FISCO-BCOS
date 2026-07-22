cmake_minimum_required(VERSION 3.16)
project(bls-verifier VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BLS_ROOT "${CMAKE_SOURCE_DIR}/../deps/bls" CACHE PATH "herumi/bls root")
set(MCL_DIR "${BLS_ROOT}/mcl")

# 库: BlsVerifier (供 FISCO-BCOS 链接)
add_library(blsverifier STATIC
    src/BlsVerifier.cpp
)
target_include_directories(blsverifier PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${MCL_DIR}/include
    ${BLS_ROOT}/include
)
target_link_libraries(blsverifier PUBLIC
    ${BLS_ROOT}/lib/libbls384_256.a
    ${MCL_DIR}/lib/libmcl.a
    pthread
)
target_compile_options(blsverifier PRIVATE -Wall -Wextra -O2)

# 测试
add_executable(test_blsverifier test/main.cpp)
target_include_directories(test_blsverifier PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${MCL_DIR}/include
    ${BLS_ROOT}/include
)
target_link_libraries(test_blsverifier PRIVATE
    blsverifier
    ${BLS_ROOT}/lib/libbls384_256.a
    ${MCL_DIR}/lib/libmcl.a
    pthread
)
target_compile_options(test_blsverifier PRIVATE -Wall -Wextra -O2)

add_definitions(-DMCLBN_FP_UNIT_SIZE=6)
add_definitions(-DMCLBN_FR_UNIT_SIZE=4)
