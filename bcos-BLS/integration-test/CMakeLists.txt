cmake_minimum_required(VERSION 3.16)
project(integration-test VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BLS_ROOT "${CMAKE_SOURCE_DIR}/../deps/bls" CACHE PATH "herumi/bls root")
set(MCL_INCLUDE_DIR "${BLS_ROOT}/mcl/include")
set(BLS_INCLUDE_DIR "${BLS_ROOT}/include")
set(BLS_STATIC_LIB "${BLS_ROOT}/lib/libbls384_256.a")
set(MCL_STATIC_LIB "${BLS_ROOT}/mcl/lib/libmcl.a")

set(BLSV_DIR "${CMAKE_SOURCE_DIR}/../bls-verifier")

add_executable(integration_test src/main.cpp ${BLSV_DIR}/src/BlsVerifier.cpp)

add_executable(test_verify src/test_verify.cpp ${BLSV_DIR}/src/BlsVerifier.cpp)

add_executable(test_rpc src/test_rpc.cpp ${BLSV_DIR}/src/BlsVerifier.cpp)

add_executable(bench_single src/bench_single.cpp)
add_executable(bench_leader src/bench_leader.cpp)

set(COMMON_DEPS ${BLS_STATIC_LIB} ${MCL_STATIC_LIB} pthread)

target_include_directories(integration_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src ${MCL_INCLUDE_DIR} ${BLS_INCLUDE_DIR}
    ${BLSV_DIR}/src)
target_include_directories(test_verify PRIVATE
    ${CMAKE_SOURCE_DIR}/src ${MCL_INCLUDE_DIR} ${BLS_INCLUDE_DIR}
    ${BLSV_DIR}/src)
target_include_directories(test_rpc PRIVATE
    ${CMAKE_SOURCE_DIR}/src ${MCL_INCLUDE_DIR} ${BLS_INCLUDE_DIR}
    ${BLSV_DIR}/src)
target_include_directories(bench_single PRIVATE
    ${CMAKE_SOURCE_DIR}/src ${MCL_INCLUDE_DIR} ${BLS_INCLUDE_DIR})
target_include_directories(bench_leader PRIVATE
    ${CMAKE_SOURCE_DIR}/src ${MCL_INCLUDE_DIR} ${BLS_INCLUDE_DIR})

target_link_libraries(integration_test PRIVATE ${COMMON_DEPS})
target_link_libraries(test_verify PRIVATE ${COMMON_DEPS})
target_link_libraries(test_rpc PRIVATE ${COMMON_DEPS})
target_link_libraries(bench_single PRIVATE ${COMMON_DEPS})
target_link_libraries(bench_leader PRIVATE ${COMMON_DEPS})

target_compile_options(integration_test PRIVATE -Wall -Wextra -O2)
target_compile_options(test_verify PRIVATE -Wall -Wextra -O2)
target_compile_options(test_rpc PRIVATE -Wall -Wextra -O2)
target_compile_options(bench_single PRIVATE -Wall -Wextra -O2)
target_compile_options(bench_leader PRIVATE -Wall -Wextra -O2)

add_definitions(-DMCLBN_FP_UNIT_SIZE=6)
add_definitions(-DMCLBN_FR_UNIT_SIZE=4)
