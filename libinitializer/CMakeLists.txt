find_package(Boost REQUIRED program_options)
find_package(jsoncpp CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)

# BlsVerifier paths (used by init and pbft_init)
set(BLS_ROOT "${CMAKE_SOURCE_DIR}/bcos-BLS/deps/bls")
set(BLSV_SRC "${CMAKE_SOURCE_DIR}/bcos-BLS/bls-verifier/src")

# --- External-use targets: referenced outside libinitializer, must remain separate ---

# command: used by fisco-bcos-air, tars RpcService/GatewayService/ExecutorService/SchedulerService/NodeService
add_library(command CommandHelper.cpp)
target_link_libraries(command PUBLIC bcos-framework Boost::program_options)
add_dependencies(command BuildInfo.h)

# protocol_init: used by tars services and lightnode
add_library(protocol_init ProtocolInitializer.cpp Common.cpp)
target_link_libraries(protocol_init PUBLIC
                     bcos-crypto tool protocol-tars security)

# pbft_init: used by fisco-bcos-air, NodeService, storage-tool, archive-tool, hsm-tool
add_library(pbft_init PBFTInitializer.cpp ProPBFTInitializer.cpp)
target_link_libraries(pbft_init PUBLIC protocol_init ledger tool sealer rpbft pbft sync storage)
# BlsVerifier include paths (used by sealer and BlockValidator)
target_include_directories(pbft_init PUBLIC
    ${BLS_ROOT}/mcl/include
    ${BLS_ROOT}/include
    ${BLSV_SRC}
    ${CMAKE_SOURCE_DIR}/bcos-BLS
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(pbft_init PUBLIC
    ${BLS_ROOT}/lib/libbls384_256.a
    ${BLS_ROOT}/mcl/lib/libmcl.a
)
target_compile_definitions(pbft_init PUBLIC MCLBN_FP_UNIT_SIZE=6 MCLBN_FR_UNIT_SIZE=4)
set_target_properties(pbft_init PROPERTIES UNITY_BUILD "ON")
add_dependencies(pbft_init BuildInfo.h)
if(WITH_LEDGER_ELECTION)
    target_link_libraries(pbft_init PUBLIC leader_election)
endif()

# --- init: merged from front_init, txpool_init, mempool_init, ledger_init, baseline_init, lightnodeinit ---
# These intermediate targets had no external consumers and are now folded directly into init.
add_library(init
    Initializer.cpp AuthInitializer.cpp
    FrontServiceInitializer.cpp
    TxPoolInitializer.cpp
    MemPoolInitializer.cpp
    LedgerInitializer.cpp
    GlobalStateStorageInitializer.cpp MultiVersionScheduler.cpp
)
target_link_libraries(init PUBLIC
    protocol_init
    tool front
    txpool
    mempool
    engine
    ledger
    transaction-scheduler transaction-executor
    scheduler storage executor rpc
    bcos-boostssl
    tomlplusplus::tomlplusplus
)

# BlsVerifier for million-node BLS signature verification
target_sources(init PRIVATE ${BLSV_SRC}/BlsVerifier.cpp)
target_include_directories(init PUBLIC
    ${BLS_ROOT}/mcl/include
    ${BLS_ROOT}/include
    ${BLSV_SRC}
    ${CMAKE_SOURCE_DIR}/bcos-BLS
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(init PUBLIC
    ${BLS_ROOT}/lib/libbls384_256.a
    ${BLS_ROOT}/mcl/lib/libmcl.a
)
target_compile_definitions(init PUBLIC MCLBN_FP_UNIT_SIZE=6 MCLBN_FR_UNIT_SIZE=4)
if(WITH_LEDGER_ELECTION)
    target_link_libraries(init PUBLIC leader_election)
endif()
if(WITH_LIGHTNODE)
    target_sources(init PRIVATE LightNodeInitializer.cpp LightNodeInitializer.h)
    target_link_libraries(init PUBLIC bcos-lightnode bcos-concepts)
endif()
set_target_properties(init PROPERTIES UNITY_BUILD "ON")
add_dependencies(init BuildInfo.h)