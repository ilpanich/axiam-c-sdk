# ---- vendored Unity test framework ----
add_library(axiam_unity STATIC ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/unity/unity.c)
target_include_directories(axiam_unity PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/unity)

# Tests link against the static library variant plus internal src/third_party
# include paths (some tests reach into internal helpers).
set(AXIAM_TEST_LINK axiam_static axiam_unity OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
set(AXIAM_TEST_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/cjson
    ${CMAKE_CURRENT_SOURCE_DIR})

# A small JWT/JWKS fixture object shared by the crypto-dependent tests.
add_library(axiam_jwtfix STATIC ${CMAKE_CURRENT_SOURCE_DIR}/jwt_fixture.c)
target_include_directories(axiam_jwtfix PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(axiam_jwtfix PUBLIC OpenSSL::Crypto)

function(axiam_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${AXIAM_TEST_INCLUDES})
    target_link_libraries(${name} PRIVATE ${AXIAM_TEST_LINK})
    if(AXIAM_ENABLE_COVERAGE)
        target_link_options(${name} PRIVATE --coverage)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

axiam_add_test(test_config test_config.c)
axiam_add_test(test_sensitive test_sensitive.c)
axiam_add_test(test_error test_error.c)
axiam_add_test(test_client_auth test_client_auth.c)
axiam_add_test(test_authz test_authz.c)
axiam_add_test(test_singleflight test_singleflight.c)
axiam_add_test(test_integration_curl test_integration_curl.c)

# Crypto-dependent tests link the JWT fixture.
add_executable(test_jwks test_jwks.c)
target_include_directories(test_jwks PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_jwks PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_jwks PRIVATE --coverage)
endif()
add_test(NAME test_jwks COMMAND test_jwks)

add_executable(test_guard test_guard.c)
target_include_directories(test_guard PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_guard PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_guard PRIVATE --coverage)
endif()
add_test(NAME test_guard COMMAND test_guard)

# ---- mTLS PEM wiring test, gated on a runtime-generated PKI fixture ----
set(AXIAM_PKI_DIR ${CMAKE_CURRENT_BINARY_DIR}/pki)
add_test(NAME gen_pki
         COMMAND ${CMAKE_COMMAND} -E env sh
                 ${CMAKE_CURRENT_SOURCE_DIR}/gen_pki.sh ${AXIAM_PKI_DIR})
set_tests_properties(gen_pki PROPERTIES FIXTURES_SETUP AXIAM_PKI)

add_executable(test_mtls test_mtls.c)
target_include_directories(test_mtls PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_mtls PRIVATE ${AXIAM_TEST_LINK})
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_mtls PRIVATE --coverage)
endif()
add_test(NAME test_mtls COMMAND test_mtls ${AXIAM_PKI_DIR})
set_tests_properties(test_mtls PROPERTIES FIXTURES_REQUIRED AXIAM_PKI)
