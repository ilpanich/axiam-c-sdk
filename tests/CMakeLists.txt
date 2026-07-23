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
axiam_add_test(test_client_failing_transport test_client_failing_transport.c)
axiam_add_test(test_authz test_authz.c)
axiam_add_test(test_singleflight test_singleflight.c)
axiam_add_test(test_refresh_org test_refresh_org.c)
axiam_add_test(test_integration_curl test_integration_curl.c)

# ---- C2 branch-coverage depth (round 2) ----
axiam_add_test(test_client_branches test_client_branches.c)
axiam_add_test(test_client_null_args test_client_null_args.c)
axiam_add_test(test_util_branches test_util_branches.c)
axiam_add_test(test_json_build test_json_build.c)

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

# ---- C2 branch-coverage depth (round 2): crypto-dependent branch sweeps ----
add_executable(test_guard_branches test_guard_branches.c)
target_include_directories(test_guard_branches PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_guard_branches PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_guard_branches PRIVATE --coverage)
endif()
add_test(NAME test_guard_branches COMMAND test_guard_branches)

add_executable(test_jwks_branches test_jwks_branches.c)
target_include_directories(test_jwks_branches PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_jwks_branches PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_jwks_branches PRIVATE --coverage)
endif()
add_test(NAME test_jwks_branches COMMAND test_jwks_branches)

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

# ---- src/transport_curl.c real-transport sweep (GET, custom method, closed
# port CURLE_* failure, CA/mTLS blob wiring) — also needs the PKI fixture.
add_executable(test_transport_curl_extra test_transport_curl_extra.c)
target_include_directories(test_transport_curl_extra PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_transport_curl_extra PRIVATE ${AXIAM_TEST_LINK})
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_transport_curl_extra PRIVATE --coverage)
endif()
add_test(NAME test_transport_curl_extra COMMAND test_transport_curl_extra ${AXIAM_PKI_DIR})
set_tests_properties(test_transport_curl_extra PROPERTIES FIXTURES_REQUIRED AXIAM_PKI)

# ---- C3: real loopback TLS/mTLS handshake round-trip through the default
# libcurl transport (server-auth via CAINFO_BLOB + mTLS via SSLCERT/SSLKEY_BLOB).
# Uses an in-process OpenSSL SSL_accept server; needs the PKI fixture. Built the
# same way as test_mtls (raw add_executable) because the test binary takes the
# PKI directory as argv[1], which the axiam_add_test() helper cannot pass.
add_executable(test_tls_server test_tls_server.c)
target_include_directories(test_tls_server PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_tls_server PRIVATE ${AXIAM_TEST_LINK})
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_tls_server PRIVATE --coverage)
endif()
add_test(NAME test_tls_server COMMAND test_tls_server ${AXIAM_PKI_DIR})
set_tests_properties(test_tls_server PROPERTIES FIXTURES_REQUIRED AXIAM_PKI)
