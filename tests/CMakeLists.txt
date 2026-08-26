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

# test_version_policy reads CMakeLists.txt and the CI workflow, so it needs the
# repository root as an absolute path rather than a guess at the working directory
# ctest happens to use.
axiam_add_test(test_version_policy test_version_policy.c)
target_compile_definitions(test_version_policy
    PRIVATE AXIAM_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/..")
axiam_add_test(test_sensitive test_sensitive.c)
axiam_add_test(test_error test_error.c)
axiam_add_test(test_client_auth test_client_auth.c)
axiam_add_test(test_client_failing_transport test_client_failing_transport.c)
axiam_add_test(test_authz test_authz.c)
axiam_add_test(test_singleflight test_singleflight.c)
axiam_add_test(test_refresh_org test_refresh_org.c)
axiam_add_test(test_integration_curl test_integration_curl.c)
axiam_add_test(test_webhook test_webhook.c)
axiam_add_test(test_uma test_uma.c)
axiam_add_test(test_uma_branches test_uma_branches.c)

# ---- §23 OPAQUE ----------------------------------------------------------
#
# A REAL shared library exporting the twelve libaxiam_opaque_ffi symbols, so
# src/opaque.c's dlopen()/dlsym() resolution is exercised against a genuine
# dynamic object rather than jumped over. It performs no cryptography — its
# whole job is to be a library that loads. MODULE rather than SHARED because
# nothing links it; it is only ever dlopen()ed.
add_library(axiam_opaque_stub MODULE ${CMAKE_CURRENT_SOURCE_DIR}/opaque_stub.c)
set_target_properties(axiam_opaque_stub PROPERTIES PREFIX "lib")

# The same source with one export renamed: a library that loads and is missing
# a symbol, which the loader must refuse rather than half-adopt.
add_library(axiam_opaque_stub_incomplete MODULE ${CMAKE_CURRENT_SOURCE_DIR}/opaque_stub.c)
target_compile_definitions(axiam_opaque_stub_incomplete PRIVATE AXIAM_OPAQUE_STUB_INCOMPLETE)
set_target_properties(axiam_opaque_stub_incomplete PROPERTIES PREFIX "lib")

# ---- §23 OPAQUE: the binding and the protocol refusals.
# Reaches into internal.h for the native-vtable seam. §23.1 forbids this SDK
# from implementing OPAQUE, so there is no cryptography to test and no
# cross-language vector suite to run — what these cover is everything above the
# ABI, driven by a fake vtable that records frees and outstanding handles.
axiam_add_test(test_opaque_binding test_opaque_binding.c)
axiam_add_test(test_opaque_login test_opaque_login.c)

# The stub paths reach the binding test as compile definitions rather than
# argv, so the suite stays runnable by `ctest` with no arguments.
add_dependencies(test_opaque_binding axiam_opaque_stub axiam_opaque_stub_incomplete)
target_compile_definitions(test_opaque_binding PRIVATE
    AXIAM_OPAQUE_STUB_PATH="$<TARGET_FILE:axiam_opaque_stub>"
    AXIAM_OPAQUE_STUB_INCOMPLETE_PATH="$<TARGET_FILE:axiam_opaque_stub_incomplete>")

# ---- D5: §16 retry, §17 decision memo, §18 close(), §19 telemetry.
# Reaches into internal.h for the injected PRNG / injected sleep seams §16.7
# requires; the assertions themselves go through the public check_access
# surface and count requests on the wire.
axiam_add_test(test_d5_conformance test_d5_conformance.c)

# ---- C2 branch-coverage depth (round 2) ----
axiam_add_test(test_client_branches test_client_branches.c)
axiam_add_test(test_client_null_args test_client_null_args.c)
axiam_add_test(test_util_branches test_util_branches.c)
axiam_add_test(test_json_build test_json_build.c)

# Crypto-dependent tests link the JWT fixture.
axiam_add_test(test_rule9_binding test_rule9_binding.c)

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

# SEC-071: strict claim validation (exp / nbf / tenant binding) in the local
# verification path both guards and axiam_jwt_verify share.
add_executable(test_jwt_claims test_jwt_claims.c)
target_include_directories(test_jwt_claims PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_jwt_claims PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_jwt_claims PRIVATE --coverage)
endif()
add_test(NAME test_jwt_claims COMMAND test_jwt_claims)

# §11 rule 9 decision reason codes. Links the JWT fixture because the second
# half of the clause is about the guard, which verifies a real token.
add_executable(test_reason_code test_reason_code.c)
target_include_directories(test_reason_code PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_reason_code PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_reason_code PRIVATE --coverage)
endif()
add_test(NAME test_reason_code COMMAND test_reason_code)

# The §20.3 emit half wired into the §11 guard (axiam_require_access_uma).
add_executable(test_uma_challenge test_uma_challenge.c)
target_include_directories(test_uma_challenge PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_uma_challenge PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_uma_challenge PRIVATE --coverage)
endif()
add_test(NAME test_uma_challenge COMMAND test_uma_challenge)

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

# ---- §12 OIDC relying party, §12.7 logout, §14 device grant, §15 token
# exchange (the contract-1.11 port; see CONTRACT.md §12.6).
#
# test_oidc and the grant suites use a scriptable fake transport and assert on
# REQUEST COUNTS, in the spirit §16.7 states outright: a tested surface nobody
# calls is worse than an absent one.
axiam_add_test(test_oidc test_oidc.c)

# The ID-token suites need real EdDSA signatures, so they link the JWT fixture.
add_executable(test_oidc_idtoken test_oidc_idtoken.c)
target_include_directories(test_oidc_idtoken PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_oidc_idtoken PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_oidc_idtoken PRIVATE --coverage)
endif()
add_test(NAME test_oidc_idtoken COMMAND test_oidc_idtoken)

add_executable(test_oidc_logout test_oidc_logout.c)
target_include_directories(test_oidc_logout PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_oidc_logout PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_oidc_logout PRIVATE --coverage)
endif()
add_test(NAME test_oidc_logout COMMAND test_oidc_logout)

axiam_add_test(test_oidc_grants test_oidc_grants.c)

# §12.1 / §9 rule 2: oidc_refresh coalesces concurrent redemptions of one
# rotating refresh token. Asserted by counting wire calls under N threads.
add_executable(test_oidc_singleflight test_oidc_singleflight.c)
target_include_directories(test_oidc_singleflight PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_oidc_singleflight PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_oidc_singleflight PRIVATE --coverage)
endif()
add_test(NAME test_oidc_singleflight COMMAND test_oidc_singleflight)

# ---- C2 branch-coverage depth: the §12/§12.7/§14/§15 refusal paths.
axiam_add_test(test_oidc_branches test_oidc_branches.c)

# The other side of every optional-field branch: the shapes a real server sends
# that the happy-path suites never produce.
add_executable(test_oidc_shapes test_oidc_shapes.c)
target_include_directories(test_oidc_shapes PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_oidc_shapes PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_oidc_shapes PRIVATE --coverage)
endif()
add_test(NAME test_oidc_shapes COMMAND test_oidc_shapes)

# Wire-level oddities in the shared request builder, plus the discovery failure
# every one of the nine operations has to surface rather than proceed past.
axiam_add_test(test_oidc_wire test_oidc_wire.c)

# ---- Allocation-failure guards, across src/ ----
#
# Wraps malloc/calloc/realloc at link time (GNU ld --wrap) so tests can make
# the Nth allocation in a call graph fail on demand and assert the guarded
# code reports failure instead of crashing. Scoped to this ONE executable —
# --wrap only rewrites symbol references resolved in this link, so every
# other test binary keeps calling the real allocator untouched.
add_executable(test_alloc_failures test_alloc_failures.c)
target_include_directories(test_alloc_failures PRIVATE ${AXIAM_TEST_INCLUDES})
# axiam_jwtfix: the §12.4 / §12.7.3 sweeps drive a REAL signature verification,
# because the "payload verified but its buffer could not be allocated" arms in
# src/jwks.c and src/oidc_logout.c sit downstream of a successful verify and are
# unreachable with an unsigned fixture.
target_link_libraries(test_alloc_failures PRIVATE ${AXIAM_TEST_LINK} axiam_jwtfix)
target_link_options(test_alloc_failures PRIVATE
    -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc)
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_alloc_failures PRIVATE --coverage)
endif()
add_test(NAME test_alloc_failures COMMAND test_alloc_failures)

# ---- §24 WebAuthn, §25 account lifecycle, §26 PAR (contract 1.28) ----
#
# All three are wire-shape suites: what §24.0 is about is that the server's
# options and the authenticator's response cross this SDK unchanged, and the
# only way to assert that is to look at the bytes that went out. test_account
# additionally counts requests, because §25.2 rule 3 ("mfa_enroll does NOT clear
# the decision memo") has no other observable.
axiam_add_test(test_webauthn test_webauthn.c)
axiam_add_test(test_account test_account.c)
axiam_add_test(test_oidc_par test_oidc_par.c)

# ---- §22 reactor protocol core + §8b rules 1–5 (contract 1.28) ----
#
# Run against the COMMITTED §22.13 reference vectors — generated by the server's
# own sign path, so a byte out of place in the canonical form is caught against a
# number the server computed rather than against this implementation's own
# opinion. The vectors travel with the repo so the suite needs no broker, no
# server and no network.
add_executable(test_reactor test_reactor.c)
target_include_directories(test_reactor PRIVATE ${AXIAM_TEST_INCLUDES})
target_link_libraries(test_reactor PRIVATE ${AXIAM_TEST_LINK})
target_compile_definitions(test_reactor PRIVATE
    AXIAM_REACTOR_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/reactor_v2_reference_vectors.json")
if(AXIAM_ENABLE_COVERAGE)
    target_link_options(test_reactor PRIVATE --coverage)
endif()
add_test(NAME test_reactor COMMAND test_reactor)

# CONTRACT.md §27 management API. management_test_util.c is the shared rig: the fake
# transport sits at the BOTTOM of the real client, so a §27.8 violation (an operation
# opening its own connection) fails these rather than passing them.
axiam_add_test(test_management_generated test_management_generated.c management_test_util.c)

