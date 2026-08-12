# Self-contained example programs. Each links against the public `axiam::axiam`
# target (the shared library by default, or the static variant when
# AXIAM_BUILD_SHARED is OFF) and uses only the public headers under include/.
#
# Gated behind AXIAM_BUILD_EXAMPLES (see the top-level CMakeLists.txt), the same
# way the test suite is gated behind AXIAM_BUILD_TESTS.

function(axiam_add_example name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE axiam::axiam)
endfunction()

axiam_add_example(login_mfa)
axiam_add_example(rest_authz)
axiam_add_example(telemetry_hook)
# The §20.3 pair: a resource server that emits the WWW-Authenticate: UMA
# challenge, and a client that consumes it.
axiam_add_example(uma_resource_server)
axiam_add_example(uma_client)
# The contract-1.11 port (§12.6): the OIDC relying party, the device grant, and
# token exchange.
axiam_add_example(oidc_login)
axiam_add_example(device_login)
axiam_add_example(token_exchange)
