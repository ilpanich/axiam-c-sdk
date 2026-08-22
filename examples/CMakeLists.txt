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
# CONTRACT.md §23: the OPAQUE (RFC 9807) exchange, which failures may fall back
# to axiam_login() and which must not, and the registration record the server
# cannot build for itself.
axiam_add_example(opaque_login)
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
# Contract 1.28: §24 WebAuthn (the wire operations plus §24.6a's JSON bridge —
# a C program has no authenticator, so there is no ceremony helper), §25 account
# lifecycle and MFA enrolment, and §26 pushed authorization requests.
axiam_add_example(webauthn_passkeys)
axiam_add_example(account_lifecycle)
axiam_add_example(par_login)
# CONTRACT.md §22 (contract 1.28): a reactor on the SDK's protocol core, with the
# §8b broker-URL guard and the §22.14 binding table. The transport is a skeleton
# — §22.11 defers the AMQP client and only the AMQP client.
axiam_add_example(reactor)
