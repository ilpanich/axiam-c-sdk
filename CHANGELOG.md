# Changelog

All notable changes to the AXIAM C SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-release qualifier `-alpha9`).

## [Unreleased]

## [1.0.0-beta07] - 2026-08-30

### Changed

- Re-vendor AXIAM contract 1.36

- **Documented contract 1.36, which this SDK already vendors.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` were re-vendored from the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396) as part of the 1.0.0-beta06 release, whose note recorded
  only "no notable changes". That understated it — the contract moved in that
  release — and v1.0.0-beta06 is tagged, so the correction is recorded here
  rather than by editing a released section. No SDK code changed with the
  artifacts; the three entries below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  every request builds its headers through `tenant_header_value(c)` in
  `src/client.c`; no endpoint is special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's. §5 rule 2's
  *unconditional* `X-Tenant-ID` is deliberately **not** renamed, and the
  contract now carries a note saying why it must not be: it names the client's
  *constructor* tenant, so folding it into `X-Axiam-Tenant` would override the
  acting tenant on every request an organization-level principal made after a
  switch. Every existing §5 rule 2 send is left exactly as it was.

- **`openapi.json` gained `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  keeps `operation_count` at **155** — bootstrap is excluded on the §27.0
  boundary — so §27 code generation is unaffected and the generated surface is
  unchanged.

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35 (carrying 1.34) — principal tenant, tenant_scope, service-account RBAC

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been fanned
  out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds 155
  operations across 24 namespaces — 1.35 changed only its `spec_digest` — so the
  eight §27 operations below arrived with 1.34 and are new here regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight generated
  operations, with the `AssignRoleToServiceAccountRequest`,
  `RoleServiceAccountAssignment` and `AddServiceAccountMemberRequest` models they
  need. `axiam_roles_unassign_from_service_account()` takes the same optional
  `resource_id` query parameter as the user and group unassign calls: passing NULL
  removes the *global* grant specifically, not every grant of that role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `axiam_login_result_t` gains `principal_tenant_id`,
  `principal_tenant_slug`, `org_id`, `reachable_tenant_ids` and
  `reachable_tenant_ids_count` — appended LAST, so every existing designated or
  positional initializer still compiles and `{0}` still means "no claim".

  `principal_tenant_id` is filled from `tenant_id` when the server omits it.
  Absent means *equal*, not unknown: a server older than 1.34 cannot switch the
  acting tenant either, so the fallback is the only value the field could have
  had. Read `org_id` from the session instead of resolving a slug through
  `GET /api/v1/organizations`, which is `super-admin`-only and returns only the
  caller's own organization.

  `axiam_login_result_dispose()` releases all of them, `reachable_tenant_ids`
  entries included.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenant_scope` /
  `tenant_scope_count` appear on the three assignment request structs and on the
  assignment objects the read paths return. NULL means unrestricted, which is what
  every assignment written before the field existed already meant.

  `reachable_tenant_ids` pairs with it on the login result: a narrowed
  organization-level principal still reports `organization_level == 1`, so an
  application gating a tenant switcher on that flag alone offers tenants the
  server refuses at the header.

- **`axiam_opaque_enrollment_for_self()`** — see below.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the tenant
  the *account* lives in, not whichever tenant the client is currently pointed at,
  and a record sealed against the acting tenant is refused with "the OPAQUE session
  was issued for a different tenant".

  `axiam_opaque_enrollment()` had one behaviour for a function documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour; the new
  `axiam_opaque_enrollment_for_self()` seals against the principal tenant captured
  at login (naming it by id and sending no `tenant_slug`, which would otherwise
  out-vote the id server-side) and is what a self-service password change must
  call. It returns `AXIAM_ERR_NETWORK` before any login has completed, because
  there is nothing to seal against then and falling back to the acting tenant is
  the bug itself.

  The two collapse to the same request for every ordinary principal, so this only
  bit an organization-level account that had switched tenant.

- **`tenant_scope: []` no longer reaches the wire** (§5.2.3 rule 1, refused with
  `400`). C's optional-array guard is `if (value->field)`, which a pointer to a
  list that filtered down to nothing passes — and that is exactly the shape "no
  tenants named" produces. `scripts/gen_management.py` now emits
  `if (value->tenant_scope && value->tenant_scope_count > 0)` for that one field.

  The allowlist is one field wide on purpose: elsewhere an empty array is
  meaningful — a replacement body clearing a list — and `test_contract_135` pins
  that an `UpdateWebhookRequest` with `events_count == 0` still sends
  `"events":[]`.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but the
AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin UI,
and the `openapi.json` vendored alongside that contract. The server never reads
`X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly acts on
the principal's own tenant instead. The discrepancy has been reported upstream; this
SDK's existing `X-Tenant-ID` sends are left as they are, being out of scope for a
contract re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Pin actions by digest, attest the release tarball, re-vendor contract 1.33

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this SDK reaches it through the ordinary config, and the
  "no tenant" refusal now says so.

  Prefer naming it over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Reject a blank tenant_slug or org_slug instead of sending it as ""

- **`axiam_client_config_validate` now rejects a blank `tenant_slug` or
  `org_slug`** (CONTRACT.md §5, §5.1, §5.2.1 rule 2), whitespace included. A
  **NULL** pointer stays accepted — that is what "not named" looks like, and it
  is the difference between an unset optional and a blank one.

  The old check tested `tenant_slug[0] != '\0'` only as part of "is a tenant
  present at all", so a config carrying a blank slug **alongside a valid
  `tenant_id`** validated, and the empty slug rode along into the login body.

  An SDK MUST NOT send an empty-string slug. Nothing can carry one, so the
  server resolves nothing — and on `/auth/opaque/login/start` it fails on the
  workspace *before* the tenant's OPAQUE mode is read, so the `404` of §23.4
  rule 10 never arrives, this SDK has no fallback to take, and sign-in fails
  even against a tenant with OPAQUE **disabled**.

## [1.0.0-beta02] - 2026-08-28

### Added

- **CONTRACT.md contract 1.31 — list search, the truthful resend, and organization scope.**
  The vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` are re-synced
  from `axiam@main`, and four behaviours follow from them.

  **`axiam_mgmt_page_req_t` gained a third member, `search` (§27.4 rule 4).** All twenty
  paginated operations accept an optional free-text term, matched case-insensitively by
  the **server** against the identifying fields of whatever is being listed — a name or
  username, plus the record id, so a UUID pasted out of a log line finds its row. The
  page's `total` then counts *matches*, not rows.

  It lives beside `offset` and `limit` rather than becoming an extra argument on twenty
  operations, and that is what makes `axiam_mgmt_page_next()` carry it across a whole
  walk. An argument has nowhere to live between one request and the next, so a walk built
  on one would return the matches followed by the unfiltered tail. The member is
  **borrowed, never owned**: nothing copies it and nothing frees it, so it must outlive
  every request derived from it. Appended last, so every existing `{ 0, 50 }` initializer
  still compiles and still means "unfiltered".

  `NULL`, `""` and `"   "` are the same request: no `search` parameter at all. The new
  `axiam_mgmt_page_search()` is that normalisation, exposed because it is the one piece a
  caller can observe going wrong. The term is never truncated — the server caps its
  length, and a client-side cap the server would not have applied is a silently different
  query.

- **`axiam_resend_own_verification()` (§25.1, §25.7).** `POST
  /api/v1/users/me/resend-verification`, session-authenticated, taking **no address** —
  the server reads it off the caller's own record, and the signature deliberately offers
  no way to name a different one. Refused client-side, with no wire call, when there is no
  session.

  It does not replace `axiam_resend_verification()`, and neither is routed to the other.
  The unauthenticated one takes an address from an anonymous caller, so it must answer
  identically whether the address exists, is already verified, or is rate-limited:
  anything else is an oracle for which addresses have accounts. This one is asked by a
  caller already signed in to the account it is asking about, so it tells the truth — a
  `409` maps to `AXIAM_ERR_AUTHZ` and a `429` to `AXIAM_ERR_NETWORK`, and this SDK does
  **not** fall back to the public endpoint on either (§25.7 rule 2). That fallback would
  turn both failures back into a silent success and restore the bug this operation exists
  to fix, with an extra round trip. `AXIAM_OK` means the mail was *enqueued*, not
  delivered.

- **`axiam_login_result_t::organization_level` (§5.2).** `1` when the account that just
  signed in is an organization-level principal — one whose record lives in its
  organization's reserved tenant, so its global grants apply in every tenant there and it
  can act on a different one by sending a different `X-Tenant-ID`, with no re-login.

  An ordinary tenant principal is a principal of exactly one tenant; the same header
  change produces a `403` for it. The flag is what an application checks *before* offering
  a tenant switch, rather than discovering the answer from a failed request. It is derived
  from the response and never asserted: never sent, and `0` when absent or when the value
  is anything but the JSON literal `true` — which is what a server older than contract
  1.31 answers, and the safe direction. Appended **last** to the struct, so every existing
  initializer still compiles and `{0}` still means "no claim".

- **Three §27.11 model additions**, regenerated: `axiam_mgmt_tenant_t::kind` (with the new
  `axiam_mgmt_tenant_kind_t` enum), `axiam_mgmt_mtls_trust_anchor_response_t::
  trusted_anchors` (with its `has_` flag — absent is *not* zero: "the listener trusts no
  CAs" and "there was no listener to ask" are different operational states), and
  `axiam_mgmt_certificate_t::bound_service_account_id`.

  That last one is a **projection**, not a member of the certificate: the server resolves
  it for a whole page in one query, so `axiam_certificates_list()` populates it and
  `axiam_certificates_get()` leaves it `NULL`, with no second request to fill it in
  (§27.11 rule 4). `scripts/gen_management.py` learned to read the registry's
  `response.projected_fields` and fold such a field onto its base struct as optional — the
  server expresses a projection as an `allOf` of the named base and an anonymous object,
  and a generator that reads only for a `$ref` sees a response with no element name at
  all.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#49)

- Contract 1.31: list search, the truthful resend, organization scope (#48)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#47)

- Name the C operations the way CONTRACT.md §27.3 spells them

- Add §27 tests, manifest layer, examples, CI drift-check and docs

- Add the CONTRACT.md §27 management surface to the C SDK

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated enums are now open, and `_from_wire()`'s contract is inverted (§27.11
  rule 1).** Every generated enum gained a trailing `_UNKNOWN` constant, and `_from_wire()`
  now returns `0` and yields it for a value this SDK's copy of the spec does not list,
  where it used to return `-1`.

  Reporting a failure there made the caller drop the whole record — or, through a page
  parse, the whole page — over one field it did not ask about. That is the failure §27.11
  rule 1 exists to prevent, and it is why this is a fix rather than a loosening.

  What the old behaviour was protecting is unchanged: an unrecognised value is still never
  read as one of the **known** constants. `_UNKNOWN` is appended **last**, so it is not the
  zero value a `calloc`'d struct starts at, and `_to_wire()` spells it as the empty string
  — which no server value is, so carrying an unrecognised value back into an update is
  refused by the server rather than written as a spelling it never used. `_from_wire()`
  still returns `-1` for a NULL argument, which is a caller error rather than a server one.

  **A `switch` over one of these enums should gain an `_UNKNOWN` arm.** The existing
  `test_an_unknown_enum_value_is_refused` was rewritten rather than removed, under a name
  that records the inversion, and it kept the two assertions the old one was really
  making.

- **CONTRACT.md §27 — the management API.** 146 operations across 24 namespaces as
  FLAT SYMBOLS (`axiam_users_list()`), which is §27.3's accommodation for languages
  without a value that carries both a receiver and a method table. Generated by
  `scripts/gen_management.py` from the vendored `management-registry.json` and
  `openapi.json`; the output is committed so building needs no Python, and a new CI job
  re-runs the generator with `--check` on every pull request.

  All 146 operations funnel through one `axiam_mgmt_send()` built on
  `axiam_client_send_raw()` — the same seam every other REST call uses — so §3 CSRF, the
  §4 cookie jar, the §5 tenant header and §6 TLS apply by construction (§27.8).

- **`axiam_mgmt_error_class()`** for §27.4 rule 7. A function rather than a struct member
  because `axiam_error_t` is stack-allocated by callers and adding a member would be an
  ABI break. `kind` follows rule 7's parent column: `404` and `409` to `AXIAM_ERR_AUTHZ`,
  `400` and `422` to `AXIAM_ERR_NETWORK`.

- **`axiam/management_manifest.h`** — the §27.6/§27.7 declarative layer: `axiam_mgmt_plan()`
  (which writes nothing) and `axiam_mgmt_apply()` (which stops at the first failure and
  does not roll back, reporting what landed so an operator can resume).

- Three examples: `management_basics`, `management_manifest`, and
  `device_mtls_provisioning` — an operator/device split that provisions an IoT device
  with a `Device` certificate and authenticates it over §6.1 mutual TLS.

- `axiam_error_kind_from_http_status()` is **unchanged**, deliberately. §27's `404`
  mapping differs from it, and that divergence is scoped to the management transport
  rather than imposed on every call in the SDK.

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Compile and test against C23 alongside the C11 floor (#43)

- **C23 is now a built and tested standard, on both gcc and clang.** The CI
  matrix gains a standard axis: it was two compilers at one standard, so the
  compiler axis was covered twice and the language axis not at all. It is now
  gcc and clang at **C11 and C23** — four legs.

  This matters more in C than a version count suggests. Newer C standards
  *remove* things rather than only adding them: K&R declarations are gone in
  C23, `bool`/`true`/`false` became keywords, and an implicit function
  declaration is an error rather than a warning. A consumer whose own project
  sets `-std=c23` would otherwise have been the first person to compile this SDK
  that way.

- **`AXIAM_MIN_C_STANDARD` and `AXIAM_NEWEST_TESTED_C_STANDARD`** in
  `<axiam/axiam.h>`, plus an `#error` guard that refuses a toolchain below the
  floor **at the point of inclusion** — one message naming the problem instead of
  a cascade of syntax errors that reads like a broken SDK.

- **`tests/test_version_policy.c`** — binds `CMAKE_C_STANDARD`, the header macros
  and the CI matrix together. It also asserts the CMake default stays
  *overridable*, which is load-bearing: a plain `set()` silently ignores
  `-DCMAKE_C_STANDARD=23`, and the newest leg would build C11 while reporting
  green.

- **`examples/version_compatibility.c`** — reports the standard in use against
  the supported range.

- **A "Supported C standards" section in the README.**

### Changed

- **`CMAKE_C_STANDARD` is now overridable rather than hardcoded.** It was
  `set(CMAKE_C_STANDARD 11)`, which overrides anything passed on the command
  line; it is now guarded by `if(NOT DEFINED ...)`. **The default is unchanged** —
  `cmake -S . -B build` with no flags still produces exactly the C11 build it
  always did — but `-DCMAKE_C_STANDARD=23` now takes effect, which is what makes
  the second CI leg possible at all.

  The configure step also prints the standard in effect, so a build's log says
  which one it used.

### Fixed

- **A C23 build does not report the same `__STDC_VERSION__` on both compilers,
  and the policy test now accounts for it.** gcc 13 has no `-std=c23`, so
  `CMAKE_C_STANDARD 23` selects `-std=c2x` and the compiler reports the
  pre-ratification `202000L`; clang 18 reports the ratified `202311L`. Both are
  correct C23 builds, so the check is a lower bound rather than an equality —
  an equality passed on clang and failed on gcc for identical, correct builds.
  Documented at the macro and in the README.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour login/start `mode` on a KE2 failure (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md at 1.29 and openapi.json at 1.0.0-alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Name the conformance sections individually
- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- The §22 reactor protocol core over a caller-supplied transport
- WebAuthn (§24), account lifecycle (§25) and PAR (§26)

### Changed

- Re-vendor CONTRACT.md at 1.28

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807)

- **The §22 reactor protocol core, over a caller-supplied transport (CONTRACT
  §22, §22.11).** `include/axiam/reactor.h`, `src/reactor.c`: §22.1–§22.8 and
  §22.14 in full — the §8 v2 verification set on the event (key version, MAC,
  two-sided freshness, nonce), the canonical serialization and HMAC in both
  directions, the §22.5 registry and its namespace-prefix allow-lists, §22.8's
  strictest-wins default, `axiam_reactor_serve`, and the
  `axiam_reactor_router_t` binding table. Contract 1.28 found the earlier
  deferral cut one notch too wide: the part that genuinely needed a vendored
  dependency was the *connection*, and the runtime around it needed none.

- `axiam_amqps_endpoint` — §8b rules 1–5 as a **public, tested function** rather
  than a doc comment (§22.11 rule 3). It refuses every scheme but `amqps://`
  including `amqp://`, with **no loopback exception** (§8b rule 8); requires a
  client certificate and its key together; carries a custom CA bundle for a
  privately-issued broker certificate; and offers no verification-skip parameter
  under any name and no way to express a plaintext fallback.

- `tests/test_reactor.c` (58) and the committed §22.13 reference vectors,
  vendored at `tests/reactor_v2_reference_vectors.json` — generated by the
  server's own sign path, so a byte out of place in the canonical form is caught
  against a number the server computed rather than against this
  implementation's own opinion. Plus four allocation-failure sweeps over the new
  call graphs.

- `examples/reactor.c` — the §8b guard, the binding table, and the runtime over a
  transport skeleton.

- **WebAuthn / passkeys (CONTRACT §24).** `include/axiam/webauthn.h`,
  `src/webauthn.c`: the six relying-party wire operations
  (`axiam_webauthn_register_start` / `_finish`, `_authenticate_start` /
  `_finish`, `_discoverable_start` / `_finish`) plus §24.6a's JSON bridge —
  `axiam_webauthn_request_json()` hands out the challenge in the exact form the
  platform authenticator APIs take, and every `*_finish` accepts the platform's
  response JSON back as a string, byte for byte. §24.6b's linked-API ceremony
  helper is deliberately absent: a C program has no authenticator, and rule 2
  forbids emulating one in software.

- §24.6b rule 5's failure classification, which is required of every SDK
  claiming §24 whether or not it ships a ceremony helper:
  `axiam_webauthn_classify()` and `axiam_webauthn_failure_message()`. The
  classifier never fails — an unrecognised name, `NULL` included, is
  `AXIAM_WEBAUTHN_UNKNOWN`.

- **Account lifecycle and MFA enrolment (CONTRACT §25).**
  `include/axiam/account.h`, `src/account.c`: nine operations — voluntary
  enrolment (`axiam_mfa_enroll` / `axiam_mfa_confirm`), forced enrolment
  (`axiam_mfa_setup_enroll` / `axiam_mfa_setup_confirm`), email verification
  (`axiam_verify_email`, `axiam_resend_verification`) and the password-reset
  triple (`axiam_request_password_reset`, `axiam_password_reset_context`,
  `axiam_confirm_password_reset`). Six of the nine are unauthenticated by
  design.

- **Pushed Authorization Requests, RFC 9126 (CONTRACT §26).** `src/oidc_par.c`:
  `axiam_oidc_par()`, `axiam_pushed_authorization_request_t` and its dispose.
  `axiam_oidc_config_t` gained `pushed_authorization_request_endpoint`; when the
  discovery document does not advertise it the call is refused client-side with
  no wire request, rather than synthesising `/oauth2/par` from the issuer.

- `examples/webauthn_passkeys.c`, `examples/account_lifecycle.c` and
  `examples/par_login.c`; `tests/test_webauthn.c` (29), `tests/test_account.c`
  (27) and `tests/test_oidc_par.c` (19).

- `axiam_url_encode()` in `src/util.c` — RFC 3986 percent-encoding, needed by
  the `reset/context` query and the PAR redirect. A reset token spliced into a
  query raw can end the query early or land in the path, and the 404 that
  produces reads exactly like an expired token.

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `axiam_login_opaque()`
  and `axiam_opaque_enrollment()`, plus `axiam_opaque_available()` for choosing
  the password path up front. `axiam_login_opaque()` fills the same
  `axiam_login_result_t` as `axiam_login()`, MFA-required and MFA-setup branches
  included.

- `include/axiam/opaque.h`, `src/opaque.c`, `examples/opaque_login.c`,
  `tests/test_opaque_binding.c` and `tests/test_opaque_login.c`.

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#36)

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement names its sections individually.** `§16–§19` and
  `§24–§26` were ranges where the contract asks for individual naming, since a
  widened range silently turns a true statement into a different claim. §16 and
  §18 are now absent rather than folded in — the contract makes them MUST-level
  and says they are not named — with a note saying so, so their absence does not
  read as a narrowing.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `axiam_login()`'s third outcome is now reachable (§25.2 rule 1): a `403`
  carrying `mfa_setup_required` fills `axiam_login_result_t::mfa_setup_required`
  and `::setup_token` instead of failing generically. Additive here — the
  result is a struct rather than a discriminated union, and both fields already
  existed.

- `axiam_mfa_setup_confirm()` adopts credentials exactly as `axiam_login()`
  does, through the same parser rather than a second one that could drift on
  what "adopted" means, and clears the §17 decision memo. `axiam_mfa_enroll()`
  deliberately does **not** clear it (§25.2 rule 3): the subject has not
  changed, and discarding a warm memo on an unrelated profile action costs a
  round trip on every check that follows.

- Both halves of an MFA enrolment are `axiam_sensitive_t` (§25.3). The
  `otpauth://` URI *contains* the secret, so wrapping `secret_base32` and
  leaving the URI a plain string would wrap nothing — the URI is the field that
  actually gets logged, because it is the one a caller passes to a QR renderer.

- Re-vendored `CONTRACT.md` at 1.28 and `openapi.json`.

- **`axiam_login_opaque()` falls back to `axiam_login()` under
  `opaque_mode: optional` (CONTRACT §23.4 rule 7, contract 1.29).** The
  `login/start` response gains an optional `mode` field carrying the tenant's
  `opaque_mode` — `"optional"` or `"required"` — and it is now the only thing
  that decides what follows a failure to open `KE2`. Under `"optional"` the SDK
  retries over `POST /api/v1/auth/login` with the same credentials before
  reporting anything and returns that call's outcome verbatim; under
  `"required"`, with **no** `mode` field at all (a server older than the field)
  or with a value this SDK does not recognise, it fails closed with
  `AXIAM_ERR_AUTH` and puts no plaintext password on the wire. `KE3` is still
  never sent in either case, and `404` handling is untouched — a tenant with
  OPAQUE disabled remains the distinguishable `AXIAM_ERR_NETWORK` it was.
  Without the `optional` clause, enabling `optional` locks out every user of a
  tenant mid-migration: every account has no registration record the moment an
  operator turns OPAQUE on, and acquires one only when its password is next
  set. `mode` is **not** downgrade protection and is not documented as such —
  a hostile server wanting the plaintext could simply answer `404`.

- Re-vendored `CONTRACT.md` at **1.29** and `openapi.json` at
  **1.0.0-alpha40**, byte-identical to the server repository's `sdks/`.

- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so `src/opaque.c` is a `dlopen`/`dlsym` binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam-opaque release page. It is
  resolved at RUN time, so a consumer who never uses OPAQUE needs nothing extra
  at build time and `axiam_opaque_available()` can honestly answer 0. Put the
  library on the loader path or point `AXIAM_OPAQUE_LIBRARY` at it.

- **Your OpenSSL version no longer decides which tenants work.** Argon2id
  arrives as an `EVP_KDF` only in OpenSSL 3.2, so the SRP path had to refuse a
  default-configured (`argon2id`) tenant on anything older — operators either
  upgraded OpenSSL or weakened the tenant to `pbkdf2_sha256`. Key stretching now
  happens inside the native library, so OpenSSL 1.1.1 serves every tenant and
  `axiam_srp_argon2_available()` has no successor.

- `axiam_opaque_enrollment()` takes a client and performs I/O — one
  `register/start` round trip — where `axiam_srp_enrollment()` was pure. OPAQUE's
  envelope is sealed under the server's oblivious PRF, so there is no offline
  computation that produces a valid record. It also loses the `identity`
  argument: a record binds to a credential identifier the server chooses, so
  passing an email where a username was wanted can no longer produce an unusable
  credential, and **renaming a user no longer invalidates it**.

- `${CMAKE_DL_LIBS}` added to the link line (empty on glibc ≥ 2.34).

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- **BREAKING** — SRP-6a. `axiam_login_srp()`, `axiam_srp_enrollment()`,
  `axiam_srp_available()`, `axiam_srp_argon2_available()`,
  `include/axiam/srp.h`, `src/srp.c` and `srp-test-vectors.json` are all gone.
  AXIAM's server-side SRP endpoints are removed in the same release, so keeping
  the client would leave a function that only ever returns 404.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#34)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#33)

## [1.0.0-alpha27] - 2026-08-17

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor CONTRACT.md 1.22 and openapi.json from the server repo
- Drive the SDK's allocation-failure arms, and fix two wild frees they exposed

## [1.0.0-alpha25] - 2026-08-16

### Added

- Subject_token_type is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §12, §12.7, §14 and §15 — the ported deferral (contract 1.11) (#20)
- §20.3 — emit a UMA challenge from the §11 guard (#19)
- §20 UMA 2.0 — Protection API and ticket grant (#18)
- §16 retry, §17 decision memo, §18 close(), §19 telemetry (D5)
- §11 rule 9 decision reason codes; contract 1.7 re-sync (D6) (#16)
- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `axiam_jwt_verify_certificate_binding(claims_json, presented_thumbprint, err)` — the
    rule, applied to the claims `axiam_jwt_verify()` handed back.
  - `axiam_certificate_thumbprint_s256(der, der_len)` — RFC 8705 §3.1 `x5t#S256`:
    base64url, **unpadded**, SHA-256 over the DER certificate. Feed it
    `SSL_get_peer_certificate()` + `i2d_X509()`. Returns a heap string; `free()` it.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `axiam_jwt_verify()` deliberately does **not** apply rule 9: it has no transport to ask
  for a peer certificate. A resource server accepting bound tokens must call both. The
  thumbprint must come from the transport, never from a caller-settable header. A `cnf`
  naming an unimplemented method is **rejected**, never read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.
- **§15.7 external-IdP subject tokens (X4).** `axiam_token_exchange()` can now exchange a token
  minted by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token
  scoped to what the resolved AXIAM user may actually do. No new operation: the same call, plus
  `axiam_token_exchange_params_t::subject_token_type` and the new `AXIAM_TOKEN_TYPE_JWT` macro
  alongside `AXIAM_TOKEN_TYPE_ACCESS_TOKEN`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and a
  wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. NULL still sends `…:access_token`, so every existing caller is unaffected; a
  JWT-shaped subject token does **not** change what is sent, which is asserted by a test.

  The new member is **last** in the struct, so no existing member moved and a zero-initialised
  `params` struct keeps behaving exactly as before.

  Also asserted: an `actor_token` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as a
  different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* — reaches
  `err.message` intact; and nothing re-exchanges an exchanged token, which both server paths
  refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.11 → 1.12 plus
  §15.7), which also brings contract 1.12's `/oauth2/*` error rows dispatching on the `error`
  field at any status, and the `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§12 OIDC relying party, §12.7 logout, §14 device grant, §15 token exchange —
  the contract-1.11 port.** These four were deferred in this SDK through
  contract 1.10; [§12.6](CONTRACT.md) reverses that and they ship together.

  `axiam_oidc_discover/begin/exchange/refresh`, `axiam_login_client_credentials`,
  `axiam_introspect`, `axiam_revoke`, `axiam_sso_start/complete`;
  `axiam_logout_url` and `axiam_verify_logout_token`;
  `axiam_device_authorize/poll/login`; `axiam_token_exchange`. All in the new
  `axiam/oidc.h`.

  The deferral was written from persona — this is a device- and IoT-oriented
  SDK and the browser-redirect flow has no natural home in it — which covered
  `oidc_begin` and `oidc_exchange` and none of the other seven operations.
  §14 exists *because* a device cannot show a browser, and §20 had already
  given this SDK a `/oauth2/token` call, so by 1.10 it was speaking OAuth2 at
  the token endpoint without §12's discovery cache or ID-token validation. The
  port removes a divergence rather than adding one.

  What the surface deliberately does not do: it stores no `state`, `nonce` or
  `code_verifier` (§12.3 rule 1 — the caller keeps them, and the `redirect_uri`
  too); it has no way to skip ID-token validation, and §12.4 rule 7's
  all-or-nothing discard means a bad `id_token` takes the access and refresh
  tokens with it; it adopts no token as the client's own credential; and it
  does not retry a grant whose credential is single-use (§16.2).

- **`axiam_sensitive_reveal()` — §7 rule 3's single explicit accessor**, now
  public. §12 returns tokens *to* the caller, and a wrapper a §12 caller can
  never read makes §12 unusable; contract 1.11's §7 table changes the C row to
  say so. `axiam_sensitive_to_string()` is unchanged and still answers
  `"[SENSITIVE]"` whatever the content.

- **`axiam_error_t::id_token_reason`** — the §12.3 rule 3 closed seven-value
  vocabulary (`invalid_alg`, `unknown_kid`, `invalid_signature`,
  `invalid_issuer`, `invalid_audience`, `token_expired`, `nonce_mismatch`).
  A second field rather than a reuse of `oauth_error`: the two carry different
  vocabularies from different clauses, and §14.2's terminal `expired_token` is
  nearly a homograph of §12.4 rule 5's `token_expired`.

- **Config:** `axiam_client_config_set_oidc_client_id`,
  `_set_oidc_client_secret`, `_set_oidc_discovery_ttl` (raised to the
  5-minute floor), `_set_oidc_clock_skew` (clamped down to 60 s, never up).

- **Examples:** `oidc_login.c`, `device_login.c`, `token_exchange.c`.

- **§20.3 challenge emission from the §11 guard.** `axiam_require_access_uma()` takes an
  `axiam_uma_challenger_t` (realm, `as_uri`, PAT) and an out-parameter; on a denial it mints a
  permission ticket for the action that was refused and writes the formatted
  `WWW-Authenticate: UMA` value there for the caller to send and free.

  It is a **separate entry point** rather than a change to `axiam_require_access()` because
  emitting a challenge means minting a credential: a guard that did it by default would turn
  every unauthorized request into a Protection API call, which is a denial-of-service amplifier
  pointed at your own authorization server. An allow mints nothing, and neither does a NULL or
  half-configured challenger. And a **minting failure is not an escalation** — an expired PAT or
  an unreachable Protection API still yields `AXIAM_GUARD_DENIED` with the out-parameter left
  NULL, never a 503 and never an allow. Both are asserted by counting Protection API calls.

  Internally both entry points share one body, so the two cannot drift on the outcome mapping.
  The requested UMA scope is the AXIAM *action*, so the ticket asks for exactly the authority
  just refused and the engine's deny rules keep applying to whatever RPT comes back.

  Paired with the new `examples/uma_resource_server.c` and `examples/uma_client.c`, which run
  both halves — including the trust decision §20.3 keeps in the caller's hands rather than
  auto-exchanging against whatever host a 403 named.

### Changed

- Widen the branch-coverage margin above the 80% floor
- Point at CONTRACT.md §22.11, the deferred reactor runtime (#28)
- Re-vendor CONTRACT.md 1.19 and openapi.json from main (R5.8) (#27)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#25)
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Make the §9 single-flight tests wait for arrivals, not a clock
- Cover the empty subject_token_type branch (§15.7)
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **README now points at CONTRACT.md §22.11 (the deferred reactor runtime).**
  §22.11 carries a SHOULD that these READMEs point at it "so an integrator finds
  the wire chapter rather than concluding reactors are unavailable" — this SDK
  ships no `reactor_serve`, but §22.1–§22.8 binds a hand-rolled integrator on it
  in full, and the §22.13 vectors are the conformance surface. Documentation
  only: no code change, and **no §22 conformance claim** — §22.11's MUST NOT
  forbids claiming the chapter while shipping no runtime, and the conformance
  statement is untouched.

- **Re-vendored `CONTRACT.md` (1.17 → 1.19) and `openapi.json` from
  `ilpanich/axiam@main`.** The vendored copies had drifted; both are now
  byte-identical to the upstream artifacts. **No code change** — nothing in
  1.18 or 1.19 binds this SDK's implemented surface.
  - **§22 Reactors — AMQP extension actors (contract 1.18).** A new chapter
    describing external allow/deny/mutate actors on the AMQP bus. [§22.11](CONTRACT.md)
    defers the *runtime helper* (`reactor_serve`) in Swift, C and C++ for the
    same reason [§8](CONTRACT.md) has never listed them among the SDKs that speak AMQP:
    there is no vendorable AMQP client for these targets. §22.1–§22.8 still
    bind a hand-rolled integrator in full. This SDK ships no reactor runtime
    and is exactly as conformant as it was under 1.17.
  - **SDK-Q10 closed (contract 1.19)** — the gRPC decision gains `reason`
    (field 4) and deprecates `deny_reason`, converging on the REST shape this
    SDK already speaks. This SDK is REST-only, so nothing moves:
    `axiam_check_result_t` already exposes exactly `allowed` + `reason_code` +
    `reason` and has never carried a `resource_type`, which is the shape
    [§11.2](CONTRACT.md) rule 9's amendment now makes canonical for both transports.
  - `openapi.json` picks up the X5.1 server surface (`dpop_bound_access_tokens`,
    `dpop_require_nonce`, `jwks`/`jwks_uri` on client registration,
    `private_key_jwt` as a client-auth method, `CnfClaim.jkt`) and the reactor
    registration health counters (`recent_timeout_count`, `recent_veto_count`).
    No paths added or removed, no schemas added or removed.
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `axiam_token_exchange_params_t::subject_token_type` is now
  required.** It shipped optional, defaulting to `…:access_token` when NULL. That satisfied
  §15.7's "never inspect the subject token" while leaving the rule it serves unenforced: an
  optional member with a default *is* a default the SDK applies whenever the caller says
  nothing. §15.1 now makes it required.

  C cannot demand a struct member at compile time, so the demand lands at the call: a NULL or
  empty `subject_token_type` returns `AXIAM_ERR_AUTH` **client-side, with no wire call**, with a
  message naming the member and both macros. A test covers NULL and `""` — the shape a
  zero-initialised params struct actually has — and asserts zero token calls.

  **Migration** — one line, naming what you were previously getting by silence:

  ```c
  axiam_token_exchange_params_t p = {0};
  p.subject_token      = subject;
  p.subject_token_type = AXIAM_TOKEN_TYPE_ACCESS_TOKEN;  /* <- add this */
  ```

  The member stays **last** in the struct, so nothing moved and a caller who does not recompile
  gets the loud client-side refusal rather than a silently different request.
- **The JWKS verifier now re-fetches once per cooldown window on an unknown
  `kid`** (§12.4 rule 2), instead of failing immediately against a warm cache.
  This fixes key rotation for the §10/§11 guards as well: previously a rotated
  key was unusable until the 300-second cache TTL expired. The window (60 s)
  bounds the fetch amplification an attacker could otherwise drive by
  presenting forged `kid` values — "never re-fetch" and "always re-fetch" are
  both explicitly forbidden.

- `axiam_oidc_refresh` is governed by its own §9-conformant single-flight
  guard, keyed on the refresh token's digest. AXIAM rotates refresh tokens, so
  two threads redeeming one concurrently would produce a winner and an
  `invalid_grant` for a token that was good a millisecond earlier. Distinct
  tokens do not contend. §9 rule 5 permits this dedicated instance rather than
  reusing the §1 cookie-session guard, whose API compares an access token's
  freshness — a comparison with no meaning for a `refresh_token` grant.

### Fixed

- Refuse both-bound tokens; document the §21.7.3 declining posture (#26)
- **CONTRACT.md §10.1 rule 9 conjunction fix, and the §21.7.3 declining posture
  documented (contract 1.16).**

  A `cnf` naming **both** a certificate and a DPoP `jkt` was previously accepted
  on the matching certificate alone, ignoring the `jkt` entirely. Two named
  constraints are a **conjunction**, and this SDK declines §21.7.2 proof
  verification — so it can establish one half and must not answer for the whole.
  Such a token is now refused. The old behaviour would let a caller holding the
  certificate but **not** the DPoP key through a door the operator bolted twice.

  Pure `jkt`-bound tokens were already refused and remain so. The README now
  documents the declining posture, completing §21.7.3's three obligations
  (reject, document, test).

  Not a breaking change for certificate-only deployments: a token naming only
  `x5t#S256` behaves exactly as before, and an unbound token is still accepted
  with or without a certificate.
- **The §9 single-flight tests no longer bet on a clock.** Both burst tests spawned eight
  workers against a flight the fake transport delayed by 60 ms, then asserted `token_calls == 1`
  — that the last worker joined the flight the first one opened. The `pthread_barrier` already
  guaranteed all eight were *running*; what no fixed delay can guarantee is that they have
  reached the *guard* before the leader finishes. Under valgrind, or on a runner with fewer
  cores than threads, the leader returns first and a follower opens a second flight — a failure
  that says nothing about the guard.

  The leader now waits for arrivals instead: each worker bumps `gate_arrived` on its way into
  `axiam_oidc_refresh`, and the transport holds the leader until `gate_expect` workers have
  entered. The 60 ms delay stays as slack for a worker that has entered but not yet parked.
  Nothing weakens: if the guard were broken the followers would reach the transport and
  `token_calls` would say so; a late arrival finds the count satisfied, so nothing deadlocks;
  and the wait is bounded at 10 s so a real regression fails the assertion rather than hanging.

  Ported from the same fix in the C++ SDK (`ilpanich/axiam-cplusplus-sdk#21`), where this
  surfaced as a CI failure. It had not yet bitten here — which is the reason to fix it now
  rather than after it does. Verified with 4/4 clean runs of `test_oidc_singleflight` under
  valgrind pinned to a single core with `taskset`.

### Notes

- Coverage after this change: **96.3% line, 80.2% branch** against gates of 96
  and 80. Both pass, but with materially less headroom than the pre-port
  figures the `coverage.yml` comments were written against — this subsystem
  checks every allocation, and those guards are one-sided by construction.
  Worth knowing before the next change lands on the wrong side of the line.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Conform local token verification to CONTRACT §10.1
- **UMA 2.0 — Protection API and ticket grant (CONTRACT §20).** New `axiam/uma.h`:
  `axiam_uma_discover`, `axiam_uma_register_resource`, `axiam_uma_read_resource`,
  `axiam_uma_update_resource`, `axiam_uma_delete_resource`, `axiam_uma_list_resources`,
  `axiam_uma_request_ticket`, `axiam_uma_exchange_ticket`, and the two local challenge
  helpers `axiam_uma_parse_challenge` / `axiam_uma_challenge_header`. Every out-parameter
  that carries heap memory has a matching `_dispose`/`_free`, and each is safe on a zeroed
  struct so a caller can dispose unconditionally on the error path.

  **This ships while §12 does not, and that is not an inconsistency.** §12.7, §14 and §15
  stay deferred because each needs an OIDC stack this SDK does not have. §20 does not: UMA
  carries its own discovery document, the Protection API is ordinary bearer-authenticated
  REST, and the ticket grant returns an opaque RPT with nothing to validate.

  The load-bearing rules, all asserted in `tests/test_uma.c`:

  - **`axiam_uma_exchange_ticket` is never retried** — not on `5xx`, not on a transport
    failure, not on `invalid_grant`. This is the one documented exception to §16, and a
    security rule rather than a performance one: the ticket is consumed *before* the
    exchange is evaluated, so a retry is a second redemption — the concurrency case whose
    measured residual `ilpanich/axiam#302` records.
  - **`axiam_uma_parse_challenge` performs no exchange.** The `as_uri` names an
    authorization server the caller has not chosen to trust.
  - **The RPT is never adopted**, and `axiam_uma_rpt_t` has no refresh-token member.
  - **`axiam_uma_update_resource` replaces the scope list rather than merging it** — no
    read-modify-write, so omitting a scope removes it.
  - **An absent PAT, ticket, `claim_token`, client secret, or a slug-only tenant is refused
    client-side**, with no wire call, so a request that could not have succeeded never
    spends a ticket.

  The grant's form body carries four secrets and is scrubbed with `axiam_secure_zero`
  before release (§7), rather than left in a freed heap block.

- **Bounded read-only retry (CONTRACT §16).** `check_access`, `can`,
  `batch_check` and the JWKS fetch now retry a transient failure: 3 attempts
  total, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`, and
  `Retry-After` honored as a **floor** — it can lengthen a wait, never shorten
  one, so a `Retry-After: 0` cannot defeat the backoff. On by default;
  `axiam_client_config_set_retry_enabled(cfg, 0)` gives exactly one attempt for
  a caller who owns their own retry layer. The attempt cap, base and cap are
  deliberately **not** settable: §16.1 permits lowering or disabling, never
  raising, and a caller who can raise them turns one client into the herd a
  backoff exists to prevent.

  Eligibility is "changes no server state", **not** "is a `GET`". The
  authorization check is a `POST` with a body and is the operation this policy
  exists for; `login`, `verify_mfa`, `logout` and `refresh` are never retried,
  both because they change state and because their credentials are single-use.
  `tests/test_d5_conformance.c` asserts that a `503` on `login` still makes
  exactly one request on the wire — the case that catches a retry wired at the
  transport layer instead of the operation layer.

- **Client-side decision memo (CONTRACT §17).** `axiam_client_config_set_decision_memo_ttl`
  enables a bounded, TTL-clamped cache of authorization decisions. **Disabled by
  default**, and `0` means disabled rather than "cache for zero milliseconds". A
  TTL above 5 s is clamped to 5 s rather than rejected, allows and denies are
  cached identically, `reason_code` comes back with the decision, failures are
  never cached, and any credential change clears it.

  **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in
  both directions — a grant just *added* can still read as denied for up to the
  TTL — which is the direction that surprises people and breaks silently.

- **Deterministic shutdown (CONTRACT §18).** `axiam_client_close()` releases the
  transport, the cookie jar and the JWKS cache, scrubs the CSRF token, and is
  idempotent. It issues **no request**: the server-side session deliberately
  outlives the client object, so a close that logged out would silently end
  every user's session on each deploy. A call on a closed client returns
  `AXIAM_ERR_NETWORK` with a message naming the cause rather than reconnecting
  or reading freed memory. `axiam_client_free()` calls it for you, so existing
  code needs no change.

- **Telemetry hooks (CONTRACT §19).** `axiam_client_config_set_telemetry_hook`
  installs a sink for `request_start`, `request_end`, `retry`, `refresh` and
  `config_clamped` events, so metrics can be wired without this library taking a
  dependency on any metrics package. One `request_start`/`request_end` pair per
  **attempt**, so a caller can count real wire calls from the events. Payloads
  cannot carry a token by construction: `axiam_telemetry_event_t` is a fixed
  struct with no free-form map, and carries the path *template* rather than a
  URL with ids substituted in.

- **Decision reason codes (CONTRACT §11 rule 9).** `axiam_check_result_t` gains
  an owned `reason_code` string, populated by `axiam_check_access`, `axiam_can`
  and every row of `axiam_batch_check`, with `AXIAM_REASON_CODE_ALLOWED`,
  `AXIAM_REASON_CODE_NO_GRANT` and `AXIAM_REASON_CODE_DENIED_BY_RULE` as
  comparison constants. The two refusals are both `allowed == 0` but mean
  opposite things to the user — *ask an admin* versus *an admin already
  decided* — and an application that cannot tell them apart sends people to
  raise tickets that will be refused.

  Deliberately a `char *` and not an enum: §11 rule 9 requires an unrecognised
  code be surfaced verbatim, so a server that adds a fourth code must not become
  a decode failure in every deployed client. A server that omits the field
  yields `NULL` (absent, not an error), and the allow/deny outcome is carried by
  `allowed` alone. Guard behaviour is unchanged — `axiam_require_access` still
  returns `AXIAM_GUARD_DENIED` (403) for both refusals — which
  `tests/test_reason_code.c` asserts alongside the reporting half.

- **ASan+UBSan and valgrind CI job (§13.4 observation 10 / §12.6.1).** `OBS-4`
  was a signed-integer overflow — undefined behaviour on the **token-decode
  path** — that survived three security passes because neither C repository had
  a sanitizer leg: the only jobs were gcc/clang builds plus coverage, and UB is
  exactly what an ordinary build does not report. The new job runs the full
  suite under ASan+UBSan with `-fno-sanitize-recover=all` (so a UBSan diagnostic
  aborts rather than printing and letting the run stay green) and then sweeps
  every test binary under valgrind with `--error-exitcode=9 --leak-check=full`.
  Verified locally before wiring: 23/23 tests pass under the sanitizers, and the
  valgrind sweep reports 0 errors and 0 definite leaks.
- **T-145 / CONTRACT §13 — webhook signature verification.** New `axiam/webhook.h`:
  `axiam_webhook_verify()`, `axiam_webhook_verify_at()` (a `now` seam for tests) and
  `axiam_webhook_verify_headers()` (which also yields the event type and the
  `X-Axiam-Delivery` dedup key). HMAC-SHA256 over `<timestamp>.<raw_body>`,
  constant-time comparison over the decoded MAC bytes (explicit volatile
  accumulator — no `memcmp`, no early return), two-sided 300s freshness window,
  typed statuses that never carry the expected signature.
- `axiam_jwt_verify_ex()` with the `AXIAM_JWT_VERIFY_*` policy flags, for callers
  that deliberately want a weaker check than the strict default.
- `axiam_verify_mfa_sensitive()`, which takes the Sensitive challenge token straight
  from `axiam_login_result_t`.

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#15)
- Device (mTLS) tokens now carry aud=axiam:m2m (#14)
- Service accounts can use login_client_credentials (#13)
- Add ASan+UBSan and valgrind gates (§13.4 observation 10 / §12.6.1) (#12)
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `axiam_error_t` gained `oauth_error[64]`, empty for every failure that is not an OAuth2
  protocol error. §20.4 requires dispatching on the body's `error` field rather than the
  HTTP status — `access_denied` answers `403` on the ticket grant where RFC 8628's answers
  `400` — so the code has to reach the caller. The contract models it as an
  `OAuthProtocolError` sub-type of the authentication error; C has no subtyping, so the
  kind stays `AXIAM_ERR_AUTH` and the code lands in the new field, leaving the §2 taxonomy
  at three kinds rather than gaining a fourth. **This changes `sizeof(axiam_error_t)`**, so
  callers must recompile; the struct is caller-allocated and pre-1.0, so no ABI promise is
  broken.

- **Re-vendored `CONTRACT.md` and `openapi.json`** from `ilpanich/axiam` at
  contract 1.7. Of the sections 1.7 adds, only §11 rule 9 is implemented here;
  §12.7 (logout), §14 (device grant) and §15 (token exchange) all build on a
  §12 OIDC relying-party layer this SDK does not have, and are recorded under
  Scope / follow-ups in the README rather than half-shipped.
- **Source-breaking:** `axiam_login_result_t.challenge_token` and `.setup_token` are
  now `axiam_sensitive_t *` instead of `char *`. Pass them to the new
  `axiam_verify_mfa_sensitive()`; `axiam_verify_mfa()` still accepts a raw string.
- **Behaviour-breaking:** a client used for route guarding must be configured with
  `axiam_client_config_set_tenant_id()` (the token's `tenant_id` claim is a UUID and
  a slug cannot be compared against it). A slug-only client that has not completed a
  login has no tenant binding available and refuses every token.
- **Behaviour-breaking (opt-in): configuring an expected issuer or audience tightens
  acceptance.** A client built with `axiam_client_config_set_expected_issuer()` or
  `..._set_expected_audience()` refuses tokens that previously passed — including
  tokens that carry no `iss`/`aud` claim at all, which fail closed rather than
  being treated as "nothing to check". Clients that set neither (the default)
  behave exactly as before. `AXIAM_JWT_VERIFY_STRICT`'s numeric value changed
  because it gained `AXIAM_JWT_VERIFY_ISSUER_AUDIENCE`; recompile against the new
  header rather than relying on a cached literal.
- Vendored `CONTRACT.md` re-synced with the new §13 (webhook signature verification)
  and §10.1 (minimum local-verification set).

### Fixed

- Enforce token lifetime and tenant binding, require https, wrap MFA tokens

### Security

- **SEC-071 (HIGH) — route guards no longer accept expired or cross-tenant tokens.**
  Local verification is now strict by default: `axiam_jwt_verify()` (and therefore
  `axiam_require_auth` / `axiam_require_access` / `axiam_require_role`) enforces the
  token lifetime — `exp` is mandatory, `nbf` is honoured when present, both with a
  60s `AXIAM_JWT_CLOCK_SKEW_SECS` allowance — and asserts that the `tenant_id` claim
  equals the client's configured tenant. The JWKS trust anchor is organization-wide,
  so a valid signature alone never implied the caller's tenant. Every new check fails
  **closed** (`AXIAM_ERR_AUTH` / HTTP 401), and the authorization server is no longer
  consulted for a token the guard should have refused.
- **CONTRACT §10.1 conformance — optional `iss` / `aud` pinning on local verification.**
  The §10.1 "minimum local-verification set" is now fully satisfied by
  `axiam_jwt_verify()` and the §10/§11 guards. Rules 1–4 and 7 (EdDSA `alg` pin
  before key lookup, mandatory numeric `exp`, `nbf` when present, asserted
  `tenant_id`, the named/bounded `AXIAM_JWT_CLOCK_SKEW_SECS`) were already
  enforced by SEC-071. Rules 5 and 6 are new: `axiam_client_config_set_expected_issuer()`
  and `axiam_client_config_set_expected_audience()` configure the expectations,
  and `AXIAM_JWT_VERIFY_STRICT` now also carries `AXIAM_JWT_VERIFY_ISSUER_AUDIENCE`.
  Both checks are **conditional** — an unset expectation (the default) means the
  claim is not checked, and no issuer is ever assumed. When one *is* configured,
  a token whose claim is absent, of the wrong JSON type, or different is refused
  with `AXIAM_ERR_AUTH` / HTTP 401. `aud` is matched against both the bare-string
  and the array-of-strings forms. A resource server guarding a user-facing API
  should set the audience to `axiam:user`.
- **SEC-073 — a plaintext `http://` base URL is refused at construction** (CONTRACT §6).
  `axiam_client_config_validate()` / `axiam_client_new()` now reject a non-`https`
  base URL, with a loopback exception (`localhost`, `127.0.0.1`, `::1`) for local
  development. There is no flag to disable the check for a routable host.
- **SEC-076 — MFA challenge/setup tokens are held behind `axiam_sensitive_t`** (§7):
  they render as `[SENSITIVE]` and their memory is zeroized on release. Login and
  MFA request bodies (which carry the password and the challenge token) are also
  scrubbed before being freed, and the Sensitive scrub now uses a volatile write
  the compiler may not elide.

### Notes

- **§13.4 observation 8 was mistaken; no change was needed.** It recorded that
  this SDK's §10.1 negative-test set "looks incomplete — `tests/test_jwt_claims.c`
  covers the `exp` cases but not evidently the rest". Auditing the file against
  the mandated list shows the set is **complete**, and each case is substantive
  rather than nominal: expired, absent `exp`, non-numeric `exp`, future `nbf`,
  malformed `nbf`, foreign tenant, absent `tenant_id`, `alg: none`, and an
  HS-signed token bearing the org's EdDSA `kid` — plus issuer and audience
  mismatches, which §10.1 requires only where the SDK supports that
  configuration. The tenant and `alg` cases additionally assert at all three
  guard entry points and that the authz server is never consulted.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6

## [1.0.0-alpha18] - 2026-07-24

### Changed

- C SDK branch coverage 70.9%→82.0% + real TLS/mTLS handshake test (#7)
- C SDK 90% → 98.8% + add gcovr regression gate (Phase D) (#6)

### Fixed

- Pin newest libcurl (8.21.0) to escape stale broken recipe revision
- Bump libcurl 8.6.0 -> 8.11.1 to unblock package-recipes CI

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info
- Adopt CONTRACT.md 1.3: the new gRPC-only `axiam_get_user_info` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract copy is re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Changed

- Add C examples, README badges, sync CONTRACT §5.1 (#4)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Make version string test resilient to pre-release suffix changes (#3)

## [1.0.0-alpha10] - 2026-07-18

### Added

- Initial greenfield C11 SDK for the AXIAM REST API.
- Client configuration (`axiam_client_config_t`) requiring a base URL and exactly
  one tenant identifier (slug or id) — no default tenant (CONTRACT §5).
- Canonical operations (CONTRACT §1): `axiam_login`, `axiam_verify_mfa`,
  `axiam_refresh`, `axiam_logout`, `axiam_check_access`, `axiam_can`,
  `axiam_batch_check`, with `(action, resource[, scope])` argument order.
- Error taxonomy `axiam_error_t` / `axiam_error_kind_t` with the three kinds
  `AXIAM_ERR_AUTH` / `AXIAM_ERR_AUTHZ` / `AXIAM_ERR_NETWORK` and the HTTP-status
  mapping (CONTRACT §2); messages never carry token material.
- Automatic CSRF forwarding: capture `X-CSRF-Token` from responses, echo on
  state-changing requests (CONTRACT §3).
- Per-client in-memory libcurl cookie engine (CONTRACT §4).
- `X-Tenant-ID` injected on every request (CONTRACT §5).
- Strict TLS always on, custom CA (PEM) as the only escape hatch (CONTRACT §6);
  in-memory client-certificate mTLS via PEM cert + key blobs (CONTRACT §6.1).
- Opaque `axiam_sensitive_t` with `[SENSITIVE]` rendering and no raw getter;
  mTLS private key held behind it (CONTRACT §7).
- Single-flight refresh guard using `pthread_mutex_t` + condition variable, with
  a concurrency test asserting exactly one refresh under load (CONTRACT §9).
- Framework-agnostic route guard `axiam_require_auth` and declarative helpers
  `axiam_require_access` / `axiam_require_role` plus `AXIAM_REQUIRE_*` macros
  (CONTRACT §10, §11), composing on top of JWKS verification.
- JWKS fetch + EdDSA/Ed25519 JWT verification (OpenSSL `EVP_DigestVerify`), 300s
  cache, non-EdDSA algorithms rejected before key lookup, `exp` not checked.
- Function-pointer HTTP transport seam (`axiam_transport_fn`) for testability;
  default libcurl implementation.
- CMake build producing static and shared `axiam` libraries, install rules,
  package config, and a CPack `.tar.gz`; vcpkg overlay port and Conan recipe.
- CI: build (gcc + clang), CTest, TLS-bypass grep gate, recipe validation,
  tag-on-main gate, release upload; Doxygen Pages; gcov/lcov → Coveralls.

### Changed

- Resolve tenant_id/org_id from access-token claim for the refresh body (#2)
- Publish API docs to gh-pages branch

### Deferred

- gRPC transport and §8 AMQP HMAC consumer are out of scope for v1.0.
