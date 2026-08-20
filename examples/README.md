# AXIAM C SDK — Examples

Small, self-contained programs that link against the public `axiam::axiam`
library and use only the public headers under [`../include/axiam`](../include/axiam).
They are illustrative and compile/link without a live AXIAM server; running them
end-to-end requires a reachable AXIAM server at the configured base URL.

| Example | Shows |
|---------|-------|
| [`login_mfa.c`](login_mfa.c)  | Two-phase `axiam_login` / `axiam_verify_mfa` flow (CONTRACT.md §1, §5, §5.1). |
| [`opaque_login.c`](opaque_login.c) | The §23 OPAQUE (RFC 9807) exchange: which failures may fall back to `axiam_login()` and which must not, and the registration record the server cannot build for itself. |
| [`rest_authz.c`](rest_authz.c) | REST authorization: `axiam_check_access`, `axiam_can`, `axiam_batch_check` (§1). |
| [`telemetry_hook.c`](telemetry_hook.c) | Metrics without a metrics dependency: §19 hooks, the §16 retry signal, and the §19.2 rule 6 clamp warning. |
| [`uma_resource_server.c`](uma_resource_server.c) | UMA 2.0 (§20), emit half: register a resource, guard it, answer a denial with `WWW-Authenticate: UMA`. |
| [`uma_client.c`](uma_client.c) | The other half: parse the challenge, make the **trust decision** §20.3 keeps in the caller's hands, then exchange the ticket for an RPT. |
| [`oidc_login.c`](oidc_login.c) | The OIDC relying-party flow (§12) and §12.7 logout — and, more to the point, the four values §12.3 rule 1 makes the **caller's** to keep across the redirect. |
| [`device_login.c`](device_login.c) | RFC 8628 (§14) for a thing with no browser: display the code, then let the SDK run §14.2's polling rules. |
| [`token_exchange.c`](token_exchange.c) | RFC 8693 (§15): delegation versus impersonation, and the refusals the SDK surfaces rather than works around. |

## Organization context (§5.1)

`login` and `refresh` require **organization context in addition to tenant
context** — a tenant slug is only unique within an organization. Both examples
therefore set the org slug next to the tenant slug:

```c
axiam_client_config_set_tenant_slug(cfg, "acme"); /* §5   */
axiam_client_config_set_org_slug(cfg, "acme");    /* §5.1 */
```

Omitting the org identifier makes the server reject login with
`400 Bad Request — "must provide org_id or org_slug"`.

## Build

Examples are built when `AXIAM_BUILD_EXAMPLES` is `ON` (the default):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

To skip them:

```sh
cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=OFF
```

The binaries land in `build/examples/`.

## Run

Connection details are read from the environment (with the defaults shown):

| Variable            | Default                                    |
|---------------------|--------------------------------------------|
| `AXIAM_BASE_URL`    | `https://localhost:8443`                   |
| `AXIAM_TENANT_SLUG` | `acme`                                     |
| `AXIAM_ORG_SLUG`    | `acme`                                     |
| `AXIAM_EMAIL`       | `user@example.com`                         |
| `AXIAM_PASSWORD`    | `changeme`                                 |
| `AXIAM_TOTP_CODE`   | `000000` (login_mfa, opaque_login)         |
| `AXIAM_USERNAME`    | `alice` (opaque_login)                     |
| `AXIAM_NEW_PASSWORD` | unset — set it to make `opaque_login` also build a registration record |
| `AXIAM_OPAQUE_LIBRARY` | full path to `libaxiam_opaque_ffi` when it is not already on the loader path (opaque_login) |
| `AXIAM_RESOURCE_ID` | `00000000-0000-0000-0000-000000000000` (rest_authz only) |
| `AXIAM_TENANT_ID`   | `11111111-1111-1111-1111-111111111111` (the §12/§14/§15 examples — a **UUID**, because five of the nine §12 operations put the tenant in a query parameter that a slug cannot satisfy) |
| `AXIAM_OIDC_CLIENT_ID` / `AXIAM_OIDC_CLIENT_SECRET` | the relying party's registration (the secret is omitted for a public client, which is what `device_login` runs as) |
| `AXIAM_REDIRECT_URI` | `https://app.example.com/callback` (oidc_login only) |
| `AXIAM_AUTH_CODE` / `AXIAM_RETURNED_STATE` | what your callback received; `oidc_login` stops before the exchange without them |
| `AXIAM_SUBJECT_TOKEN` / `AXIAM_ACTOR_TOKEN` | token_exchange only — **the actor token's presence is what selects delegation over impersonation** |

```sh
export AXIAM_BASE_URL=https://iam.example.com
export AXIAM_EMAIL=alice@example.com
export AXIAM_PASSWORD=s3cret
./build/examples/login_mfa
./build/examples/rest_authz
./build/examples/telemetry_hook
```

Strict TLS verification is always on (§6). For a self-signed dev server, add a
custom CA in the source via `axiam_client_config_set_custom_ca()` — there is no
insecure/skip-verify switch anywhere in the SDK.
