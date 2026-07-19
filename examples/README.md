# AXIAM C SDK — Examples

Small, self-contained programs that link against the public `axiam::axiam`
library and use only the public headers under [`../include/axiam`](../include/axiam).
They are illustrative and compile/link without a live AXIAM server; running them
end-to-end requires a reachable AXIAM server at the configured base URL.

| Example | Shows |
|---------|-------|
| [`login_mfa.c`](login_mfa.c)  | Two-phase `axiam_login` / `axiam_verify_mfa` flow (CONTRACT.md §1, §5, §5.1). |
| [`rest_authz.c`](rest_authz.c) | REST authorization: `axiam_check_access`, `axiam_can`, `axiam_batch_check` (§1). |

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
| `AXIAM_TOTP_CODE`   | `000000` (login_mfa only)                  |
| `AXIAM_RESOURCE_ID` | `00000000-0000-0000-0000-000000000000` (rest_authz only) |

```sh
export AXIAM_BASE_URL=https://iam.example.com
export AXIAM_EMAIL=alice@example.com
export AXIAM_PASSWORD=s3cret
./build/examples/login_mfa
./build/examples/rest_authz
```

Strict TLS verification is always on (§6). For a self-signed dev server, add a
custom CA in the source via `axiam_client_config_set_custom_ca()` — there is no
insecure/skip-verify switch anywhere in the SDK.
