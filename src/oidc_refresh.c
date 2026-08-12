/*
 * AXIAM C SDK — `oidc_refresh` and its single-flight guard (CONTRACT.md §12.1,
 * §9 rule 2).
 *
 * WHY THIS IS NOT axiam_refresh(). §12.1 is explicit that `oidc_refresh` and the
 * §1 `refresh` are distinct operations that MUST NOT be merged, aliased, or made
 * to fall back to one another. They speak to different endpoints
 * (`/oauth2/token` against `/api/v1/auth/refresh`), carry different credentials
 * (a caller-held refresh token against a session cookie), and answer differently
 * on failure. Two functions, two guards.
 *
 * WHY A GUARD AT ALL, GIVEN THE CALLER SUPPLIES THE TOKEN. AXIAM rotates refresh
 * tokens: redeeming one invalidates it and issues a replacement. Two threads
 * that redeem the SAME token concurrently therefore produce one winner and one
 * `invalid_grant` for a token that was perfectly good a millisecond earlier —
 * and the loser cannot tell that from a genuinely revoked session. §9 rule 2's
 * observable requirement (one wire call per burst, that one outcome shared with
 * every concurrent caller) is exactly the fix.
 *
 * The guard is keyed on the token's SHA-256 rather than on the client, because
 * unrelated tokens have no reason to contend, and on the DIGEST rather than the
 * token so the registry never holds a second copy of a live credential.
 * §9 rule 5 permits this dedicated instance rather than reusing the §1 cookie
 * guard, whose API compares an access token's freshness — a comparison with no
 * meaning for a `refresh_token` grant.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "oidc_internal.h"

struct axiam_oidc_flight {
    char key[65]; /* hex SHA-256 of the refresh token */
    int done;
    int refs; /* leader + waiters; the last one out frees the node */
    axiam_error_kind_t kind;
    axiam_error_t err;
    axiam_oidc_token_set_t result;
    struct axiam_oidc_flight *next;
};

/* Hex SHA-256 of `s` into `out` (65 bytes). Returns 1 on success. */
static int digest_hex(const char *s, char out[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, s, strlen(s)) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != 32) return 0;
    for (unsigned i = 0; i < len; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    return 1;
}

/* The wire call itself. Called by the leader only. */
static axiam_error_kind_t perform_oidc_refresh(axiam_client_t *c,
                                               const char *refresh_token,
                                               const char *scope, const char *tenant_uuid,
                                               const char *client_id,
                                               axiam_oidc_token_set_t *out,
                                               axiam_error_t *err) {
    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(c, &config, err);
    if (kind != AXIAM_OK) return kind;

    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", "refresh_token");
    oidc_form_add(&form, "refresh_token", refresh_token);
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "client_secret", axiam_sensitive_reveal(c->cfg->oidc_client_secret));
    /* Optional; omitted rather than sent empty (§12.1). */
    oidc_form_add(&form, "scope", scope);

    char *body = NULL;
    /* NOT retryable. §16.2 disqualifies it twice over — a rotating refresh token
     * is single-use, and §9 rule 3 already forbids a retry loop here by name.
     * §16 does not amend §9. */
    kind = oidc_token_grant(c, &form, &config, tenant_uuid, 0, "oidc refresh failed",
                            &body, err);
    oidc_form_dispose(&form);
    if (kind == AXIAM_OK) {
        /* §12.4 rule 6 is skipped for a refresh-issued ID token (OIDC Core
         * §12.2 does not require a nonce there); rules 1-5 and 7 still apply. */
        kind = oidc_parse_token_set(c, body, &config, NULL, out, err);
    }
    free(body);
    axiam_oidc_config_dispose(&config);
    return kind;
}

/* Copy a completed flight's outcome to one participant, then release its
 * reference. Called with oidc_refresh_mtx held; unlocks nothing. */
static axiam_error_kind_t take_outcome(axiam_client_t *c, struct axiam_oidc_flight *f,
                                       axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_error_kind_t kind = f->kind;
    if (kind == AXIAM_OK) {
        if (!oidc_token_set_copy(&f->result, out)) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            kind = AXIAM_ERR_NETWORK;
        }
    } else if (err) {
        *err = f->err;
    }
    if (--f->refs == 0) {
        axiam_oidc_token_set_dispose(&f->result);
        free(f);
    }
    (void)c;
    return kind;
}

axiam_error_kind_t axiam_oidc_refresh(axiam_client_t *client,
                                      const axiam_sensitive_t *refresh_token,
                                      const char *scope, const char *tenant_id,
                                      axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *raw = axiam_sensitive_reveal(refresh_token);
    if (!raw || !raw[0]) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "oidc_refresh requires a refresh token");
        return AXIAM_ERR_AUTH;
    }
    const char *client_id = oidc_require_client_id(client, "oidc_refresh", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, tenant_id, "oidc_refresh", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    char key[65];
    if (!digest_hex(raw, key)) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "oidc_refresh: digest failed");
        return AXIAM_ERR_NETWORK;
    }

    double started = axiam_telemetry_installed(&client->telemetry) ? axiam_now_ms() : 0.0;

    pthread_mutex_lock(&client->oidc_refresh_mtx);
    for (struct axiam_oidc_flight *f = client->oidc_refresh_flights; f; f = f->next) {
        if (strcmp(f->key, key) != 0) continue;
        /* A FOLLOWER. It issues no request of its own and shares the leader's
         * one outcome — the observable §9 rule 2 requires, and the reason the
         * §16.7-style assertion for this is a wire-call COUNT rather than a
         * check that the helper exists. */
        f->refs++;
        while (!f->done) pthread_cond_wait(&client->oidc_refresh_cond, &client->oidc_refresh_mtx);
        axiam_error_kind_t shared = take_outcome(client, f, out, err);
        pthread_mutex_unlock(&client->oidc_refresh_mtx);
        axiam_telemetry_refresh(&client->telemetry, AXIAM_REFRESH_FOLLOWER,
                                axiam_telemetry_installed(&client->telemetry)
                                    ? axiam_now_ms() - started : 0.0);
        return shared;
    }

    struct axiam_oidc_flight *flight = calloc(1, sizeof(*flight));
    if (!flight) {
        pthread_mutex_unlock(&client->oidc_refresh_mtx);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    memcpy(flight->key, key, sizeof(key));
    flight->refs = 1;
    flight->next = client->oidc_refresh_flights;
    client->oidc_refresh_flights = flight;
    pthread_mutex_unlock(&client->oidc_refresh_mtx);

    axiam_error_t local;
    axiam_error_reset(&local);
    axiam_oidc_token_set_t result;
    axiam_error_kind_t kind =
        perform_oidc_refresh(client, raw, scope, tenant, client_id, &result, &local);

    pthread_mutex_lock(&client->oidc_refresh_mtx);
    /*
     * UNLINK BEFORE PUBLISHING. A caller arriving after this point must start a
     * fresh flight rather than attach to a finished one: the token this flight
     * redeemed is now spent, and handing its result to a later caller would be
     * a cache, not a coalesce — with no TTL and no invalidation.
     */
    struct axiam_oidc_flight **link = &client->oidc_refresh_flights;
    while (*link && *link != flight) link = &(*link)->next;
    if (*link == flight) *link = flight->next;

    flight->kind = kind;
    flight->err = local;
    if (kind == AXIAM_OK) flight->result = result;
    flight->done = 1;
    client->oidc_refresh_count++;
    pthread_cond_broadcast(&client->oidc_refresh_cond);
    axiam_error_kind_t mine = take_outcome(client, flight, out, err);
    pthread_mutex_unlock(&client->oidc_refresh_mtx);

    axiam_telemetry_refresh(&client->telemetry, AXIAM_REFRESH_LEADER,
                            axiam_telemetry_installed(&client->telemetry)
                                ? axiam_now_ms() - started : 0.0);
    return mine;
}
