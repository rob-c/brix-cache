/* client/lib/cred_s3.c
 *
 * WHAT: S3-keys credential handler for the unified credential store (cred.c).
 *       Implements xrdc_cred_s3keys() returning the XRDC_CRED_S3KEYS handler
 *       with available / acquire operations.
 * WHY:  S3 key discovery was inline in s3.c with no shared path for auth
 *       pre-flight diagnostics.  A unified handler lets the store serve both the
 *       S3 transport (s3.c) and the auth pre-flight probe (credinfo.c) from one
 *       place and covers all three discovery levels consistently.
 * HOW:  Discovery precedence (highest to lowest):
 *         1. cfg->s3_access + cfg->s3_secret  (CLI --s3-access/--s3-secret)
 *         2. $AWS_ACCESS_KEY_ID + $AWS_SECRET_ACCESS_KEY  (environment)
 *         3. ~/.aws/credentials [default] section
 *            (aws_access_key_id / aws_secret_access_key)
 *       Both access key AND secret are required; a partial pair is treated as
 *       "not available".
 *
 *       available() returns 1 iff a complete pair is obtainable via any level.
 *       acquire() fills out->s3_access + out->s3_secret from function-static
 *       buffers and sets *not_after=0 (static keys have no expiry).
 *       refresh = NULL (static keys are long-lived; rotation is operator-driven).
 *
 *       Lifetime contract (cred.h §LIFETIME CONTRACT): acquire() writes
 *       out->s3_access / out->s3_secret as pointers to function-local static
 *       char[] buffers that remain valid after acquire() returns.  The store's
 *       slot_store_view strdup's them immediately afterward — before any other
 *       acquire can overwrite the buffers.  Single-threaded per-acquire, so one
 *       static buffer pair is safe for this window.
 *
 *       Secret values are NEVER written to log or error messages.
 *
 * ngx-free.  No goto.  Functional/modular: one responsibility per function.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "xrdc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Maximum length for an S3 access key or secret (generous upper bound). */
#define S3KEY_BUFSZ 512

/* ~/.aws/credentials INI parser */
/*
 * trim_inplace — strip leading and trailing ASCII whitespace from a string.
 *
 * WHAT: modifies s in-place; returns a pointer to the first non-space char.
 * WHY:  INI files may have arbitrary whitespace around '=' or at line ends;
 *       normalising both sides before comparison avoids false-negative matches.
 * HOW:  advance start past spaces; NUL-terminate at the last non-space.
 *       The returned pointer may be s or an interior location within s.
 */
static char *
trim_inplace(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }
    return s;
}

/*
 * parse_ini_key_value — extract the value for a given key from an INI line.
 *
 * WHAT: checks whether the trimmed line matches "<key> = <value>" (whitespace
 *       around '=' is tolerated); on match copies the trimmed value into out[outsz].
 * WHY:  shared between the access-key and secret-key extraction so each has one
 *       call site with the same logic.
 * HOW:  look for '='; split; trim both sides; compare the key; copy the value.
 *       Returns 1 on match, 0 otherwise.  out is always NUL-terminated within outsz.
 *       Mutates buf in place (NUL-terminates at '=').
 */
static int
parse_ini_key_value(char *buf, const char *key,
                    char *out, size_t outsz)
{
    /* mutates buf in place */
    char *eq    = strchr(buf, '=');
    char *lkey;
    char *lval;

    if (eq == NULL) {
        return 0;
    }
    *eq  = '\0';
    lkey = trim_inplace(buf);
    lval = trim_inplace(eq + 1);

    if (strcmp(lkey, key) != 0) {
        return 0;
    }
    snprintf(out, outsz, "%s", lval);
    return 1;
}

/*
 * parse_aws_credentials_default — read the [default] section of an AWS
 * credentials file and extract the access key and secret.
 *
 * WHAT: opens the credentials file at `path` and scans it line by line;
 *       populates access_out[access_sz] and secret_out[secret_sz] when
 *       the [default] section's two keys are found.
 * WHY:  minimal INI reader — no third-party dependency, handles only the
 *       fields the S3 handler needs.
 * HOW:  track `in_default` flag: set on "[default]", cleared on any other
 *       "[section]" header.  Extract aws_access_key_id and aws_secret_access_key
 *       while in_default; stop early once both are found.
 *       Returns 1 iff both access_out and secret_out are non-empty.
 */
static int
parse_aws_credentials_default(const char *path,
                               char *access_out, size_t access_sz,
                               char *secret_out,  size_t secret_sz)
{
    FILE *f;
    char  line[1024];
    int   in_default    = 0;
    int   got_access    = 0;
    int   got_secret    = 0;

    access_out[0] = '\0';
    secret_out[0] = '\0';

    f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }

    while (fgets(line, (int)sizeof(line), f) != NULL) {
        char *t = trim_inplace(line);

        /* Skip blank lines and comments. */
        if (t[0] == '\0' || t[0] == '#' || t[0] == ';') {
            continue;
        }

        /* Section header. */
        if (t[0] == '[') {
            in_default = (strcmp(t, "[default]") == 0) ? 1 : 0;
            continue;
        }

        if (!in_default) {
            continue;
        }

        if (!got_access) {
            char tmp[S3KEY_BUFSZ];
            if (parse_ini_key_value(t, "aws_access_key_id",
                                    tmp, sizeof(tmp)) && tmp[0] != '\0') {
                snprintf(access_out, access_sz, "%s", tmp);
                got_access = 1;
            }
        }
        if (!got_secret) {
            char tmp[S3KEY_BUFSZ];
            if (parse_ini_key_value(t, "aws_secret_access_key",
                                    tmp, sizeof(tmp)) && tmp[0] != '\0') {
                snprintf(secret_out, secret_sz, "%s", tmp);
                got_secret = 1;
            }
        }

        if (got_access && got_secret) {
            break;   /* found both keys; no need to read further */
        }
    }

    fclose(f);
    return (got_access && got_secret) ? 1 : 0;
}

/*
 * try_credentials_file — attempt to read ~/.aws/credentials using $HOME.
 *
 * WHAT: builds the credentials path as $HOME/.aws/credentials; delegates to
 *       parse_aws_credentials_default.
 * WHY:  isolated from discover_s3_keys so the path-construction logic has one
 *       home and can be unit-tested independently.
 * HOW:  getenv("HOME"); snprintf the path; call parse_aws_credentials_default.
 *       Returns 1 iff both keys were found.  Returns 0 if $HOME is absent.
 */
static int
try_credentials_file(char *access_out, size_t access_sz,
                     char *secret_out,  size_t secret_sz)
{
    const char *home = getenv("HOME");
    char        path[XRDC_PATH_MAX];

    if (home == NULL || home[0] == '\0') {
        return 0;
    }
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    return parse_aws_credentials_default(path, access_out, access_sz,
                                         secret_out, secret_sz);
}

/* key discovery */
/*
 * discover_s3_keys — probe all three discovery levels; fill access + secret.
 *
 * WHAT: tries cfg override → environment → ~/.aws/credentials in order;
 *       returns 1 iff a complete (access + secret) pair was found.
 * WHY:  single authoritative resolution path shared by available() and acquire()
 *       so both always agree on whether keys are present.
 * HOW:  three explicit, ordered checks with early-return on the first complete
 *       pair.  Partial pairs (access without secret or vice-versa) are skipped
 *       so a misconfigured override does not shadow a good env / file pair.
 */
static int
discover_s3_keys(const xrdc_cred_config *cfg,
                 char *access_out, size_t access_sz,
                 char *secret_out,  size_t secret_sz)
{
    const char *env_access;
    const char *env_secret;

    /* Level 1: explicit cfg fields (both must be present and non-empty). */
    if (cfg != NULL
        && cfg->s3_access != NULL && cfg->s3_access[0] != '\0'
        && cfg->s3_secret != NULL && cfg->s3_secret[0] != '\0') {
        snprintf(access_out, access_sz, "%s", cfg->s3_access);
        snprintf(secret_out, secret_sz, "%s", cfg->s3_secret);
        return 1;
    }

    /* Level 2: environment variables (both must be set and non-empty). */
    env_access = getenv("AWS_ACCESS_KEY_ID");
    env_secret = getenv("AWS_SECRET_ACCESS_KEY");
    if (env_access != NULL && env_access[0] != '\0'
        && env_secret != NULL && env_secret[0] != '\0') {
        snprintf(access_out, access_sz, "%s", env_access);
        snprintf(secret_out, secret_sz, "%s", env_secret);
        return 1;
    }

    /* Level 3: ~/.aws/credentials [default] section. */
    return try_credentials_file(access_out, access_sz, secret_out, secret_sz);
}

/* handler callbacks */
/*
 * s3keys_available — 1 iff a complete S3 key pair is obtainable.
 *
 * WHAT: fast probe for auth pre-flight diagnostics and xrdc_cred_available().
 * WHY:  must mirror acquire() — if available() returns 1, acquire() must succeed.
 * HOW:  discover_s3_keys into scratch buffers; result is the return value.
 */
static int
s3keys_available(const xrdc_cred_config *cfg)
{
    char access[S3KEY_BUFSZ];
    char secret[S3KEY_BUFSZ];
    return discover_s3_keys(cfg, access, sizeof(access), secret, sizeof(secret));
}

/*
 * s3keys_acquire — discover the S3 key pair and fill *out.
 *
 * WHAT: the store's acquire call for XRDC_CRED_S3KEYS.
 * WHY:  single canonical acquire path for AWS SigV4 credentials.
 * HOW:  1) discover_s3_keys into function-static buffers (lifetime contract);
 *       2) on failure → -1 + XRDC_EAUTH (no secret values in the message);
 *       3) fill out: kind=S3KEYS, s3_access=s_access, s3_secret=s_secret,
 *          not_after=0 (static keys have no per-use expiry).
 *
 * Lifetime of s_access / s_secret: declared static so they remain valid after
 * this function returns.  slot_store_view strdup's out->s3_{access,secret}
 * before any other acquire can overwrite the buffers.
 *
 * Secret values are NEVER written into st->msg or any log path.
 */
static int
s3keys_acquire(const xrdc_cred_config *cfg, xrdc_cred_view *out,
               int64_t *not_after, xrdc_status *st)
{
    /* static: must outlive this return so slot_store_view can strdup them */
    static char s_access[S3KEY_BUFSZ];
    static char s_secret[S3KEY_BUFSZ];

    if (!discover_s3_keys(cfg, s_access, sizeof(s_access),
                              s_secret, sizeof(s_secret))) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "s3keys: no S3 credentials found "
                        "(set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
                        "or add [default] to ~/.aws/credentials)");
        return -1;
    }

    out->kind      = XRDC_CRED_S3KEYS;
    out->path      = NULL;
    out->token     = NULL;
    out->s3_access = s_access;   /* static buffer; store deep-copies via slot_store_view */
    out->s3_secret = s_secret;   /* static buffer; store deep-copies via slot_store_view */

    *not_after = 0;   /* static keys have no per-use expiry */
    return 0;
}

/* handler accessor */
static const xrdc_cred_handler s_s3keys_handler = {
    .kind      = XRDC_CRED_S3KEYS,
    .available = s3keys_available,
    .acquire   = s3keys_acquire,
    .refresh   = NULL,   /* static keys are long-lived; rotation is operator-driven */
};

/*
 * xrdc_cred_s3keys — return the static S3-keys handler.
 *
 * WHAT: strong definition that overrides the weak accessor in cred.c.
 * WHY:  weak/strong pattern lets lib and test binaries link without every handler
 *       compiled in; this file provides the real S3-keys implementation.
 * HOW:  returns a pointer to the file-scoped static handler struct.
 */
const xrdc_cred_handler *
xrdc_cred_s3keys(void)
{
    return &s_s3keys_handler;
}
