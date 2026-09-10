/*
 * sss_id_unittest.c — standalone unit driver for the SSS identity registry.
 *
 * WHAT: Exercises sss_id.c end to end: bounded setters, the proxied-credential
 *       file reader, register/replace/unregister/find, the hard slot cap, and
 *       the entity view handed to the credential builder.
 * WHY:  The registry's whole value is that a lookup miss NEVER substitutes
 *       another identity.  That is a property no end-to-end test can show
 *       convincingly (a miss looks like an auth failure either way), so it is
 *       pinned here, at the only layer where the substitution would be visible.
 * HOW:  No harness: a `check()` macro counts failures and main() returns
 *       non-zero if any fired, so the Python wrapper
 *       (tests/test_release20_sss_unit.py) just asserts the exit status and the
 *       "all checks passed" line.
 *
 *   gcc -Wall -Wextra -Werror -I src -I client/lib -o /tmp/sss_id_ut \
 *       client/lib/auth/sss/sss_id.c src/core/compat/sss_entity.c \
 *       src/core/compat/sss_bf.c src/core/compat/crc32_ieee.c \
 *       client/lib/auth/sss/sss_id_unittest.c -lcrypto -pthread
 */
#include "sss_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void
check(const char *what, int ok)
{
    if (!ok) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}


/* ---- bounded setters ---- */

static void
test_ident_set(void)
{
    brix_sss_ident id;
    char           big[BRIX_SSS_ENT_VORG_MAX + 8];

    check("set: full entity",
          brix_sss_ident_set(&id, "alice", "cms", "production",
                             "cms,prod", "endo-blob") == 0);
    check("set: name kept",  strcmp(id.name, "alice") == 0);
    check("set: vorg kept",  strcmp(id.vorg, "cms") == 0);
    check("set: role kept",  strcmp(id.role, "production") == 0);
    check("set: grps kept",  strcmp(id.grps, "cms,prod") == 0);
    check("set: endo kept",  strcmp(id.endo, "endo-blob") == 0);
    check("set: no creds",   id.creds_len == 0);

    check("set: NULL fields are absent, not an error",
          brix_sss_ident_set(&id, "bob", NULL, "", NULL, NULL) == 0);
    check("set: absent vorg is empty", id.vorg[0] == '\0');
    check("set: absent role is empty", id.role[0] == '\0');

    memset(big, 'v', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    check("set: over-cap vorg fails closed",
          brix_sss_ident_set(&id, "bob", big, NULL, NULL, NULL) == -1);
    check("set: failed set leaves nothing behind", id.name[0] == '\0');

    big[BRIX_SSS_ENT_VORG_MAX - 1] = '\0';
    check("set: exactly cap-1 fits",
          brix_sss_ident_set(&id, "bob", big, NULL, NULL, NULL) == 0);

    check("set: NULL ident refused",
          brix_sss_ident_set(NULL, "a", NULL, NULL, NULL, NULL) == -1);
}


static void
test_ident_creds(void)
{
    brix_sss_ident id;
    uint8_t        blob[64];

    memset(blob, 0xA5, sizeof(blob));
    check("creds: base", brix_sss_ident_set(&id, "alice", NULL, NULL, NULL, NULL) == 0);
    check("creds: attach", brix_sss_ident_set_creds(&id, blob, sizeof(blob)) == 0);
    check("creds: length", id.creds_len == sizeof(blob));
    check("creds: bytes", memcmp(id.creds, blob, sizeof(blob)) == 0);

    check("creds: clear", brix_sss_ident_set_creds(&id, NULL, 0) == 0);
    check("creds: cleared length", id.creds_len == 0);

    check("creds: over-cap refused",
          brix_sss_ident_set_creds(&id, blob, BRIX_SSS_ENT_CREDS_MAX + 1) == -1);
    check("creds: NULL ident refused",
          brix_sss_ident_set_creds(NULL, blob, sizeof(blob)) == -1);
}


static void
test_entity_view(void)
{
    brix_sss_ident    id;
    brix_sss_entity_t ent;
    uint8_t           blob[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    check("view: set", brix_sss_ident_set(&id, "alice", "cms", NULL, "g1", NULL) == 0);
    check("view: creds", brix_sss_ident_set_creds(&id, blob, sizeof(blob)) == 0);
    brix_sss_ident_to_entity(&id, &ent);

    check("view: name points at the slot", ent.name == id.name);
    check("view: vorg points at the slot", ent.vorg == id.vorg);
    check("view: empty role becomes NULL", ent.role == NULL);
    check("view: grps set", ent.grps != NULL && strcmp(ent.grps, "g1") == 0);
    check("view: empty endo becomes NULL", ent.endo == NULL);
    check("view: creds carried", ent.creds == id.creds && ent.creds_len == sizeof(blob));

    brix_sss_ident_to_entity(NULL, &ent);
    check("view: NULL ident yields an empty entity",
          ent.name == NULL && ent.creds == NULL && ent.creds_len == 0);
    brix_sss_ident_to_entity(&id, NULL);   /* must not crash */
}


/* ---- proxied credential file ---- */

static void
test_creds_file(void)
{
    static const char TEMPLATE[] = "/tmp/brix_sss_id_ut_XXXXXX";
    char     path[sizeof(TEMPLATE)];
    uint8_t  buf[128];
    size_t   len = 0;
    uint8_t  payload[37];
    int      fd;

    memset(payload, 0x5A, sizeof(payload));
    memcpy(path, TEMPLATE, sizeof(path));
    fd = mkstemp(path);
    check("file: mkstemp", fd >= 0);
    if (fd < 0) {
        return;
    }
    check("file: write", write(fd, payload, sizeof(payload)) == (ssize_t) sizeof(payload));
    close(fd);

    check("file: read", brix_sss_creds_read_file(path, buf, sizeof(buf), &len) == 0);
    check("file: length", len == sizeof(payload));
    check("file: bytes", memcmp(buf, payload, sizeof(payload)) == 0);

    check("file: too small a buffer fails closed",
          brix_sss_creds_read_file(path, buf, 8, &len) == -1);
    check("file: failed read reports no length", len == 0);

    check("file: missing path fails",
          brix_sss_creds_read_file("/nonexistent/brix/sss/creds", buf,
                                   sizeof(buf), &len) == -1);
    check("file: NULL path fails",
          brix_sss_creds_read_file(NULL, buf, sizeof(buf), &len) == -1);
    check("file: empty path fails",
          brix_sss_creds_read_file("", buf, sizeof(buf), &len) == -1);
    check("file: a directory is not a credential",
          brix_sss_creds_read_file("/tmp", buf, sizeof(buf), &len) == -1);
    unlink(path);

    /* mkstemp rewrote the template in place; restore it before reusing it. */
    memcpy(path, TEMPLATE, sizeof(path));
    fd = mkstemp(path);
    check("file: mkstemp (empty)", fd >= 0);
    if (fd >= 0) {
        close(fd);
        check("file: an empty file is not a credential",
              brix_sss_creds_read_file(path, buf, sizeof(buf), &len) == -1);
        unlink(path);
    }
}


/* ---- the registry ---- */

static void
test_registry_basics(void)
{
    brix_sss_id_registry *reg = brix_sss_id_create();
    brix_sss_ident        alice, bob, got;

    check("reg: create", reg != NULL);
    if (reg == NULL) {
        return;
    }
    check("reg: starts empty", brix_sss_id_count(reg) == 0);

    check("reg: alice", brix_sss_ident_set(&alice, "alice", "cms", "prod", NULL, "e1") == 0);
    check("reg: bob",   brix_sss_ident_set(&bob, "bob", "atlas", NULL, NULL, NULL) == 0);

    check("reg: register alice", brix_sss_id_register(reg, "u1", &alice) == 0);
    check("reg: register bob",   brix_sss_id_register(reg, "u2", &bob) == 0);
    check("reg: count", brix_sss_id_count(reg) == 2);

    check("reg: find alice", brix_sss_id_find(reg, "u1", &got) == 0);
    check("reg: alice name", strcmp(got.name, "alice") == 0);
    check("reg: alice vorg", strcmp(got.vorg, "cms") == 0);
    check("reg: alice endo", strcmp(got.endo, "e1") == 0);

    check("reg: find bob", brix_sss_id_find(reg, "u2", &got) == 0);
    check("reg: bob name", strcmp(got.name, "bob") == 0);

    /* Replace in place: same lid, new identity, no new slot. */
    check("reg: replace u1", brix_sss_id_register(reg, "u1", &bob) == 0);
    check("reg: replace did not grow", brix_sss_id_count(reg) == 2);
    check("reg: replaced find", brix_sss_id_find(reg, "u1", &got) == 0);
    check("reg: replaced value", strcmp(got.name, "bob") == 0);

    /* The default slot is a slot like any other. */
    check("reg: default slot via NULL", brix_sss_id_register(reg, NULL, &alice) == 0);
    check("reg: default slot via \"\"", brix_sss_id_find(reg, "", &got) == 0);
    check("reg: default value", strcmp(got.name, "alice") == 0);

    check("reg: unregister", brix_sss_id_unregister(reg, "u2") == 0);
    check("reg: count after unregister", brix_sss_id_count(reg) == 2);
    check("reg: unregister twice fails", brix_sss_id_unregister(reg, "u2") == -1);
    check("reg: survivor still there", brix_sss_id_find(reg, "u1", &got) == 0);

    brix_sss_id_destroy(reg);
    brix_sss_id_destroy(NULL);   /* NULL-safe */
}


/*
 * The security property: an unregistered lid is a MISS, never a substitution.
 * A front end that got a fallback identity here would present one user's
 * request under another user's name.
 */
static void
test_registry_miss_is_fail_closed(void)
{
    brix_sss_id_registry *reg = brix_sss_id_create();
    brix_sss_ident        alice, got;

    check("miss: create", reg != NULL);
    if (reg == NULL) {
        return;
    }
    check("miss: alice", brix_sss_ident_set(&alice, "alice", "cms", NULL, NULL, NULL) == 0);
    check("miss: register", brix_sss_id_register(reg, "u1", &alice) == 0);

    memset(&got, 0xEE, sizeof(got));
    check("miss: unknown lid is a miss", brix_sss_id_find(reg, "u9", &got) == -1);
    check("miss: output zeroed on a miss", got.name[0] == '\0' && got.creds_len == 0);

    memset(&got, 0xEE, sizeof(got));
    check("miss: the sole slot is NOT a fallback for the default lid",
          brix_sss_id_find(reg, "", &got) == -1);
    check("miss: default-lid output zeroed", got.name[0] == '\0');

    memset(&got, 0xEE, sizeof(got));
    check("miss: a prefix does not match", brix_sss_id_find(reg, "u", &got) == -1);
    memset(&got, 0xEE, sizeof(got));
    check("miss: an extension does not match", brix_sss_id_find(reg, "u10", &got) == -1);

    check("miss: NULL registry fails", brix_sss_id_find(NULL, "u1", &got) == -1);
    check("miss: NULL out fails", brix_sss_id_find(reg, "u1", NULL) == -1);
    check("miss: register on NULL registry fails",
          brix_sss_id_register(NULL, "u1", &alice) == -1);
    check("miss: register NULL ident fails", brix_sss_id_register(reg, "u1", NULL) == -1);
    check("miss: unregister on NULL registry fails",
          brix_sss_id_unregister(NULL, "u1") == -1);
    check("miss: count of NULL is 0", brix_sss_id_count(NULL) == 0);

    brix_sss_id_destroy(reg);
}


static void
test_registry_bounds(void)
{
    brix_sss_id_registry *reg = brix_sss_id_create();
    brix_sss_ident        id;
    char                  lid[XRDC_SSS_LID_MAX + 8];
    int                   i, over = 0;

    check("bounds: create", reg != NULL);
    if (reg == NULL) {
        return;
    }
    check("bounds: ident", brix_sss_ident_set(&id, "alice", NULL, NULL, NULL, NULL) == 0);

    memset(lid, 'x', sizeof(lid) - 1);
    lid[sizeof(lid) - 1] = '\0';
    check("bounds: over-long lid refused", brix_sss_id_register(reg, lid, &id) == -1);
    lid[XRDC_SSS_LID_MAX - 1] = '\0';
    check("bounds: cap-1 lid accepted", brix_sss_id_register(reg, lid, &id) == 0);
    check("bounds: unregister it", brix_sss_id_unregister(reg, lid) == 0);

    for (i = 0; i < XRDC_SSS_ID_SLOTS_MAX + 4; i++) {
        char key[XRDC_SSS_LID_MAX];

        snprintf(key, sizeof(key), "u%d", i);
        if (brix_sss_id_register(reg, key, &id) != 0) {
            over++;
        }
    }
    check("bounds: the slot cap holds",
          brix_sss_id_count(reg) == XRDC_SSS_ID_SLOTS_MAX);
    check("bounds: the overflow was refused, not silently dropped", over == 4);

    brix_sss_id_destroy(reg);
}


int
main(void)
{
    test_ident_set();
    test_ident_creds();
    test_entity_view();
    test_creds_file();
    test_registry_basics();
    test_registry_miss_is_fail_closed();
    test_registry_bounds();

    if (failures == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d failures\n", failures);
    return 1;
}
