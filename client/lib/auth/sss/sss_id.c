/*
 * sss_id.c — per-connection SSS identity registry (the XrdSecsssID role).
 *
 * WHAT: Implements sss_id.h: bounded setters for one SSS entity, a file reader
 *       for a proxied credential, and a mutex-guarded lid → identity map.
 * WHY:  See sss_id.h.  The security property this file exists to hold is that a
 *       lookup miss is an ERROR, never a substitution: a front end that cannot
 *       find the caller's identity must fail the request rather than mint one
 *       under whatever identity happens to be at hand.
 * HOW:  A dynamic array of fixed-size slots, doubled on growth and capped at
 *       XRDC_SSS_ID_SLOTS_MAX.  Every mutator takes the registry mutex; find()
 *       copies the slot out under the same lock so a concurrent unregister
 *       cannot free the bytes a caller is still minting from.  Slots are wiped
 *       with an explicit_bzero-equivalent memset through a volatile pointer on
 *       removal and teardown so a proxied credential does not outlive its use.
 */
#include "sss_id.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char           lid[XRDC_SSS_LID_MAX];
    brix_sss_ident id;
} sss_id_slot;

struct brix_sss_id_registry {
    pthread_mutex_t  mu;
    sss_id_slot     *slots;
    size_t           n;
    size_t           cap;
};


/*
 * WHAT: Overwrite `len` bytes at `p` with zeroes in a way the compiler may not
 *       elide.
 * WHY:  A slot holds a proxied credential — bearer material.  A plain memset on
 *       memory that is about to be freed is a textbook dead-store elimination
 *       candidate, so the wipe has to go through a volatile pointer.
 * HOW:  Byte loop through a `volatile unsigned char *` (the portable idiom;
 *       explicit_bzero is not available everywhere the client builds).
 */
static void
sss_id_wipe(void *p, size_t len)
{
    volatile unsigned char *v = (volatile unsigned char *) p;

    while (len-- > 0) {
        *v++ = 0;
    }
}


/*
 * WHAT: Copy `src` into dst[cap], failing when it does not fit.
 * WHY:  Truncating an identity field silently is the bug class this whole
 *       feature is meant to avoid: a truncated VO or role is a DIFFERENT
 *       authorization claim, not a shorter one.  The server's parser fails the
 *       same way on an over-cap field, so the two ends agree.
 * HOW:  NULL/empty leaves dst empty and succeeds (the field is simply absent);
 *       otherwise strlen must be < cap.  Returns 0 / -1.
 */
static int
sss_id_set_field(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (src == NULL || src[0] == '\0') {
        dst[0] = '\0';
        return 0;
    }
    n = strlen(src);
    if (n >= cap) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}


int
brix_sss_ident_set(brix_sss_ident *id, const char *name, const char *vorg,
                   const char *role, const char *grps, const char *endo)
{
    if (id == NULL) {
        return -1;
    }
    memset(id, 0, sizeof(*id));

    if (sss_id_set_field(id->name, sizeof(id->name), name) != 0
        || sss_id_set_field(id->vorg, sizeof(id->vorg), vorg) != 0
        || sss_id_set_field(id->role, sizeof(id->role), role) != 0
        || sss_id_set_field(id->grps, sizeof(id->grps), grps) != 0
        || sss_id_set_field(id->endo, sizeof(id->endo), endo) != 0)
    {
        memset(id, 0, sizeof(*id));
        return -1;
    }
    return 0;
}


int
brix_sss_ident_set_creds(brix_sss_ident *id, const uint8_t *creds, size_t len)
{
    if (id == NULL) {
        return -1;
    }
    if (creds == NULL || len == 0) {
        sss_id_wipe(id->creds, sizeof(id->creds));
        id->creds_len = 0;
        return 0;
    }
    if (len > sizeof(id->creds)) {
        return -1;
    }
    memcpy(id->creds, creds, len);
    id->creds_len = len;
    return 0;
}


/* An empty string means "field absent", which the builder encodes as no TLV. */
static const char *
sss_id_or_null(const char *s)
{
    return (s != NULL && s[0] != '\0') ? s : NULL;
}


void
brix_sss_ident_to_entity(const brix_sss_ident *id, brix_sss_entity_t *ent)
{
    if (ent == NULL) {
        return;
    }
    memset(ent, 0, sizeof(*ent));
    if (id == NULL) {
        return;
    }
    ent->name = sss_id_or_null(id->name);
    ent->vorg = sss_id_or_null(id->vorg);
    ent->role = sss_id_or_null(id->role);
    ent->grps = sss_id_or_null(id->grps);
    ent->endo = sss_id_or_null(id->endo);
    if (id->creds_len > 0) {
        ent->creds = id->creds;
        ent->creds_len = id->creds_len;
    }
}


int
brix_sss_creds_read_file(const char *path, uint8_t *out, size_t out_max,
                         size_t *out_len)
{
    struct stat sb;
    size_t      got = 0;
    int         fd;

    if (path == NULL || path[0] == '\0' || out == NULL || out_len == NULL) {
        return -1;
    }
    *out_len = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)
        || sb.st_size <= 0 || (size_t) sb.st_size > out_max)
    {
        close(fd);
        return -1;
    }

    while (got < (size_t) sb.st_size) {
        ssize_t r = read(fd, out + got, (size_t) sb.st_size - got);
        if (r > 0) {
            got += (size_t) r;
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    close(fd);

    if (got != (size_t) sb.st_size) {
        sss_id_wipe(out, out_max);
        return -1;
    }
    *out_len = got;
    return 0;
}


brix_sss_id_registry *
brix_sss_id_create(void)
{
    brix_sss_id_registry *reg = calloc(1, sizeof(*reg));

    if (reg == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&reg->mu, NULL) != 0) {
        free(reg);
        return NULL;
    }
    return reg;
}


void
brix_sss_id_destroy(brix_sss_id_registry *reg)
{
    if (reg == NULL) {
        return;
    }
    if (reg->slots != NULL) {
        sss_id_wipe(reg->slots, reg->cap * sizeof(reg->slots[0]));
        free(reg->slots);
    }
    pthread_mutex_destroy(&reg->mu);
    free(reg);
}


/* Canonical key: NULL and "" both name the default slot. */
static const char *
sss_id_key(const char *lid)
{
    return (lid != NULL) ? lid : "";
}


/* Exact-match slot lookup; caller holds the lock.  NULL when absent. */
static sss_id_slot *
sss_id_slot_find(brix_sss_id_registry *reg, const char *lid)
{
    size_t i;

    for (i = 0; i < reg->n; i++) {
        if (strcmp(reg->slots[i].lid, lid) == 0) {
            return &reg->slots[i];
        }
    }
    return NULL;
}


/* Grow the slot array by doubling (from 8), honouring the hard cap. 0 / -1. */
static int
sss_id_grow(brix_sss_id_registry *reg)
{
    size_t       want = (reg->cap == 0) ? 8 : reg->cap * 2;
    sss_id_slot *next;

    if (reg->n < reg->cap) {
        return 0;
    }
    if (reg->n >= XRDC_SSS_ID_SLOTS_MAX) {
        return -1;
    }
    if (want > XRDC_SSS_ID_SLOTS_MAX) {
        want = XRDC_SSS_ID_SLOTS_MAX;
    }
    next = calloc(want, sizeof(*next));
    if (next == NULL) {
        return -1;
    }
    if (reg->slots != NULL) {
        memcpy(next, reg->slots, reg->n * sizeof(*next));
        sss_id_wipe(reg->slots, reg->cap * sizeof(*next));
        free(reg->slots);
    }
    reg->slots = next;
    reg->cap = want;
    return 0;
}


int
brix_sss_id_register(brix_sss_id_registry *reg, const char *lid,
                     const brix_sss_ident *id)
{
    const char  *key = sss_id_key(lid);
    sss_id_slot *slot;
    int          rc = -1;

    if (reg == NULL || id == NULL || strlen(key) >= XRDC_SSS_LID_MAX) {
        return -1;
    }

    pthread_mutex_lock(&reg->mu);
    slot = sss_id_slot_find(reg, key);
    if (slot == NULL && sss_id_grow(reg) == 0) {
        slot = &reg->slots[reg->n];
        memcpy(slot->lid, key, strlen(key) + 1);
        reg->n++;
    }
    if (slot != NULL) {
        slot->id = *id;
        rc = 0;
    }
    pthread_mutex_unlock(&reg->mu);
    return rc;
}


int
brix_sss_id_unregister(brix_sss_id_registry *reg, const char *lid)
{
    const char  *key = sss_id_key(lid);
    sss_id_slot *slot;
    int          rc = -1;

    if (reg == NULL) {
        return -1;
    }

    pthread_mutex_lock(&reg->mu);
    slot = sss_id_slot_find(reg, key);
    if (slot != NULL) {
        sss_id_wipe(slot, sizeof(*slot));
        *slot = reg->slots[reg->n - 1];
        sss_id_wipe(&reg->slots[reg->n - 1], sizeof(*slot));
        reg->n--;
        rc = 0;
    }
    pthread_mutex_unlock(&reg->mu);
    return rc;
}


int
brix_sss_id_find(brix_sss_id_registry *reg, const char *lid,
                 brix_sss_ident *out)
{
    const sss_id_slot *slot;
    int                rc = -1;

    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (reg == NULL) {
        return -1;
    }

    pthread_mutex_lock(&reg->mu);
    slot = sss_id_slot_find(reg, sss_id_key(lid));
    if (slot != NULL) {
        *out = slot->id;
        rc = 0;
    }
    pthread_mutex_unlock(&reg->mu);
    return rc;
}


size_t
brix_sss_id_count(brix_sss_id_registry *reg)
{
    size_t n;

    if (reg == NULL) {
        return 0;
    }
    pthread_mutex_lock(&reg->mu);
    n = reg->n;
    pthread_mutex_unlock(&reg->mu);
    return n;
}
