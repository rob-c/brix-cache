/* Archive metadata and MSS state transitions use the production decorator. */
#include "fs/backend/frm/sd_frm_arc_internal.h"
#include <assert.h>

typedef struct {
    int member, archive, poll, begin_error, list_error, durable;
    unsigned begins, polls, destroyed, names, stop;
} fixture;

static int residency(void *data, const char *key, off_t *size, time_t *mtime)
{
    fixture *f = data;
    if (size) { *size = 42; } if (mtime) { *mtime = 123; }
    return strstr(key, BRIX_ARC_SUFFIX) ? f->archive : f->member;
}

static int begin(void *data, const char *key)
{
    fixture *f = data; assert(key); f->begins++;
    if (f->begin_error) { errno = f->begin_error; return -1; }
    return 0;
}

static int poll(void *data, const char *key)
{
    fixture *f = data; assert(key); f->polls++; errno = EIO; return f->poll;
}

static int durable(void *data, const char *key)
{
    fixture *f = data;
    return strstr(key, BRIX_ARC_SUFFIX) ? f->durable : 0;
}

static int opened(void *data, const char *key)
{
    assert(data && key); errno = EACCES; return -1;
}

static int exchanged(void *data, const char *a, const char *b)
{
    assert(data && !strcmp(a, "/one") && !strcmp(b, "/two")); return 0;
}

static int mkpath(void *data, const char *key, mode_t bits)
{
    assert(data && !strcmp(key, "/one") && bits == 0700); return 0;
}

static int listed(void *data, const char *key,
    int (*cb)(void *, const char *, int), void *opaque)
{
    fixture *f = data; assert(key);
    if (f->list_error) { errno = f->list_error; return -1; }
    if (cb(opaque, "alpha", 0)) { return 0; }
    (void) cb(opaque, "dir", 1); return 0;
}

static int collect(void *data, const char *name, int is_dir)
{
    fixture *f = data; assert(name && (is_dir == 0 || is_dir == 1));
    f->names++; printf("entry:%s:%d\n", name, is_dir); return f->names == f->stop;
}

static void destroyed(void *data) { ((fixture *) data)->destroyed++; }

/* WHAT: Check metadata values from the actual sidecar codec.
 * WHY: Unsafe or malformed lines cannot create an archive member.
 * HOW: Query a known entry and enumerate only accepted member names. */
static void metadata(arc_ctx_t *ctx, const char *member, int expected)
{
    brix_zip_entry_t entry = {0}; time_t when = 0;
    int rc = arc_sidecar_lookup(ctx, "/dataset", member, &entry, &when);
    assert(rc == expected);
    if (rc == 1) {
        assert(!strcmp(entry.name, member) && entry.size == 7 && entry.lfh_off == 11
               && entry.crc == 0x1234 && when > 0);
    }
}

/* WHAT: Publish an actual sorted sidecar.
 * WHY: Dataset listings depend on stable ordering and exact member metadata.
 * HOW: Write unsorted entries, then read the original values back through the codec. */
static void roundtrip(arc_ctx_t *ctx)
{
    brix_zip_entry_t entries[2] = {{.name = "zeta", .size = 7, .lfh_off = 11, .crc = 0x1234},
                                 {.name = "alpha", .size = 7, .lfh_off = 11, .crc = 0x1234}};
    assert(arc_sidecar_write(ctx, "/dataset", entries, 2) == 0);
    metadata(ctx, "alpha", 1); metadata(ctx, "zeta", 1);
}

/* WHAT: Query residency and recall through external tape states.
 * WHY: An index does not itself make bytes online or durable.
 * HOW: Assert the public result and exact underlying recall-call counts. */
static void transition(arc_ctx_t *ctx, const char *operation, const char *key, int expected)
{
    int result; off_t size = -1; time_t when = -1;
    if (!strcmp(operation, "residency")) {
        result = brix_mss_arc_adapter.residency(ctx, key, &size, &when);
        if (result == BRIX_RESIDENCY_OFFLINE && ctx->inner->residency(ctx->ictx, key, NULL, NULL)
            == BRIX_RESIDENCY_ABSENT) { assert(size >= 0 && when > 0); }
    } else if (!strcmp(operation, "begin")) { result = brix_mss_arc_adapter.recall_begin(ctx, key); }
    else if (!strcmp(operation, "poll")) { result = brix_mss_arc_adapter.recall_poll(ctx, key); }
    else { assert(!strcmp(operation, "durable")); result = brix_mss_arc_adapter.on_tape(ctx, key); }
    assert(result == expected);
}

int main(int argc, char **argv)
{
    assert(argc == 12); fixture f = {.member = atoi(argv[4]), .archive = atoi(argv[5]),
        .poll = atoi(argv[6]), .begin_error = atoi(argv[7]), .list_error = atoi(argv[8]),
        .durable = atoi(argv[9]), .stop = (unsigned) atoi(argv[10])};
    brix_mss_adapter_t inner = {.residency = residency, .recall_begin = begin,
        .recall_poll = poll, .on_tape = durable, .open_online = opened,
        .exchange = exchanged, .list = listed, .mkpath = mkpath, .destroy = destroyed};
    if (!strcmp(argv[3], "no-list")) { inner.list = NULL; }
    if (!strcmp(argv[3], "no-durable")) { inner.on_tape = NULL; }
    if (!strcmp(argv[3], "no-exchange")) { inner.exchange = NULL; }
    if (!strcmp(argv[3], "no-mkdir")) { inner.mkpath = NULL; }
    arc_ctx_t *ctx = brix_mss_arc_create(&inner, &f, argv[1], 1, NULL); assert(ctx);
    const char *operation = argv[2], *key = argv[3]; int expected = atoi(argv[11]);
    if (!strcmp(operation, "metadata")) { metadata(ctx, key, expected); }
    else if (!strcmp(operation, "roundtrip")) { roundtrip(ctx); }
    else if (!strcmp(operation, "list")) {
        int rc = brix_mss_arc_adapter.list(ctx, !strcmp(key, "no-list") ? "/" : key, collect, &f);
        assert(rc == expected);
    } else if (!strcmp(operation, "exchange")) {
        const char *a = !strncmp(key, "no-", 3) ? "/one" : key;
        assert(brix_mss_arc_adapter.exchange(ctx, a, "/two") == expected);
        if (expected) { assert(errno == ENOTSUP); }
    } else if (!strcmp(operation, "mkdir")) {
        assert(brix_mss_arc_adapter.mkpath(ctx, "/one", 0700) == expected);
        if (expected) { assert(errno == ENOTSUP); }
    } else { transition(ctx, operation, key, expected); }
    printf("begins:%u polls:%u\n", f.begins, f.polls);
    brix_mss_arc_adapter.destroy(ctx); assert(f.destroyed == 1);
    brix_mss_arc_adapter.destroy(NULL); return 0;
}
