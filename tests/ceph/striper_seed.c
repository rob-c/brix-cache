/*
 * striper_seed.c — write a known file via libradosstriper, to simulate existing
 * Glasgow/RAL (stock XrdCeph) data for the in-place-migration spike. Throwaway.
 *
 *   gcc striper_seed.c -lradosstriper -lrados -o striper_seed && \
 *     ./striper_seed <pool> <soid> [size_bytes] [object_size] [stripe_unit] [stripe_count]
 */
#include <rados/librados.h>
#include <radosstriper/libradosstriper.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* zlib adler32 (mod 65521) — the common XRootD/XrdCks checksum. */
static unsigned long
adler32_buf(const unsigned char *d, size_t n)
{
    unsigned long a = 1, b = 0;
    size_t        i;
    for (i = 0; i < n; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; }
    return (b << 16) | a;
}

int
main(int argc, char **argv)
{
    rados_t            cl;
    rados_ioctx_t      io;
    rados_striper_t    st;
    const char        *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    const char        *pool = (argc > 1) ? argv[1] : "xrdtest";
    const char        *soid = (argc > 2) ? argv[2] : "atlas/data/file.root";
    size_t             size = (argc > 3) ? (size_t) strtoull(argv[3], NULL, 0) : (10u << 20);
    unsigned           osz  = (argc > 4) ? (unsigned) strtoul(argv[4], NULL, 0) : (4u << 20);
    unsigned           su   = (argc > 5) ? (unsigned) strtoul(argv[5], NULL, 0) : osz;
    unsigned           sc   = (argc > 6) ? (unsigned) strtoul(argv[6], NULL, 0) : 1;
    char              *buf;

    if (rados_create(&cl, "admin") < 0 || rados_conf_read_file(cl, conf) < 0
        || rados_connect(cl) < 0) { fprintf(stderr, "connect failed\n"); return 1; }
    if (rados_ioctx_create(cl, pool, &io) < 0) { fprintf(stderr, "ioctx\n"); return 1; }
    if (rados_striper_create(io, &st) < 0) { fprintf(stderr, "striper\n"); return 1; }

    /* explicit geometry. Striper and CephFS share Ceph's striping algorithm, so
     * (stripe_unit, stripe_count, object_size) define an identical offset→object
     * mapping; only the object NAME differs. */
    rados_striper_set_object_layout_stripe_unit(st, su);
    rados_striper_set_object_layout_stripe_count(st, sc);
    rados_striper_set_object_layout_object_size(st, osz);

    /* position-dependent pattern: each 8-byte word holds its own byte offset, so
     * any object/stripe mis-ordering after migration is detectable (a plain fill
     * would compare equal under a scrambled interleave). */
    buf = malloc(size);
    {
        size_t o;
        for (o = 0; o + 8 <= size; o += 8) {
            uint64_t v = (uint64_t) o;
            memcpy(buf + o, &v, 8);
        }
        for (; o < size; o++) { buf[o] = (char) (o & 0xff); }
    }

    if (rados_striper_write_full(st, soid, buf, size) < 0) {
        fprintf(stderr, "striper write failed\n"); return 1;
    }

    /* stamp an XrdCks checksum xattr on the first stripe, as a real XrdCeph
     * deployment would, so the migrator's carry + verify can be exercised. */
    {
        char first[1024], hex[16];
        snprintf(first, sizeof(first), "%s.%016x", soid, 0);
        snprintf(hex, sizeof(hex), "%08lx",
                 adler32_buf((const unsigned char *) buf, size));
        rados_setxattr(io, first, "user.XrdCks.adler32", hex, strlen(hex));
        printf("checksum: user.XrdCks.adler32=%s\n", hex);
    }
    printf("seeded striper soid '%s' in pool '%s': %zu bytes, "
           "object_size %u stripe_unit %u stripe_count %u "
           "(pattern: word@off==off)\n",
           soid, pool, size, osz, su, sc);

    free(buf);
    rados_striper_destroy(st);
    rados_ioctx_destroy(io);
    rados_shutdown(cl);
    return 0;
}
