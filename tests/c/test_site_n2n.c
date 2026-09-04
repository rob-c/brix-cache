/*
 * test_site_n2n.c — the tunable site name-translation (N2N) that maps a logical
 * path (LFN) to the physical name a backend addresses. Covers the real GridPP
 * Ceph schemes: RAL/Glasgow (RADOS object name "<pool>:<prefix><lfn>", pool split
 * by stock XrdCephOss::extractPool) and CephFS (POSIX path "<localroot><lfn>"),
 * plus identity. Pure libc; the reverse pfn2lfn powers the root directory listing.
 *
 * The C13.4 verification bar (phase-108): the canonicalizer folds "."/"//" and
 * REJECTS every ".." before a prefix is composed, the round-trip is exact on the
 * canonical corpus, extract_pool keeps its stock no-colon quirk, overflow is
 * ENAMETOOLONG (never truncation), and a randomized arm proves no crash / no
 * escape on adversarial bytes.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../src/fs/path/site_n2n.h"

/* ---- round-trip: pfn2lfn(lfn2pfn(x)) == x over a canonical corpus ---------
 * The corpus is already canonical (no ".", "..", "//") because lfn2pfn folds
 * those on the way out; the property under test is that the composed physical
 * name reverses exactly, including UTF-8, %-sequences and an embedded ':' (the
 * ':' must survive RAL's pool split, which keys on the FIRST colon only). */
static void
roundtrip(const brix_n2n_cfg_t *c, const char *lfn)
{
    char pfn[1024], back[1024];

    assert(brix_n2n_lfn2pfn(c, lfn, pfn, sizeof(pfn)) == 0);
    assert(brix_n2n_pfn2lfn(c, pfn, back, sizeof(back)) == 0);
    assert(strcmp(back, lfn) == 0);
}

static void
test_roundtrip_all_schemes(void)
{
    static const char *corpus[] = {
        "/atlas/rucio/f1",
        "/data/\xc3\xa9t\xc3\xa9/file",          /* UTF-8 "été" */
        "/store/data%2Fencoded",                 /* literal %-sequence bytes */
        "/ns/a:b/c",                             /* embedded colon in the LFN */
        "/x",
        "/deep/a/b/c/d/e/f/g",
    };
    brix_n2n_cfg_t c;
    size_t i;

    for (i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_IDENTITY;
        roundtrip(&c, corpus[i]);

        memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
        snprintf(c.pool, sizeof(c.pool), "atlas");
        snprintf(c.prefix, sizeof(c.prefix), "/store");
        roundtrip(&c, corpus[i]);

        memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
        snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
        roundtrip(&c, corpus[i]);
    }
}

/* ---- "."/"//" collapse: three spellings map to ONE physical name ----------
 * The live-lane W3 proof showed "/p/./x", "/p//x" and "/p/x" reach the stage
 * un-collapsed, so a regression here silently forks a client's object. Asserted
 * directly (per C13.4), not left to the round-trip. */
static void
test_dot_slash_collapse(void)
{
    brix_n2n_cfg_t c;
    char a[512], b[512], d[512];

    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "cms");
    snprintf(c.prefix, sizeof(c.prefix), "/store");

    assert(brix_n2n_lfn2pfn(&c, "/p/./x", a, sizeof(a)) == 0);
    assert(brix_n2n_lfn2pfn(&c, "/p//x",  b, sizeof(b)) == 0);
    assert(brix_n2n_lfn2pfn(&c, "/p/x",   d, sizeof(d)) == 0);
    assert(strcmp(a, b) == 0 && strcmp(b, d) == 0);
    assert(strcmp(d, "cms:/store/p/x") == 0);
}

/* ---- traversal is rejected BEFORE the prefix is composed ------------------
 * The named C13.2 case ("/a/../b" is refused, not resolved to "/b") plus the
 * ordering proof: a ".." fails even with a prefix set, because canonicalization
 * runs first — so the operator prefix can never carry a resolved traversal out
 * of the export. errno is EINVAL on the ".." refusal (not ENAMETOOLONG). */
static void
test_traversal_rejected_before_prefix(void)
{
    brix_n2n_cfg_t c;
    char pfn[512];

    /* the named C13.2 decision case */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_IDENTITY;
    errno = 0;
    assert(brix_n2n_lfn2pfn(&c, "/a/../b", pfn, sizeof(pfn)) == -1);
    assert(errno == EINVAL);

    /* ordering: a prefix is configured, yet ".." still fails and nothing that
     * looks like the prefix+target is produced */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    snprintf(c.prefix, sizeof(c.prefix), "/store");
    assert(brix_n2n_lfn2pfn(&c, "/a/../../etc/passwd", pfn, sizeof(pfn)) == -1);
    assert(brix_n2n_lfn2pfn(&c, "../x", pfn, sizeof(pfn)) == -1);
    c.scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
    assert(brix_n2n_lfn2pfn(&c, "/ok/../../bad", pfn, sizeof(pfn)) == -1);
}

/* ---- the flagship C13.2 decision, isolated on the canonicalizer -----------
 * "/a/../b" is REJECTED (EINVAL), never RESOLVED to "/b". This is the single
 * semantic that separates brix_n2n_canonicalize from the stock
 * XrdCephOss::normalize it replaced (which resolved ".."): a resolving
 * canonicalizer would let an operator prefix carry a client's write out of its
 * export. Pinned directly on the canonicalizer so the discovery is discoverable
 * from the test name alone, independent of any scheme. */
static void
test_a_dotdot_b_is_rejected_not_resolved(void)
{
    char out[512];

    /* fold: "." and "//" collapse — three spellings, one canonical path */
    assert(brix_n2n_canonicalize("/a/./b", out, sizeof(out)) == 0);
    assert(strcmp(out, "/a/b") == 0);
    assert(brix_n2n_canonicalize("/a//b", out, sizeof(out)) == 0);
    assert(strcmp(out, "/a/b") == 0);

    /* refuse: "/a/../b" is EINVAL, NOT rewritten to "/b". The distinguishing
     * negative — a resolving canonicalizer would have returned 0 with "/b". */
    errno = 0;
    assert(brix_n2n_canonicalize("/a/../b", out, sizeof(out)) == -1);
    assert(errno == EINVAL);
    assert(strcmp(out, "/b") != 0);           /* it was not resolved to /b */

    /* leading, trailing and deep ".." are equally refused */
    assert(brix_n2n_canonicalize("/../etc/passwd", out, sizeof(out)) == -1);
    assert(brix_n2n_canonicalize("/a/..", out, sizeof(out)) == -1);
    assert(brix_n2n_canonicalize("/a/b/../../c", out, sizeof(out)) == -1);

    /* a dotted filename is NOT a traversal component: "..foo"/"foo.." pass */
    assert(brix_n2n_canonicalize("/a/..foo/b", out, sizeof(out)) == 0);
    assert(strcmp(out, "/a/..foo/b") == 0);

    /* a path that folds to nothing becomes the bare root "/" (never empty) */
    assert(brix_n2n_canonicalize("/./", out, sizeof(out)) == 0);
    assert(strcmp(out, "/") == 0);

    printf("ok a_dotdot_b_is_rejected_not_resolved\n");
}

/* ---- behaviour-preserving migration: the sd_ceph key corpus ----------------
 * W3 folded sd_ceph's hand-rolled key derivation (its own normalize + string
 * concat) into a single brix_n2n_lfn2pfn call. A site's Pb+ of already-written
 * objects keep resolving ONLY if the new path emits byte-for-byte what the old
 * derivation did. These are the exact reference bytes for both live GridPP Ceph
 * conventions (RADOS "<pool>:<prefix><lfn>", CephFS "<localroot><lfn>") plus
 * identity — a migration corpus, asserted literally so a regression is loud. */
static void
test_ceph_key_derivation_byte_for_byte_migration(void)
{
    struct {
        brix_n2n_scheme_t scheme;
        const char       *pool;
        const char       *prefix;
        const char       *lfn;
        const char       *want;
    } corpus[] = {
        /* CephFS POSIX key = localroot + canonical(lfn) */
        { BRIX_N2N_CEPHFS_PATH, "", "/mnt/cephfs/atlas", "/rucio/f1",
          "/mnt/cephfs/atlas/rucio/f1" },
        /* the migration ALSO fixed the un-collapsed "./" fork (W3 live proof) */
        { BRIX_N2N_CEPHFS_PATH, "", "/mnt/cephfs/lancs", "/a/./b",
          "/mnt/cephfs/lancs/a/b" },
        /* RADOS object name = "<pool>:<prefix><lfn>" */
        { BRIX_N2N_RAL, "atlas", "/store", "/data/2024/f",
          "atlas:/store/data/2024/f" },
        /* RADOS with an empty prefix — pool colon then the bare LFN */
        { BRIX_N2N_RAL, "cms", "", "/x/y", "cms:/x/y" },
        /* identity export — the key is the LFN unchanged */
        { BRIX_N2N_IDENTITY, "", "", "/atlas/x", "/atlas/x" },
    };
    brix_n2n_cfg_t c;
    char           pfn[1024];
    size_t         i;

    for (i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        memset(&c, 0, sizeof(c));
        c.scheme = corpus[i].scheme;
        snprintf(c.pool, sizeof(c.pool), "%s", corpus[i].pool);
        snprintf(c.prefix, sizeof(c.prefix), "%s", corpus[i].prefix);

        assert(brix_n2n_lfn2pfn(&c, corpus[i].lfn, pfn, sizeof(pfn)) == 0);
        assert(strcmp(pfn, corpus[i].want) == 0);
    }
    printf("ok ceph_key_derivation_byte_for_byte_migration\n");
}

/* ---- extract_pool keeps its stock XrdCephOss quirk ------------------------ */
static void
test_extract_pool_quirk(void)
{
    char pool[256];
    const char *rest;

    assert(brix_n2n_extract_pool("atlas:/atlas/rucio/f1", pool,
                                 sizeof(pool), &rest) == 0);
    assert(strcmp(pool, "atlas") == 0);
    assert(strcmp(rest, "/atlas/rucio/f1") == 0);

    /* no colon → stock returns the whole string as the pool and *rest == "".
     * A "fix" here silently breaks interop with stock XrdCeph. */
    rest = NULL;
    assert(brix_n2n_extract_pool("noprefixhere", pool, sizeof(pool), &rest) == 0);
    assert(strcmp(pool, "noprefixhere") == 0);
    assert(rest != NULL && rest[0] == '\0');
}

/* ---- overflow is ENAMETOOLONG at the pool/prefix boundaries --------------- */
static void
test_overflow_boundaries(void)
{
    brix_n2n_cfg_t c;
    char pfn[16];

    /* result does not fit the destination → -1 / ENAMETOOLONG, never truncation */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    errno = 0;
    assert(brix_n2n_lfn2pfn(&c, "/atlas/rucio/f1", pfn, sizeof(pfn)) == -1);
    assert(errno == ENAMETOOLONG);

    /* a pool filled to its 127-byte usable bound (128 incl. NUL) still composes
     * when the destination is large enough — the boundary is honoured, not the
     * cause of a spurious failure */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    memset(c.pool, 'p', sizeof(c.pool) - 1);   /* 127 'p' + implicit NUL */
    {
        char big[1024];
        assert(brix_n2n_lfn2pfn(&c, "/x", big, sizeof(big)) == 0);
        assert(strncmp(big, c.pool, sizeof(c.pool) - 1) == 0);
        assert(big[sizeof(c.pool) - 1] == ':');
    }

    /* a prefix filled to its 255-byte usable bound (256 incl. NUL) likewise */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
    memset(c.prefix, 'r', sizeof(c.prefix) - 1);
    {
        char big[1024];
        assert(brix_n2n_lfn2pfn(&c, "/y", big, sizeof(big)) == 0);
        assert(strncmp(big, c.prefix, sizeof(c.prefix) - 1) == 0);
    }
}

/* ---- pfn2lfn confinement -------------------------------------------------- */
static void
test_pfn2lfn_confinement(void)
{
    brix_n2n_cfg_t c;
    char lfn[512];

    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
    assert(brix_n2n_pfn2lfn(&c, "/elsewhere/f", lfn, sizeof(lfn)) != 0);

    /* RAL: a pfn without the pool colon is not ours */
    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    assert(brix_n2n_pfn2lfn(&c, "no-colon-here", lfn, sizeof(lfn)) != 0);
}

/* ---- basic scheme spot-checks (retained from the original suite) ---------- */
static void
test_scheme_basics(void)
{
    char pfn[1024], lfn[1024];
    brix_n2n_cfg_t c;

    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_IDENTITY;
    assert(brix_n2n_lfn2pfn(&c, "/atlas/x", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "/atlas/x") == 0);
    assert(brix_n2n_pfn2lfn(&c, "/atlas/x", lfn, sizeof(lfn)) == 0);
    assert(strcmp(lfn, "/atlas/x") == 0);

    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_RAL;
    snprintf(c.pool, sizeof(c.pool), "atlas");
    assert(brix_n2n_lfn2pfn(&c, "/atlas/rucio/f1", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "atlas:/atlas/rucio/f1") == 0);

    memset(&c, 0, sizeof(c)); c.scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(c.prefix, sizeof(c.prefix), "/mnt/cephfs/atlas");
    assert(brix_n2n_lfn2pfn(&c, "/rucio/data/f", pfn, sizeof(pfn)) == 0);
    assert(strcmp(pfn, "/mnt/cephfs/atlas/rucio/data/f") == 0);
}

/* ---- randomized arm: no crash, no ".." escape ----------------------------
 * A cheap deterministic PRNG feeds adversarial LFNs (slashes, dots, colons,
 * high bytes) through every scheme. The stage must never crash and never let a
 * ".." component through: if lfn2pfn returns 0 the physical name must not carry
 * a "/../" or trailing "/.." — i.e. canonicalization actually removed it (it
 * cannot, so any accepted input simply had no ".." to begin with). */
static int
has_dotdot(const char *s)
{
    size_t n = strlen(s);
    size_t i;

    for (i = 0; i + 1 < n; i++) {
        if (s[i] == '.' && s[i + 1] == '.') {
            int lb = (i == 0) || s[i - 1] == '/';
            int rb = (i + 2 == n) || s[i + 2] == '/';
            if (lb && rb) {
                return 1;
            }
        }
    }
    return 0;
}

static void
test_fuzz_no_escape(void)
{
    static const char alpha[] = "/.:%ab\xff\xc3";
    unsigned long rng = 0x9e3779b97f4a7c15UL;
    brix_n2n_cfg_t schemes[3];
    char lfn[64], pfn[512];
    int  i, s, k, len;

    memset(&schemes[0], 0, sizeof(schemes[0]));
    schemes[0].scheme = BRIX_N2N_IDENTITY;
    memset(&schemes[1], 0, sizeof(schemes[1]));
    schemes[1].scheme = BRIX_N2N_RAL;
    snprintf(schemes[1].pool, sizeof(schemes[1].pool), "atlas");
    snprintf(schemes[1].prefix, sizeof(schemes[1].prefix), "/store");
    memset(&schemes[2], 0, sizeof(schemes[2]));
    schemes[2].scheme = BRIX_N2N_CEPHFS_PATH;
    snprintf(schemes[2].prefix, sizeof(schemes[2].prefix), "/mnt/x");

    for (i = 0; i < 20000; i++) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;   /* xorshift64 */
        len = (int) (rng % (sizeof(lfn) - 1));
        for (k = 0; k < len; k++) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            lfn[k] = alpha[rng % (sizeof(alpha) - 1)];
        }
        lfn[len] = '\0';
        for (s = 0; s < 3; s++) {
            if (brix_n2n_lfn2pfn(&schemes[s], lfn, pfn, sizeof(pfn)) == 0) {
                assert(!has_dotdot(pfn));   /* accepted ⇒ no ".." survived */
            }
        }
    }
}

int
main(void)
{
    test_scheme_basics();
    test_roundtrip_all_schemes();
    test_dot_slash_collapse();
    test_a_dotdot_b_is_rejected_not_resolved();
    test_ceph_key_derivation_byte_for_byte_migration();
    test_traversal_rejected_before_prefix();
    test_extract_pool_quirk();
    test_overflow_boundaries();
    test_pfn2lfn_confinement();
    test_fuzz_no_escape();

    printf("test_site_n2n: ALL PASS\n");
    return 0;
}
