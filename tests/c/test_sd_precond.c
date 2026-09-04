/*
 * test_sd_precond.c — the phase-107 C6 publish-precondition evaluator, pinned
 * against the REAL shipped ETag generator.
 *
 * WHAT: drives brix_sd_precond_eval_stat() and brix_sd_precond_absent()
 *       (src/fs/backend/sd_batch_types.h) — the one comparator every
 *       stat-grammar publish path shares: vfs_staged.c, vfs_copy.c,
 *       namespace_ops_copy.c (twice), sd_posix_staged.c, sd_frm_staged.c and
 *       sd_pblock_staged.c all reach this body, so its verdict IS the answer a
 *       conditional PUT/COPY gets on seven code paths.
 * WHY:  the header claims the comparison "never forks" from
 *       core/http/etag.h's grammar — but the evaluator formats its own tag with
 *       a second snprintf rather than calling brix_http_etag_str(). That is a
 *       fork by construction: two literals that agree today and nothing that
 *       says so. This unit links the REAL http/etag.o and compares the two, so
 *       a change to either side fails here instead of silently making every
 *       If-Match on the tree unsatisfiable (a 412 no client can ever clear).
 *       The refusal edges matter for the same reason in the other direction: a
 *       comparator that accepts a SHORT tag turns If-Match into a formality an
 *       attacker satisfies with a prefix, and a comparator that returns 0 for a
 *       kind it does not know publishes over a precondition it never evaluated.
 * HOW:  no spies and no nginx: the evaluator is a static inline over plain
 *       (off_t, time_t) and the generator is an ngx-free object, so the unit is
 *       the two real bodies and nothing else. Every etag input is BUILT by
 *       brix_http_etag_str rather than retyped, except where the case is
 *       precisely about a tag the generator would never emit.
 *
 * Cases (success + error + security-negative):
 *   success:      the strong tag the shipped generator emits is accepted for
 *                 the same (mtime, size), across a spread that includes zero
 *                 and the 64-bit extremes; the generator's WEAK form is
 *                 accepted too (RFC 7232 §2.3.2 weak comparison); MATCH_META
 *                 accepts an exact pair; a zeroed struct reads as NONE and
 *                 brix_sd_precond_absent() is NULL-safe.
 *   error:        MATCH_META refuses ECANCELED when EITHER field differs (each
 *                 pinned alone, so one field being ignored cannot pass);
 *                 MATCH_ETAG refuses the tag of a different resource.
 *   security-neg: a strict PREFIX of the true tag is refused — the length
 *                 equality is the whole defence, memcmp alone would accept it;
 *                 a tag with trailing bytes is refused; etag_len is honoured
 *                 rather than strlen, so an unterminated buffer never overreads
 *                 and never wins on its tail; a bare "W/" is not stripped
 *                 (the want_len > 2 guard) and refuses instead of reading past
 *                 it; a NULL tag refuses without a dereference; and every kind
 *                 the evaluator was not taught — NONE, ABSENT, and an
 *                 out-of-range future member — is ENOTSUP, never 0, so adding
 *                 an enum member cannot silently publish.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("sd_precond").
 */
#include "fs/backend/sd_batch_types.h"
#include "core/http/etag.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The (mtime, size) spread every etag case runs over: zero, an ordinary epoch,
 * and the extremes that stress both the %lx/%llx widths and the 48-byte
 * buffers on each side of the comparison. */
typedef struct {
    time_t  mtime;
    off_t   size;
} stat_pair_t;

static const stat_pair_t g_pairs[] = {
    { 0,             0 },
    { 1756900000,    4096 },
    { 1756900000,    5ULL * 1000 * 1000 * 1000 * 1000 },  /* 5 TB, C5's ceiling */
    { 2147483647,    2147483647 },                        /* 32-bit time_t edge */
    { (time_t) INT64_MAX, (off_t) INT64_MAX }             /* width extreme       */
};

#define NPAIRS  (sizeof(g_pairs) / sizeof(g_pairs[0]))

/* Build a precondition over a caller-supplied tag WITHOUT copying it: the
 * struct borrows the pointer, which is the contract the header states and the
 * reason the length must be carried separately. */
static brix_sd_precond_t
etag_precond(const char *tag, size_t len)
{
    brix_sd_precond_t pre;

    memset(&pre, 0, sizeof(pre));
    pre.kind     = BRIX_SD_PRECOND_MATCH_ETAG;
    pre.etag     = tag;
    pre.etag_len = len;
    return pre;
}

static brix_sd_precond_t
meta_precond(off_t size, time_t mtime)
{
    brix_sd_precond_t pre;

    memset(&pre, 0, sizeof(pre));
    pre.kind  = BRIX_SD_PRECOND_MATCH_META;
    pre.size  = size;
    pre.mtime = mtime;
    return pre;
}

/* Every refusal must set errno itself; a stale errno passing for a verdict is
 * how a refusal turns into the wrong wire status. Seed a value neither arm
 * uses so "the evaluator set it" is what the assertion reads. */
static int
refuses_with(brix_sd_precond_t *pre, off_t size, time_t mtime, int want_errno)
{
    errno = EOWNERDEAD;
    return brix_sd_precond_eval_stat(pre, size, mtime) == -1
           && errno == want_errno;
}

/* ---- success ------------------------------------------------------------- */

/* The claim the header makes in prose — "the shared body ... so the etag
 * comparison never forks" — as an assertion over the REAL generator. The
 * evaluator formats its own tag; this is the only thing that says the two
 * literals still agree. */
static void
test_success_generator_tag_is_accepted(void)
{
    char              tag[48];
    brix_sd_precond_t pre;
    size_t            i;

    for (i = 0; i < NPAIRS; i++) {
        brix_http_etag_str(tag, sizeof(tag), g_pairs[i].mtime, g_pairs[i].size,
                           0);
        assert(tag[0] == '"' && "the shipped strong grammar is quoted");
        pre = etag_precond(tag, strlen(tag));
        errno = 0;
        assert(brix_sd_precond_eval_stat(&pre, g_pairs[i].size,
                                         g_pairs[i].mtime) == 0
               && "the evaluator must accept the tag the tree emits");
    }
}

/* RFC 7232 §2.3.2: If-Match uses strong comparison, but a client that echoes
 * back the weak tag a PROPFIND handed it must still be able to publish — the
 * evaluator strips the caller's W/ rather than refusing it. The weak form is
 * taken from the generator, not retyped, so the prefix stays one fact. */
static void
test_success_weak_form_of_the_generator_is_accepted(void)
{
    char              weak[48];
    brix_sd_precond_t pre;
    size_t            i;

    for (i = 0; i < NPAIRS; i++) {
        brix_http_etag_str(weak, sizeof(weak), g_pairs[i].mtime,
                           g_pairs[i].size, BRIX_ETAG_WEAK);
        assert(weak[0] == 'W' && weak[1] == '/'
               && "the shipped weak grammar leads with W/");
        pre = etag_precond(weak, strlen(weak));
        errno = 0;
        assert(brix_sd_precond_eval_stat(&pre, g_pairs[i].size,
                                         g_pairs[i].mtime) == 0
               && "weak comparison must accept the generator's own weak tag");
    }
}

static void
test_success_match_meta_exact_pair(void)
{
    brix_sd_precond_t pre;
    size_t            i;

    for (i = 0; i < NPAIRS; i++) {
        pre = meta_precond(g_pairs[i].size, g_pairs[i].mtime);
        errno = 0;
        assert(brix_sd_precond_eval_stat(&pre, g_pairs[i].size,
                                         g_pairs[i].mtime) == 0);
    }
}

/* The fail-safe-by-zero discipline the header states: a caller who forgets to
 * fill the struct gets today's unconditional replace, never an accidental
 * refusal — and never an accidental create-if-absent. */
static void
test_success_zeroed_struct_is_none_and_absent_is_null_safe(void)
{
    brix_sd_precond_t zero;
    brix_sd_precond_t absent;
    brix_sd_precond_t etag;
    /* The macro dereferences its argument, so it types as the pointer every
     * caller actually holds — a bare NULL literal would not even compile. */
    const brix_sd_precond_t *none = NULL;

    memset(&zero, 0, sizeof(zero));
    assert(zero.kind == BRIX_SD_PRECOND_NONE);
    assert(zero.atomic == 0 && "the OUT bit starts clear, never claimed");
    assert(!brix_sd_precond_absent(&zero));
    assert(!brix_sd_precond_absent(none)
           && "no condition at all is not create-if-absent");

    memset(&absent, 0, sizeof(absent));
    absent.kind = BRIX_SD_PRECOND_ABSENT;
    assert(brix_sd_precond_absent(&absent));

    etag = etag_precond("\"0-0\"", 5);
    assert(!brix_sd_precond_absent(&etag)
           && "a compare-and-publish is not a create-if-absent");
}

/* ---- error --------------------------------------------------------------- */

/* Each field alone, so a comparator that dropped one of them cannot pass by
 * agreeing on the other. */
static void
test_error_match_meta_refuses_each_field_independently(void)
{
    brix_sd_precond_t pre = meta_precond(4096, 1756900000);

    assert(refuses_with(&pre, 4097, 1756900000, ECANCELED)
           && "a differing size must refuse");
    assert(refuses_with(&pre, 4096, 1756900001, ECANCELED)
           && "a differing mtime must refuse");
    assert(refuses_with(&pre, 4097, 1756900001, ECANCELED));
}

static void
test_error_match_etag_of_another_resource_refuses(void)
{
    char              other[48];
    brix_sd_precond_t pre;

    brix_http_etag_str(other, sizeof(other), 1756900000, 4096, 0);
    pre = etag_precond(other, strlen(other));
    assert(refuses_with(&pre, 8192, 1756900000, ECANCELED)
           && "the tag of a different version must not publish");
}

/* ---- security-negative --------------------------------------------------- */

/* memcmp over the CALLER's length would accept every prefix of the true tag —
 * `"` alone would satisfy any If-Match on the tree. The length equality is the
 * entire defence, so it gets its own case at every truncation point. */
static void
test_secneg_prefix_of_the_true_tag_is_refused(void)
{
    char              tag[48];
    brix_sd_precond_t pre;
    size_t            full, cut;

    brix_http_etag_str(tag, sizeof(tag), 1756900000, 4096, 0);
    full = strlen(tag);
    assert(full > 3);

    for (cut = 0; cut < full; cut++) {
        pre = etag_precond(tag, cut);
        assert(refuses_with(&pre, 4096, 1756900000, ECANCELED)
               && "no prefix of the true tag may satisfy a precondition");
    }
}

static void
test_secneg_trailing_bytes_after_the_true_tag_are_refused(void)
{
    char              buf[64];
    brix_sd_precond_t pre;
    size_t            full;

    brix_http_etag_str(buf, sizeof(buf), 1756900000, 4096, 0);
    full = strlen(buf);
    memcpy(buf + full, "AAAA", 5);
    pre = etag_precond(buf, full + 4);
    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED)
           && "a longer tag sharing the true prefix must refuse");
}

/* etag is bytes+len, not a C string: the comparison must read exactly
 * etag_len bytes. An unterminated window whose tail happens to hold the rest
 * of a valid tag must neither win nor be read past. */
static void
test_secneg_length_is_authoritative_not_nul_termination(void)
{
    char              tag[48];
    char              window[64];
    brix_sd_precond_t pre;
    size_t            full;

    brix_http_etag_str(tag, sizeof(tag), 1756900000, 4096, 0);
    full = strlen(tag);

    memset(window, 'Z', sizeof(window));
    memcpy(window, tag, full);              /* correct bytes, no terminator */
    pre = etag_precond(window, full);
    errno = 0;
    assert(brix_sd_precond_eval_stat(&pre, 4096, 1756900000) == 0
           && "the length, not a NUL, delimits the tag");

    pre = etag_precond(window, full - 1);   /* same buffer, short window   */
    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED)
           && "the byte after the window must not be consulted");
}

/* The weak-prefix strip is guarded by want_len > 2 so a two-byte "W/" cannot
 * advance the pointer past its own buffer. Pin the guard at its boundary. */
static void
test_secneg_bare_weak_marker_is_not_stripped(void)
{
    brix_sd_precond_t pre = etag_precond("W/", 2);

    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED)
           && "a bare W/ is not a tag and must not be stripped into one");

    pre = etag_precond("W/", 1);
    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED));

    pre = etag_precond("", 0);
    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED)
           && "an empty tag is a refusal, never a wildcard");
}

static void
test_secneg_null_tag_refuses_without_dereference(void)
{
    brix_sd_precond_t pre = etag_precond(NULL, 0);

    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED));

    /* A non-zero length with a NULL pointer is a caller bug; it must still
     * refuse rather than read from NULL. */
    pre = etag_precond(NULL, 8);
    assert(refuses_with(&pre, 4096, 1756900000, ECANCELED));
}

/* "A new enum member must be taught here explicitly, never silently passed."
 * NONE and ABSENT are not questions about (size, mtime) and reach the same
 * fail-closed tail as a member that does not exist yet — the property that
 * keeps a future kind from publishing over an unevaluated precondition. */
static void
test_secneg_untaught_kinds_are_enotsup_never_success(void)
{
    brix_sd_precond_t pre;

    memset(&pre, 0, sizeof(pre));
    pre.kind = BRIX_SD_PRECOND_NONE;
    assert(refuses_with(&pre, 4096, 1756900000, ENOTSUP)
           && "NONE is the caller's job, not a silent pass here");

    pre.kind = BRIX_SD_PRECOND_ABSENT;
    assert(refuses_with(&pre, 4096, 1756900000, ENOTSUP)
           && "ABSENT is the caller's job, not a silent pass here");

    pre.kind = (brix_sd_precond_kind_t) (BRIX_SD_PRECOND_MATCH_META + 1);
    assert(refuses_with(&pre, 4096, 1756900000, ENOTSUP)
           && "an untaught kind must refuse, never publish");

    pre.kind = (brix_sd_precond_kind_t) 0x7fffffff;
    assert(refuses_with(&pre, 4096, 1756900000, ENOTSUP));
}

/* The two 48-byte buffers — the generator's caller-supplied one and the
 * evaluator's private tag[48] — must both hold the widest grammar the type
 * ranges can produce, or the extremes silently compare truncated forms. */
static void
test_secneg_widest_grammar_fits_both_buffers(void)
{
    char   tag[48];
    size_t widest;

    brix_http_etag_str(tag, sizeof(tag), (time_t) INT64_MAX, (off_t) INT64_MAX,
                       BRIX_ETAG_WEAK);
    widest = strlen(tag);
    assert(widest < sizeof(tag) - 1
           && "the weak extreme must not fill the generator's buffer");
    /* W/ + quote + 16 hex + '-' + 16 hex + quote = 37; the evaluator's own
     * tag[48] holds the strong form (35) with the same margin. */
    assert(widest <= 37);
}

int
main(void)
{
    test_success_generator_tag_is_accepted();
    test_success_weak_form_of_the_generator_is_accepted();
    test_success_match_meta_exact_pair();
    test_success_zeroed_struct_is_none_and_absent_is_null_safe();
    test_error_match_meta_refuses_each_field_independently();
    test_error_match_etag_of_another_resource_refuses();
    test_secneg_prefix_of_the_true_tag_is_refused();
    test_secneg_trailing_bytes_after_the_true_tag_are_refused();
    test_secneg_length_is_authoritative_not_nul_termination();
    test_secneg_bare_weak_marker_is_not_stripped();
    test_secneg_null_tag_refuses_without_dereference();
    test_secneg_untaught_kinds_are_enotsup_never_success();
    test_secneg_widest_grammar_fits_both_buffers();

    printf("sd_precond: 13 cases OK\n");
    return 0;
}
