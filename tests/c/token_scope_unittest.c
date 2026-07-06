/* WLCG token scope conformance — Layer-1 unit (ngx-free).
 *
 * WHAT: Standalone unit tests for brix_token_scope_path_matches() boundary
 *       semantics and the full parse/check_read/check_write surface.
 * WHY:  Ensures the path-prefix guard prevents "/data" matching "/database",
 *       correctly covers sub-paths, and that each WLCG storage.* permission
 *       maps to exactly the right read/write bits.
 * HOW:  Links scopes.c only; no nginx headers.  SCP-01..03 are the initial
 *       path-boundary skeleton; SCP-04..22 extend coverage to permission bits,
 *       empty/missing inputs, traversal raw behavior, and scope-count limits.
 *
 * NOTE: VER-* (wlcg.ver claim validation) cases live in
 *       token_conformance_test.c (Task 5) — wlcg.ver is not parsed by
 *       scopes.c.
 */
#include <stdio.h>
#include <string.h>
#include "auth/token/scopes.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void test_path_boundary(void)
{
    /* SCP-01: "/data" scope must NOT authorize "/database". */
    CHECK(brix_token_scope_path_matches("/data", "/database") == 0,
          "SCP-01 boundary /data != /database");
    CHECK(brix_token_scope_path_matches("/data", "/data/f") == 1,
          "SCP-02 /data covers /data/f");
    CHECK(brix_token_scope_path_matches("/", "/anything") == 1,
          "SCP-03 root scope covers all");
}

/* SCP-04..09: permission string → struct flag mapping. */
static void test_permission_bits(void)
{
    brix_token_scope_t scopes[8];
    int n;

    /* SCP-04: storage.read sets read=1, write/create/modify=0. */
    n = brix_token_parse_scopes("storage.read:/a", scopes, 8);
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/a") == 1,
          "SCP-04 storage.read grants read");
    CHECK(n == 1 && brix_token_check_write(scopes, n, "/a") == 0,
          "SCP-04 storage.read denies write");

    /* SCP-05: storage.write sets write=1, read=0. */
    n = brix_token_parse_scopes("storage.write:/a", scopes, 8);
    CHECK(n == 1 && brix_token_check_write(scopes, n, "/a") == 1,
          "SCP-05 storage.write grants write");
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/a") == 0,
          "SCP-05 storage.write denies read");

    /* SCP-06: storage.create sets create=1, treated as write-like. */
    n = brix_token_parse_scopes("storage.create:/a", scopes, 8);
    CHECK(n == 1 && brix_token_check_write(scopes, n, "/a") == 1,
          "SCP-06 storage.create grants write");
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/a") == 0,
          "SCP-06 storage.create denies read");

    /* SCP-07: storage.modify sets modify=1, treated as write-like. */
    n = brix_token_parse_scopes("storage.modify:/a", scopes, 8);
    CHECK(n == 1 && brix_token_check_write(scopes, n, "/a") == 1,
          "SCP-07 storage.modify grants write");
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/a") == 0,
          "SCP-07 storage.modify denies read");

    /* SCP-08: storage.stage sets read=1 only (staged = readable, not writable). */
    n = brix_token_parse_scopes("storage.stage:/a", scopes, 8);
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/a") == 1,
          "SCP-08 storage.stage grants read");
    CHECK(n == 1 && brix_token_check_write(scopes, n, "/a") == 0,
          "SCP-08 storage.stage denies write");

    /* SCP-09: unknown permission consumes one slot but grants no capability. */
    n = brix_token_parse_scopes("storage.bogus:/a", scopes, 8);
    CHECK(n == 1,
          "SCP-09 unknown perm consumes a slot");
    CHECK(brix_token_check_read(scopes, n, "/a") == 0,
          "SCP-09 unknown perm grants no read");
    CHECK(brix_token_check_write(scopes, n, "/a") == 0,
          "SCP-09 unknown perm grants no write");
}

/* SCP-10..11: edge inputs to brix_token_parse_scopes. */
static void test_empty_path_and_missing(void)
{
    brix_token_scope_t scopes[8];
    int n;

    /* SCP-10: empty path component after ":" defaults to "/" (matches everything). */
    n = brix_token_parse_scopes("storage.read:", scopes, 8);
    CHECK(n == 1 && brix_token_check_read(scopes, n, "/anything") == 1,
          "SCP-10 empty scope path defaults to /");

    /* SCP-11: empty scope string produces no entries. */
    n = brix_token_parse_scopes("", scopes, 8);
    CHECK(n == 0,
          "SCP-11 empty scope string returns 0");
}

/* SCP-12..14: extended path-boundary checks at the path_matches level. */
static void test_path_boundary_extended(void)
{
    /* SCP-12: word-boundary guard — "/data" must NOT match "/database". */
    CHECK(brix_token_scope_path_matches("/data", "/database") == 0,
          "SCP-12 boundary /data != /database");

    /* SCP-13: trailing "/" on scope_path is stripped before prefix comparison. */
    CHECK(brix_token_scope_path_matches("/data/", "/data/x") == 1,
          "SCP-13 trailing-slash trimmed: /data/ covers /data/x");

    /* SCP-14: scope_path without trailing slash is a proper prefix of sub-path. */
    CHECK(brix_token_scope_path_matches("/data", "/data/x") == 1,
          "SCP-14 /data covers sub-path /data/x");
}

/* SCP-15..16: cross-permission denials. */
static void test_permission_cross_check(void)
{
    brix_token_scope_t scopes[8];
    int n;

    /* SCP-15: write-only token must NOT grant read access. */
    n = brix_token_parse_scopes("storage.write:/a", scopes, 8);
    CHECK(brix_token_check_read(scopes, n, "/a") == 0,
          "SCP-15 read denied on write-only scope");

    /* SCP-16: read-only token must NOT grant write access. */
    n = brix_token_parse_scopes("storage.read:/a", scopes, 8);
    CHECK(brix_token_check_write(scopes, n, "/a") == 0,
          "SCP-16 write denied on read-only scope");
}

/* SCP-17..20: raw (unresolved) traversal behavior. */
static void test_traversal_raw_behavior(void)
{
    brix_token_scope_t scopes[8];
    int n;

    /*
     * The scope layer performs a pure string-prefix match — it does NOT
     * collapse "..".  "/a/../b" starts with "/a" followed by '/', so the
     * boundary check passes and the scope layer grants access.
     *
     * This proves canonicalization MUST happen upstream (INVARIANT §4):
     * the scope layer does NOT collapse '..'.  Wire-level SCP tests (pytest)
     * prove the resolved path is canonical before this is reached.
     */
    n = brix_token_parse_scopes("storage.read:/a", scopes, 8);

    /* SCP-17: check_read with an unresolved dotdot — raw prefix match grants it. */
    CHECK(brix_token_check_read(scopes, n, "/a/../b") == 1,
          "SCP-17 raw: check_read grants /a/../b (must canonicalize upstream)");

    /* SCP-18: scope_path_matches raw — /a/../b prefixes /a with next='/' → 1. */
    CHECK(brix_token_scope_path_matches("/a", "/a/../b") == 1,
          "SCP-18 raw: scope_path_matches /a vs /a/../b == 1 (no dotdot collapse)");

    /* SCP-19: a path on a different subtree is denied even by raw matching. */
    CHECK(brix_token_scope_path_matches("/a", "/b") == 0,
          "SCP-19 raw: /a does not match /b");

    /* SCP-20: scope "/a" does not match "/ab" — boundary check rejects non-'/' next char. */
    CHECK(brix_token_scope_path_matches("/a", "/ab") == 0,
          "SCP-20 boundary: /a does not match /ab");
}

/* SCP-21..22: max-scopes truncation and multi-scope OR semantics. */
static void test_scope_limits(void)
{
    brix_token_scope_t scopes[8];
    int n;

    /* SCP-21: parse stops at max_scopes even when the string contains more entries. */
    n = brix_token_parse_scopes(
        "storage.read:/p0 storage.read:/p1 storage.read:/p2 storage.read:/p3"
        " storage.read:/p4 storage.read:/p5 storage.read:/p6 storage.read:/p7"
        " storage.read:/p8 storage.read:/p9",
        scopes, 8);
    CHECK(n == 8,
          "SCP-21 10-entry string truncated to max_scopes=8");

    /* SCP-22: scopes are ORed — each permission applies only within its own path. */
    n = brix_token_parse_scopes("storage.read:/a storage.write:/b", scopes, 8);
    CHECK(n == 2 && brix_token_check_read(scopes, n, "/a") == 1,
          "SCP-22 multi-scope: read on /a granted");
    CHECK(n == 2 && brix_token_check_write(scopes, n, "/b") == 1,
          "SCP-22 multi-scope: write on /b granted");
    CHECK(n == 2 && brix_token_check_write(scopes, n, "/a") == 0,
          "SCP-22 multi-scope: write on /a denied (write scope covers /b only)");
}

/* --------------------------------------------------------------------------
 * RFC scope-layer conformance
 * (RFC 6749 §3.3, WLCG/SciTokens rules 97, 113, 117, 139-140)
 * -------------------------------------------------------------------------- */
static void test_scope_rfc_conformance(void)
{
    brix_token_scope_t scopes[8];
    int                n;

    /*
     * RFC117-sibling-boundary (rule citation re-affirmation):
     * Rule 117 [SEC]: path authorisation is on segment boundaries;
     * "/foo" MUST NOT authorise "/foobar" (the sibling-path CVE class).
     * Already covered as SCP-01/SCP-12; re-confirmed here with the rule id
     * for traceability to docs/10-reference/wlcg-token-rfc-rules.md.
     */
    CHECK(brix_token_scope_path_matches("/foo", "/foobar") == 0,
          "RFC117-sibling-boundary");

    /*
     * RFC3986-139-no-normalize-DIVERGENCE:
     * Rule 139 [SEC] (SciTokens v2.0): "$PATH MUST be normalised per
     * RFC 3986 before compare" — ".." MUST be resolved.  A normalised
     * "/foo/../bar" collapses to "/bar" and would then match request_path
     * "/bar" (returning 1).
     * Actual: brix_token_scope_path_matches() performs a pure strncmp —
     * it does NOT normalise ".." in the scope path.  strncmp("/foo/../bar",
     * "/bar", 11) fails at the first character difference → returns 0.
     * The result is conservative (safer) in this specific case, but scope
     * paths embedded in tokens are never normalised by this layer.
     * Architecture note: canonicalisation of the REQUEST path is done
     * upstream via resolve_path() (INVARIANT §4); scope-path normalisation
     * is not implemented and would require a separate pass over the scope
     * claim at parse time.
     */
    CHECK(brix_token_scope_path_matches("/foo/../bar", "/bar") == 0,
          "RFC3986-139-no-normalize-DIVERGENCE");

    /*
     * RFC6749-97-charset-DIVERGENCE:
     * Rule 97: scope-token charset is 1*(%x21/%x23-5B/%x5D-7E), which
     * excludes space (0x20), '"' (0x22), and '\' (0x5C).  A '"' embedded
     * in a scope path MUST be rejected.
     * Actual: brix_token_parse_scopes() copies the path verbatim with no
     * charset validation; '"' lands in scope->path unchanged.  The
     * embedded character is not rejected at the scope-parse layer.
     * Defense-in-depth would validate charset here; currently the caller
     * (validate.c) relies on well-formed tokens from trusted issuers.
     */
    n = brix_token_parse_scopes("storage.read:/a\"b", scopes, 8);
    CHECK(n == 1 && strcmp(scopes[0].path, "/a\"b") == 0,
          "RFC6749-97-charset-DIVERGENCE");
}

int main(void)
{
    test_path_boundary();
    test_permission_bits();
    test_empty_path_and_missing();
    test_path_boundary_extended();
    test_permission_cross_check();
    test_traversal_raw_behavior();
    test_scope_limits();
    printf("\n--- RFC scope-layer conformance (rules 97,117,139) ---\n");
    test_scope_rfc_conformance();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
