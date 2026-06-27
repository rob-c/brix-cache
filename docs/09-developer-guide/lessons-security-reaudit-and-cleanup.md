# Lessons: security re-audit + the src/ & client/ cleanup pass

**Status:** Captured 2026-06-27. All code changes referenced here landed and build
clean under `-Werror`; each security fix has a test. This document is the durable
*why* — the reusable rules, not a changelog.

**Scope:** a `src/`/`client/` cleanup campaign (docblock de-slop, two real dedups,
function decomposition) followed by a security re-audit that produced four fixes.
Two arcs are worth remembering: a **scripted comment-edit that corrupted code**,
and four **security findings whose root cause is a recurring class** of mistake.

---

## Part 1 — Security lessons

### 1.1 SNI is not hostname verification

The most impactful finding. Several outbound TLS clients did this:

```c
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);   /* chain verified */
SSL_set_tlsext_host_name(ssl, host);              /* SNI only — NOT verification */
SSL_connect(ssl);
```

`SSL_VERIFY_PEER` validates the certificate **chain** (signed by a trusted CA, not
expired, etc.). It does **not** check that the cert's SAN/CN matches the host you
dialed. `SSL_set_tlsext_host_name` only sets the *outbound* SNI hint — it asks the
server which cert to send; it verifies nothing. So any cert signed by a trusted CA
(or, with `SSL_CTX_set_default_verify_paths`, any public-CA cert) for a host the
attacker controls is accepted → on-path MITM of the fetched data.

**Rule:** an OpenSSL *client* that verifies a peer MUST bind the expected name:

```c
SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
if (SSL_set1_host(ssl, expected_host) != 1) { /* fail */ }
```

`SSL_set1_host` folds an `X509_check_host` match into the handshake verification,
so a name mismatch fails `SSL_connect`. Grep audit:

```sh
# every client SSL_connect / TLS_client_method site MUST have a paired set1_host
grep -rln 'SSL_connect\|TLS_client_method' --include='*.c' src
grep -rn  'SSL_set1_host\|X509_VERIFY_PARAM_set1_host' --include='*.c' src
```

**Corollary — verify-vs-encrypt are different goals.** One connector intentionally
runs *encrypt-only* (`SSL_VERIFY_NONE` when no CA is configured; identity is carried
at a higher layer by GSI/token). Adding `SSL_set1_host` there would be a no-op —
host verification only means something when the chain is already being verified. Add
the host check **in the branch where verification is active**, and don't pretend an
encrypt-only channel is authenticated. (nginx-managed `ngx_ssl_*` upstream paths are
a separate case: they had *no* verification at all, which is a deliberate opt-in
feature decision — `proxy_ssl_verify`-style directive — not a one-line fix.)

### 1.2 Every MAC/secret comparison must be constant-time

A macaroon's HMAC-SHA256 signature was checked with `memcmp`:

```c
if (CRYPTO_memcmp(sig, provided_sig, 32) != 0) { /* reject */ }   /* fixed */
```

A timing-variable `memcmp` over a MAC is a byte-by-byte forgery oracle; for a
*bearer token* that is an auth-bypass surface. The tell here was **inconsistency**:
`handshake/sigver.c` and all of `dashboard/auth.c` already used `CRYPTO_memcmp` — the
macaroon and the TPC key-registry compares were simply missed.

**Rule:** compare any signature/MAC/shared-secret/key with `CRYPTO_memcmp`, never
`memcmp`/`strcmp`/`ngx_memcmp`. Audit:

```sh
grep -rnE '\b(memcmp|ngx_memcmp|strcmp)\b' --include='*.c' src \
  | grep -iE 'sig|hmac|mac|secret|key|token|digest|password'
```

**Gotcha for `strcmp` on a secret string:** constant-time requires equal-length,
content-independent comparison. For a fixed-capacity field (the TPC key lives in a
`char key[XROOTD_TPC_KEY_LEN]`, NUL-padded), copy the presented value into a
zero-filled buffer of that width and `CRYPTO_memcmp` the **whole field**, so timing
doesn't leak the matching-prefix length. Reject an over-long input up front.

### 1.3 Confinement boundaries drift — keep them uniform, and know where they aren't

The data plane reaches the filesystem two ways:

- WebDAV/S3 and the primary root:// open → `xrootd_open_beneath` =
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` — kernel-enforced, guards every
  path component.
- A few narrow server-managed paths (resume staging, cache-hit serving) use a raw
  `open()`. `O_NOFOLLOW` only guards the **final** component, not intermediates.

The cache-hit open was missing even `O_NOFOLLOW`. Low severity (the cache tree is
server-written, not client-controlled), but free defense-in-depth: a planted
symlink is now refused with `ELOOP` rather than followed out of the cache. **Rule:**
prefer the `RESOLVE_BENEATH` primitive everywhere; where a raw `open()` is genuinely
required, it must carry at least `O_NOFOLLOW | O_CLOEXEC` and a comment justifying
why the path is trusted.

### 1.4 Audit your own audit — calibrate severity before you write it down

Finding #6 ("root:// open isn't confined") was **over-stated**: a closer read showed
the primary client path already used `RESOLVE_BENEATH`; only one server-managed
branch was raw. The fix shrank from "rewrite the open path" to "add one flag."

**Rule:** before asserting a finding, read the *whole* call path and state the real
exploit precondition (who controls the input? is it network-reachable?). An audit
that cries wolf on already-mitigated code is as costly as one that misses a bug — it
burns the reviewer's trust and time. Distinguish *exploitable now* from
*defense-in-depth* from *parity-with-upstream-by-design* (e.g. SSS integrity is
CRC32-under-Blowfish — that is stock XRootD, not a new hole).

---

## Part 2 — Engineering-process lessons

### 2.1 A "comment-only" script can still corrupt code — `*` is both a separator and a declarator

The de-slop swept decorative `/* ---- … ---- */` banners across 85 files with a
title-preserving regex (safe). A **follow-up cleanup** regex meant to strip a stray
trailing ` *` from reflowed comment openers —

```perl
s{^(\s*/\*.*\S)\s+\*$}{$1}    # intended: strip a dangling " *" on a comment line
```

— also matched a compact one-line style some files use, `/* desc */TYPE *`, and
stripped the **pointer `*` from the return type**, turning `static char *` into
`static char`. The build broke (`-Werror=int-conversion`: "returns char, not
char *") in three files.

**Lessons:**
- ` *` is ambiguous: comment-continuation marker **and** pointer declarator. A regex
  that strips a trailing ` *` is unsafe tree-wide. Scope such edits to lines that are
  *purely* a comment (contain no `*/`), or hand-edit.
- The de-decoration pass itself (stripping `-{3,}` runs) was safe; the hazard was the
  artifact pass. **Separate the safe transform from the risky one** and reconsider the
  risky one's blast radius.
- **`-Werror` is the safety net that caught it.** A comment-only change that fails an
  `-Werror` build is, by definition, not comment-only — investigate, don't suppress.
  Recovery: `grep -rnE '\*/[A-Za-z]'` finds the merged `*/CODE` lines; restore the
  star on the pointer-returning ones; rebuild.
- This is the second instance of the standing rule (see `parse_x509` in the de-slop
  backlog memory): **never script code extraction/transformation in multi-function C
  files.** Comment *reflow* is fine *only* when the pattern can't alias code.

### 2.2 Test at the level you can make deterministic

For two fixes (TLS host-verify, cache `O_NOFOLLOW`) a faithful end-to-end test needs
a mismatched-cert TLS origin or a crafted cache tree — heavy, and historically flaky
on this host. Instead we wrote **self-contained C unit tests of the exact primitive
each fix relies on**: `X509_check_host` (what `SSL_set1_host` enforces) and
`open(O_NOFOLLOW)` symlink refusal. They are deterministic, fast, and guard the
security property; the *call site* is covered by the clean build + code review.

A first attempt used an in-process memory-BIO TLS handshake to be "more end-to-end."
It never converged (a harness bug), and its one "passing" assertion passed
**spuriously** because the handshake failed in *all* cases. **Lesson:** a negative
test that can pass for the wrong reason (the thing under test never ran) is worse
than no test. Always include a **positive control** (here: the matching-host cert
*is* accepted) so a harness that fails-everything is caught.

The other two fixes (macaroon, TPC key) were validated behaviorally end-to-end
because feasible harnesses already existed (`test_macaroon_negative.py`, the native
TPC pull) — prefer that when it's not flaky.

### 2.3 Inconsistency is a finding generator

Three of the four security issues were found not by deep analysis but by noticing the
codebase **already did the right thing elsewhere**: `crypto/ocsp.c` set the host,
`sigver.c` used `CRYPTO_memcmp`, the primary open used `RESOLVE_BENEATH`. Grepping for
"who does X" and then "who *should* but doesn't" is a high-yield audit technique —
the gaps are where a pattern was applied unevenly.

---

## Quick audit checklist (reusable)

```sh
# TLS clients: every verify site binds the host
grep -rln 'SSL_connect\|TLS_client_method' --include='*.c' src client
grep -rn  'SSL_set1_host' --include='*.c' src client

# MAC/secret compares are constant-time
grep -rnE '\b(memcmp|strcmp|ngx_memcmp)\b' --include='*.c' src \
  | grep -iE 'sig|hmac|mac|secret|key|token|digest|password'

# raw filesystem opens carry O_NOFOLLOW (or go through RESOLVE_BENEATH)
grep -rnE '\bopen(at)?\s*\(' --include='*.c' src \
  | grep -v 'O_NOFOLLOW\|beneath\|RESOLVE_BENEATH'

# scripted comment edits didn't merge a comment into code
grep -rnE '\*/[A-Za-z]' --include='*.c' src
```

## See also
- `postmortem-shmtx-semaphore-stall.md`, `postmortem-proxy-retry-leak.md` — debugging-arc postmortems.
- `adversarial-testing.md` — the evil-actor / fuzz suites.
- `coding-standards.md` — the no-`goto` / docblock rules the de-slop enforces.
- `../07-security/` — the security posture docs.
