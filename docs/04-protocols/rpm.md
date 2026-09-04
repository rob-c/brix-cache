# The RPM repository mirror surface (`brix_rpm_mirror`)

**Status: source-verified 2026-08-19** against `src/protocols/rpm/`. This page
is the *wire* contract — what the mirror answers and why. The operator page is
[rpm-mirror.md](../05-operations/rpm-mirror.md); the other RPM plane, where you
publish your own repository instead of caching someone else's, is
[rpm-on-cvmfs.md](../05-operations/rpm-on-cvmfs.md).

There is no RPM *protocol*: a repository is static HTTP. What makes this a
surface rather than a `proxy_pass` is that the file NAMES carry the policy, and
one of them carries a checksum.

---

## 1. The four routes, read once

`src/protocols/rpm/rpm_classify.c` turns a decoded URI into exactly one route.
Every later decision — freshness window, verify-at-edge, metric row, log field
— reads that verdict rather than re-parsing the path.

| Route | Shape | Mutable? | Verified at the edge? |
|---|---|---|---|
| `repomd` | `…/repodata/repomd.xml[.asc\|.key]` | **yes** — the freshness root | no (nothing names its digest) |
| `metadata` | `…/repodata/<hex>-<name>` | no — the name IS the digest | **yes**, against that name |
| `package` | `…/*.rpm`, `…/*.drpm` | no, in practice | no — dnf checks the RPM header |
| `aux` | every other legal repository file | yes | no |

A path the grammar refuses is `400` (`414` when it is over the 1024-byte cap),
never `404`: answering "not found" would tell a traversal probe that its shape
was legal and only the target was absent. The traversal defense is the grammar
itself — a path that classifies cannot escape the store, because every
component that could escape is rejected.

The classifier is pure C over the caller's buffer, with no nginx types, which
is what lets the fill-side verify (`src/fs/cache/verify.c`) and the cache TTL
policy re-read a key with the **same** grammar the gate used.

---

## 2. Method matrix

| Method | Answer |
|---|---|
| `GET`, `HEAD` | serve from cache, or fill from upstream and serve |
| anything else | **405** + `Allow: GET, HEAD`, plus a `signal=rpmwrite` guard line |

The refusal happens at the gate, before the store is touched and before any
upstream connection exists. dnf never writes; a write here is a scanner looking
for a repository it can plant a package in.

---

## 3. Freshness

`brix_rpm_metadata_ttl` (default 60s) is stamped as the location's manifest
TTL, so it bounds the `repomd` route — and only it. Everything the classifier
called `metadata` or `package` is immutable and is never revalidated.

This is not this server's opinion about repositories: dnf sends
`Cache-Control: no-cache` + `Pragma: no-cache` on its `repomd.xml` fetch and on
nothing else (measured — phase-104 Appendix X, finding X-2). The client's own
`metadata_expire` is a **second** window stacked on this one, so keep this
short.

### 3.1 Warming the two files that come next (`brix_rpm_prefetch`)

A dnf run does not fetch `repomd.xml` for its own sake: EL9's dnf4 follows it
with `primary` and `filelists`, unconditionally, every time the index moved
(measured — Appendix X, finding X-3; `other` is never fetched). With
`brix_rpm_prefetch on` a repomd fetch that was a **fill** — a new index, not a
TTL re-read — warms those two objects on the thread pool while the client is
still reading the index that named them.

This is prediction, not speculation. The set comes from the `<location href>`
entries of the very bytes being served, so the mirror fetches what this
repository actually publishes rather than what a URL template guesses. And
`repomd.xml` is the one route here that is *not* self-verifying, so its
contents are treated as untrusted input: every href is re-read through the
classifier and warmed only if it lands on the `metadata` route. Anything else
— an absolute URL, a `..`, a leading `/`, an escape, a name that is not
digest-named — is logged and dropped. What survives is digest-named, so the
warm fill verifies against its own name exactly as a client-driven fill would
(§4).

It is off by default because it spends upstream bandwidth on behalf of a client
that may never arrive, and it is advisory in both directions: the response
being written never waits on it, and a warm fill that fails changes nothing a
client can observe — the object is simply fetched on demand later.

---

## 4. Verification — the name is the proof

`brix_cache_verify rpm-repodata` is the third self-addressing mode in this
tree, beside `cvmfs-cas` and `oci-digest`, and they share one dispatcher and
one fail-closed policy. On the `metadata` route the hex **length** in the
filename names the algorithm — 40 → sha1, 64 → sha256, 96 → sha384, 128 →
sha512 — and the staged part file is hashed under exactly that one before it
is published. A mismatch is discarded (or quarantined) and answered `502`; it
is never served, and never becomes a cache entry.

A file that merely *begins* with hex digits has no recognised length and is not
verified rather than being verified under a guessed function.

The mode is mandatory for this surface: a `brix_rpm_mirror` location
configured with any other `brix_cache_verify` value refuses to start, as does
one whose upstream is `http://` without `brix_rpm_mirror_insecure on`.

---

## 5. Cache key and store layout

The key is `r->uri` **verbatim**, so the on-disk tree mirrors the repository
tree and an operator can read the store with `find`. The export root anchors
at `/` — a mirror is a pure cache node with no local export tree, so the path
IS the key.

Fills go through the shared never-drop plane (T20), which coalesces a herd onto
one upstream GET and holds a waiter to its deadline. That is why a transient
upstream failure answers a keep-alive **`504` + `Retry-After`** rather than a
`502`: `404` means the repository says no, `503` means ask again, and
collapsing the two turns a mirror hiccup into a client-side dependency error.
A definitive upstream verdict is mapped instead — `404` → `404`, `401`/`403` →
`403` (relaying the challenge would make dnf prompt for credentials this mirror
cannot use), everything else → `502`.

---

## 6. Metrics

`src/observability/metrics/rpm.c`. Repository, package and version names are
unbounded wire data and appear in **no** label (INVARIANT #8):

| Family | Labels | Reads |
|---|---|---|
| `brix_rpm_requests_total` | `class` × `outcome` | 5 × 5 fixed-enum series, emitted even at zero |
| `brix_rpm_verify_fail_total` | — | repodata fills whose bytes did not hash to their own name |
| `brix_rpm_prefetch_total` | — | objects warmed by `brix_rpm_prefetch` (§3.1) |
| `brix_rpm_prefetch_fail_total` | — | warm fills that failed; invisible to clients, so this counter is the only place they show |

`class` = repomd\|metadata\|package\|aux\|bad;
`outcome` = hit\|fill\|local\|refused\|error. The interesting ratio is per
class: `repomd` is *expected* to miss on every TTL expiry, and averaging it
with the package hit rate hides both.

The same verdict is on every access-log line through `$rpm_class` and
`$brix_cache_status` — the cross-plane `HIT`/`MISS`/`NEGHIT`/`-`
vocabulary that replaced the plane-local `$rpm_cache` in phase 112.
`local` reads as `HIT` (served without touching the upstream); `refused`
and `error` are not cache dispositions and read as `-`, so a hit rate
computed from the log is never silently wrong — read those two off the
`outcome` label instead.

---

## 7. Guard signals

Two `signal=` tokens, both with shipped fail2ban assets under
`deploy/fail2ban/`:

- **`rpmwrite`** — a write-class method aimed at the mirror. No honest client
  produces one, so the jail ships `enabled = true` with `maxretry = 1`.
- **`rpm_tamper`** — a repodata fill whose bytes did not hash to the checksum
  in their own filename. The host on that line is the **upstream mirror**, not
  a client, so a ban takes the repository offline for everyone; the jail ships
  `enabled = false` on purpose. Nothing bad was cached either way — the client
  got a `502` and the line is the alert.

---

## 8. What this surface does not do

It does not sign, rewrite or re-index anything: bytes are served as the
upstream produced them, which is precisely what lets dnf's own GPG check mean
something (the mirror is not in the trust chain — see
[rpm-mirror.md](../05-operations/rpm-mirror.md) §4). It does not synchronise a
repository on a schedule — `brix_rpm_prefetch` warms two named files off a
fetch a client already made, which is not the same thing — and it does not
create one: `brixrpm createrepo`
does that, on the publishing side.
