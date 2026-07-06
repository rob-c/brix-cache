# Cache Authorization — Conformance & Best Practice

**Guarantee:** the read/staging cache reflects the backend's per-user permissions exactly.
No data leaks between groups, or between individual users within a group, through the cache.

This document states the invariant, explains the enforcement architecture, tells operators
how to configure a leak-free deployment, tells developers how to keep it leak-free, and shows
how to verify conformance.

---

## 1. The invariant

> **Cache transparency.** For every principal *P*, path *X*, and operation *op*, the
> authorization verdict is identical whether the bytes are served from the origin, the read
> cache, or the stage:
>
> ```
> verdict_cached(P, X, op)  ==  verdict_origin(P, X, op)
> ```
>
> The cache is a performance optimization that is **invisible to authorization**. A cache hit
> is authorized by exactly the same gate, on exactly the same namespace path, as a cache miss.

A violation of this invariant is a cross-user (or cross-group) data leak: principal A pulls an
object into the shared, content-addressed (path-only-keyed) cache, and principal B — whom the
backend would deny — is served A's bytes.

---

## 2. Enforcement architecture

Authorization is enforced at **the protocol handler's serve-path gate**, on **every** open of
an export path, against the **export-root namespace path** (never the physical cache-root
path). It is deliberately *not* pushed into the VFS/storage layer: the VFS is the identity-
agnostic storage-truth plane, reached by off-event-loop workers (TPC, FRM, scan, copy) that
carry no request/identity context and no wire to send a denial on. Impersonation already
brackets the VFS as the *mapped* user; the authorization *decision* belongs one layer up.

### The single-checkpoint rule (critical for developers)

The cache serve and fill helpers — `brix_open_resolved_file()` and
`brix_cache_open_or_fill()` — perform **zero** authorization. This is by design: they are the
byte-transfer machinery. Consequently **the protocol handler's gate is the *sole*
authorization checkpoint for a cached read.** If a serve path reaches those helpers without
running the gate first, it leaks.

For `root://` this checkpoint is `brix_open_cached_read()` in
`src/protocols/root/read/open_cache.c`, which runs the full three-tier gate:

```c
/* Same gate, same args, same namespace path as the direct/miss path
 * (open_request.c). Runs BEFORE the residency stat, so a denied principal
 * never even probes cache residency (no cache-hit timing oracle). */
if (brix_auth_gate(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
                     clean_path, acl_path, conf,
                     BRIX_AUTH_READ, 0) != NGX_OK) {
    return ctx->write_rc;
}
```

The three tiers, in order (`src/auth/authz/auth_gate.c`):

1. **authdb** (native `u/g/p` rules or XrdAcc) — per-DN / per-VO / per-host grants.
2. **VO ACL** (`brix_require_vo`) — VOMS VO membership vs path.
3. **token scope** — WLCG/SciToken `scope` claim vs path + access class.

`allow_write` is a global pre-gate checked before any handler.

### Per-protocol map

| Protocol | Where authorization runs | Cache-differential? |
|---|---|---|
| `root://` cached read | `open_cache.c` full 3-tier gate, before the residency stat | **Closed** — same gate as miss/direct. |
| `root://` prepare/stage | `prepare.c` runs the 3 tiers for existing **and** absent (`noerrs`) paths | **Closed** — a stage of a not-yet-materialised object still proves READ/STAGE rights. |
| WebDAV GET/HEAD/PROPFIND | `access.c` (NGINX access phase) runs **before** the content handler, for hit, miss, and direct alike | **No differential** — the access-phase gate covers a cached GET automatically. |
| S3 GET | `s3_verify_sigv4` + `s3_acc_check` run **pre-dispatch**, cache-independent | **No differential.** S3 is one credential per location; there is no per-user scope to leak across. |
| cvmfs / scvmfs | Public content cache (anonymous by design) | **Out of scope** — see §5. |

### Performance

Re-running the full gate on every hit is cheap: `brix_auth_gate` is fronted by an
**identity-scoped** two-level decision cache (`auth_gate.c`). L1 is per-worker and lockless; a
warm hit is a single hash probe (tens of ns) against the file open + sendfile that follows.
The key folds in the DN, VO list, and token scope, so User A's cached *grant* can never satisfy
User B's lookup. Only the first open of a given `(identity, path, level)` pays the full
evaluation, TTL-bounded so a revoked grant cannot outlive the window.

---

## 3. Operator best practice — configuring a leak-free deployment

1. **Enable an authorization backend on every cache node**, not just the origin. A cache node
   with no `brix_authdb` / `brix_require_vo` / token config is a *public* server — it will
   serve any authenticated (or anonymous) principal. Configure the cache node with the **same
   authorization policy as the origin it fronts.**
2. **Key policy on the logical namespace path**, e.g. `g cms /cms rl`. A remote-origin cache
   node roots at `/`; confirm your rule paths match the wire path the node sees (check the
   access log — it prints the resolved path and the denial reason).
3. **Turn on impersonation (`brix_impersonation map`) for multi-user nodes** so the actual file
   I/O runs as the mapped uid — defence in depth beneath the authorization gate. The gate
   decides *allow/deny*; impersonation ensures the bytes are read as the right kernel identity.
4. **Do not put private data behind a cvmfs node.** cvmfs is a public content-distribution
   cache and ignores credentials by design (§5).
5. **Prefer scoped tokens or VO/DN authdb rules over `allow_write`-only configs.** `allow_write`
   is coarse (whole-server read-only vs writable); per-path authz is what prevents cross-user
   reads.
6. **Verify after any config change** with the conformance suite (§6).

---

## 4. Developer best practice — keeping it leak-free

- **Any new cache/serve entry point must run `brix_auth_gate` (or the protocol's equivalent)
  against the export namespace path before reaching `brix_open_resolved_file` /
  `brix_cache_open_or_fill`.** Those helpers do not and will not authorize — that is the
  single-checkpoint contract.
- **Authorize on the *logical* export path, never the cache-root physical path.** Pass
  `clean_path` (wire path) and the export-root `acl_path` (from `brix_beneath_full_path`).
- **Gate before the residency `stat`.** Denying after probing residency leaks a cache-hit
  timing oracle.
- **Fill identity ≠ serve identity.** Origin fills use a service credential; therefore the
  *serve* must re-authorize the requesting principal. Never assume "it's in the cache, so it's
  already been authorized" — it was authorized for *whoever filled it*.
- **Prepare/stage authorize the path, not the object.** Authorization is a property of
  (identity, logical path); it must hold even when the object does not yet exist on disk.
- **Every change ships three tests:** success (authorized principal served), error (absent /
  not-found handling unchanged), and **security-negative** (a denied principal refused a cache
  hit).

---

## 4a. Physical exposure of cache/staging artifacts (hardened)

The protocol gate (§2) governs the *served* path, but the on-disk cache/staging artifacts are a
service-owned tree that aggregates many users' bytes. If those files are world/group-readable,
a mapped low-privilege uid (under `brix_impersonation map`, users land on real system uids) can
read another user's cached bytes — or the `.cinfo` residency bitmap, size, and mtime — by
**direct filesystem access**, bypassing the gate entirely. This matters most on shared
filesystems / login nodes.

**Landed hardening:** all cache/stage artifacts are created `0600` (files) / `0700` (dirs),
owner-writable but with no group/other bits. The decisive site is the cache tier
(`sd_cache.c`): the physical store file previously inherited the origin's group/other bits
(`snap.mode & 0777` → `0644`); it is now forced `0600`. This is safe because cache files are
created *and served as the worker* (never through the impersonation VFS), and the **client-facing
mode is decoupled** — it rides in the `.cinfo` record and is served by `sd_cache_stat()`, so
tightening the physical mode does not change what a client sees in `stat`. The `.cinfo` sidecar
and the `cstore`/`fetch`/`xmeta` fill paths are likewise `0600`/`0700`.

**Developer rule:** cache/stage store artifacts (`src/fs/cache/`, `src/fs/meta/` sidecars,
`src/fs/backend/cache/`) must be created `0600`/`0700`. Do **not** propagate the origin's
group/other permission bits onto the physical cache file — carry the client-facing mode in
`.cinfo` instead. Namespace file/dir modes (`origin_write.c`, `op_table.c`, `mkdir.c`, `mv.c`)
are the *served* file's real perms and must **not** be forced to `0600`.

## 4d. In-flight upload/staging temps — stage-private, publish-intended (hardened)

The write-side analog of §4a: an upload is written to a **temp** file that is later atomically
`rename`d onto the namespace object. Those temps were world-readable (`0644`), so under
`brix_impersonation map` a peer mapped uid could read another user's **in-progress** upload by
direct FS access — most acute for the resumable-PUT partial, which persists across requests and
restarts.

The subtlety: **`rename` preserves the temp's mode, so the temp mode becomes the final served
mode.** Forcing the temp to `0600` would therefore ship every object `0600` and break VO-shared
impersonated reads. The pattern is **stage-private, publish-intended**: write the temp `0600`
(private during the upload), then `fchmod(fd, final_mode)` on the still-open fd immediately
before the commit `rename`, restoring the client's intended mode. Landed in the staging
primitive (`brix_staged_file_t.final_mode`, `staged_file.c`), so it covers WebDAV PUT (main +
resume), S3 PUT, and chkpoint through one chokepoint; the fd-based `brix_commit_staged` takes a
`final_mode` param (`0` = leave-as-is, e.g. root:// POSC temps that the sd driver already
creates with the client's mode). The S3 multipart-assembly temp and the tier-staging
unknown-provenance fallback were likewise moved to `0600`.

**Developer rule:** any temp that will be `rename`d onto a namespace path must be created
`0600` and have its client-intended mode restored (`fchmod`) just before the commit — never
create the temp at the final mode. New stagers must go through `brix_staged_open` /
`brix_staged_open_resume` (which set `final_mode` for you), not open the temp directly.

## 4e. TPC (third-party copy) direction

A WebDAV `COPY` is authorized on `r->uri`, but the operation's *direction* determines whether
`r->uri` is read or written: a **PULL** (`Source:` header) writes `r->uri` (the local
destination), a **PUSH** / plain intra-server `COPY` reads it. The op mapping now returns
`BRIX_AOP_CREATE` for a PULL and `BRIX_AOP_READ` otherwise, so a read-only principal cannot
pull remote data onto a path it may not write. **Developer rule:** when an HTTP method's
read/write direction depends on a header (COPY/MOVE with Source/Destination), branch the
authorization op on that header — do not assume a fixed direction.

## 4b. Existence oracles (hardened)

A metadata op must authorize **before** it probes on-disk existence, or a denied principal
distinguishes "absent" (`kXR_NotFound`) from "present-but-denied" (`kXR_NotAuthorized`) — a
namespace-existence oracle. All read/metadata ops now gate-before-probe: `statx`, `stat`,
`cksum`, `fattr`, `locate`, and the read-**open** path (`open_request.c` — the gate now runs
before `brix_open_read_probe`, so a denied principal is refused, and is *not* forwarded
upstream, before existence is checked). The `manager_map` redirect that precedes auth is a
**config-prefix routing decision** (it matches configured path prefixes, not on-disk file
existence), so it does not leak per-file existence and needs no change.

**Developer rule:** any new path/metadata op authorizes against (identity, logical path)
*before* touching the filesystem for existence/type. The gate has no dependency on the probe
result, so it is always safe to run first.

## 4c. WebDAV native authdb + VO-ACL read parity (LANDED)

WebDAV's access-phase gate (`access.c`) enforced the xrdacc engine and token scope, but **not**
native `authdb` (per-DN/VO/host) or VO-ACL rules for reads — so a deployment expressing per-user
authz via native `authdb`/`require_vo` (as `root://` does) had no WebDAV equivalent, and a
cached WebDAV GET (the access-phase gate fronts the content handler for hit/miss/direct alike)
was ungated by those mechanisms.

**Landed.** Two directives — `brix_webdav_authdb <file>` and `brix_webdav_require_vo <path>
<vo>` — populate two loc-conf arrays (reusing the stream parsers `brix_parse_authdb` /
`brix_normalize_policy_path`, finalized under the export root at startup with
`brix_finalize_{authdb,vo}_rules`). The access-phase read gate runs
`brix_check_authdb_identity` + `brix_check_vo_acl_identity` — the **same helpers `root://`
uses** — against the resolved path and the already-populated request identity, for
non-write/non-OPTIONS methods. It is a no-op unless configured (the helpers return `NGX_OK` on
empty rule sets), so existing deployments are unaffected; writes keep their `allow_write` +
xrdacc + token-scope gates. Verified by `tests/test_mu_webdav_authz.py` (a reader is served
under a granted subtree but 403'd outside it, for GET/HEAD/PROPFIND).

**VO ACL over WebDAV (VOMS extraction — fixed).** `brix_webdav_require_vo` enforces VOMS VO
membership, which is now extracted correctly over the nginx-TLS WebDAV path. Two bugs were
closed: (1) `brix_voms_init` ran only from the stream postconfig, so a WebDAV-only deployment
(no `stream{}` block) never loaded libvomsapi and `brix_voms_available()` was false — WebDAV
now loads it when a location sets `brix_webdav_vomsdir`; (2) the per-TLS auth cache stores only
the DN, so cached follow-up requests dropped the VO — VOMS is now re-derived on both the
cache-hit and cache-miss auth paths. Verified: a VO=cms proxy is served and a VO=atlas proxy is
403'd under a `require_vo` rule (`test_mu_webdav_authz.py`).

## 5. cvmfs is public by design

`cvmfs://` / `scvmfs://` is a public content-distribution cache. Its content is
cryptographically signed and world-readable; it does not carry per-user backend permissions.
The conformance suite therefore holds cvmfs to *public* guardrails, not enforcement:
credentials are **ignored** and **no privilege is inferred** from a presented token (an
authenticated principal gets exactly what an anonymous one gets). **Do not front private,
per-user data with a cvmfs node** — use `root://`, WebDAV, or S3, which enforce per-user
authorization.

---

## 6. Verifying conformance

- **No-root smoke** (`PYTHONPATH=tests pytest tests/test_mu_cache_serve_authz.py`): stands up
  an anonymous origin behind a GSI+authdb cache (impersonation off) and asserts a denied
  principal is refused a resident cache **hit** while an authorized one is served. Runs as an
  ordinary uid.
- **Full suite** (`sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh`): ~225 cells
  across the [multi-user conformance suite](multiuser-conformance.md) — every cell asserts the
  cache-transparency invariant for a (principal, path, op, protocol). The leak-marked families
  (F1 cache-hit re-auth, F3 stage laundering, F4 prepare bypass, F5 cross-protocol, F8
  revocation) are the direct regression tests for this fix: a failure means the leak has been
  reintroduced.

**Definition of done:** `pytest -m leak` is green — every cache/stage serve reaches the same
verdict as the origin, for every principal.
