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
