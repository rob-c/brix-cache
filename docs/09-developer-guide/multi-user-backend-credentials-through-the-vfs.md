# Multi-User Backend Credentials through the VFS

> **Architecture record.** How a cache/proxy node stopped speaking to its origin as a
> single service account and learned to authenticate to the backend *as the user who
> made the request* — through reads, writes, namespace ops, and detached write-back,
> without a single new global.
>
> **Scope:** davs · S3 · root:// → remote origin &nbsp;·&nbsp; **Backends:** xroot · http · s3 · ceph
> &nbsp;·&nbsp; **Delivered across:** Phase 1 (selection), Phase 2 (surfaces + capture), Phase 3 (completion + Ceph)
>
> **Companion operator reference:** [`docs/10-reference/per-user-backend-credentials.md`](../10-reference/per-user-backend-credentials.md)
> — that doc is the *how to configure it* guide; this one is the *how and why it was built* record.

---

## Contents

1. [The problem](#1-the-problem)
2. [The security invariant](#2-the-security-invariant)
3. [The credential journey](#3-the-credential-journey)
4. [`brix_sd_cred_t` and the four kinds](#4-brix_sd_cred_t-and-the-four-kinds)
5. [The gate — the sole checkpoint](#5-the-gate--the-sole-checkpoint)
6. [Forwarders and the leaf-unwrap](#6-forwarders-and-the-leaf-unwrap)
7. [The four hard problems](#7-the-four-hard-problems)
8. [Every surface that needed wiring](#8-every-surface-that-needed-wiring)
9. [The backend drivers](#9-the-backend-drivers)
10. [Bugs found and fixed](#10-bugs-found-and-fixed)
11. [Design decisions and rationale](#11-design-decisions-and-rationale)
12. [How it was proven](#12-how-it-was-proven)
13. [Limits and follow-ups](#13-limits-and-follow-ups)

---

## 1. The problem

A BriX cache/proxy node fronts a remote storage origin. Every user reaches it over
`davs://`, S3, or `root://`, authenticated by their own identity — a GSI cert DN, a WLCG
token subject, an S3 access key. But the node then reached the origin with **one static
service credential** configured on the export.

So on the wire between the node and the origin, *every* user's read, write, rename, and
delete looked identical: they all came from the service account. The origin could enforce
nothing per-user; audit logs named the proxy, not the person; and a deployment that
wanted the origin to see real identities simply couldn't have it. The credential stopped
at the front door.

The job: when a request is authenticated as user **U**, the origin session used for that
request's opens, reads, writes, and namespace operations must authenticate **as U's
credential** — falling back to the service credential only when policy allows, and
refusing loudly when it doesn't. The identity had to travel the whole storage plane:
`proto → VFS → backend → origin`.

> **The one rule that shaped everything.** The VFS is the *sole source of storage truth* —
> bytes, namespace, and metadata all funnel through `brix_vfs_*`. That constraint is also
> the leverage: thread identity into the VFS once, and every protocol inherits it. The whole
> feature is an exercise in getting a credential to the one seam below the VFS — the
> storage-driver vtable (`brix_sd_driver_t`) — and no further up.

---

## 2. The security invariant

One sentence governs the entire design. Every review, every test, and every bug below is
measured against it:

> **Invariant.** A request's origin operation authenticates as the **requesting user's**
> credential. In `fallback=deny` mode with no valid user credential, the operation fails
> with `EACCES` → 403 / `kXR_NotAuthorized` **before any origin operation touches the
> service credential**. A user must never ride the service credential — or another user's —
> in deny mode. A detached write-back flushes as the **original owner**, never the current
> requester or the service account (except an explicit allow-mode fallback).

Two words carry disproportionate weight:

- **Before** — the check must happen prior to opening the origin session, not after. A
  pre-flight probe that leaks a service-credential stat before the gate rejects is a
  violation, and one of them shipped and was caught (§10).
- **Owner** — the flusher runs minutes later, possibly after a restart, with no request
  context. So the identity must be *durable*, and re-resolving it at flush time is what
  makes expiry meaningful.

---

## 3. The credential journey

A single open travels this path. The credential is **selected** at the gate, **checked**
there (the deny checkpoint), and **presented** only at the leaf driver that knows how to
speak the origin's auth protocol. Everything between is plumbing that must not drop it.

```
  ┌───────────────────────────────────────────────────────────────┐
  │ Identity — set by the auth layer                              │
  │   brix_identity_t  ·  DN / token sub / S3 access key          │
  └───────────────────────────────────────────────────────────────┘
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │ VFS ctx — identity threaded in                                │
  │   brix_vfs_ctx_t.identity  + brix_vfs_ctx_bind_backend_cred()  │
  └───────────────────────────────────────────────────────────────┘
                              │   ◄── deny → EACCES / 403 (before any open)
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ THE GATE — selection + deny checkpoint                         ┃
  ┃   brix_vfs_backend_cred()                                      ┃
  ┃   ucred_select: identity → <dir>/<key>.{pem,token,s3,keyring}  ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │ Forwarder — cred-or-plain dispatch                            │
  │   brix_sd_open_maybe_cred()  (refuses if slot missing + deny)  │
  └───────────────────────────────────────────────────────────────┘
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │ Decorators — unwrapped to the leaf                            │
  │   sd_cache / sd_stage  ·  brix_vfs_ns_leaf()                   │
  └───────────────────────────────────────────────────────────────┘
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │ Leaf driver — presents the credential                         │
  │   sd_xroot · sd_remote · sd_http · sd_ceph                     │
  └───────────────────────────────────────────────────────────────┘
                              │
  ╔═══════════════════════════════════════════════════════════════╗
  ║ Origin session — authenticated as U                           ║
  ║   root:// GSI · S3 SigV4 · HTTP Bearer · RADOS CephX           ║
  ╚═══════════════════════════════════════════════════════════════╝
```

Two structural insights make this work, and both were *discovered, not assumed* — and both
had a bug hiding in them (§10):

- **Origin sessions in `sd_xroot` were already per-open** — a fresh connect + handshake per
  `driver->open()`, no pooling. So a per-user credential is just a per-open field, with no
  session-keying rework.
- **The decorators are transparent to identity** — the read-cache and write-stage tiers are
  pure pass-through for namespace ops, so dispatch can reach past them to the leaf.

---

## 4. `brix_sd_cred_t` and the four kinds

The credential is a small, borrowed-pointer struct passed from the VFS gate down to the
driver's open slot. It grew over three phases, and the shape of that growth is itself a
lesson (§11). Its final form carries exactly one of four **mutually-exclusive credential
kinds**, plus the metadata a detached flush needs to re-resolve it:

```c
/* src/fs/backend/sd.h — borrowed pointers, valid only for the open() call.
 * The gate fills exactly ONE kind; the others are NULL. */
typedef struct {
    const char *x509_proxy;                    /* GSI proxy PEM path      — sd_xroot        */
    const char *bearer;                        /* WLCG token text         — sd_xroot (ztn), sd_http */
    const char *s3_ak, *s3_sk, *s3_region;     /* SigV4 keys              — sd_remote        */
    const char *ceph_keyring, *ceph_user;      /* CephX keyring + user    — sd_ceph          */
    const char *key;                           /* cred-dir lookup key (audit + flush re-resolve) */
    const char *principal;                     /* authenticated principal (audit / ledger)  */
    const char *cred_dir;                      /* export cred dir     (flush re-resolve)     */
    unsigned    fallback_deny:1;               /* 1 = service fallback forbidden             */
} brix_sd_cred_t;
```

Each kind is a file in the export's **credential directory**, selected by a key derived
from the request's identity:

| File | Selects | Presented to the origin as |
|------|---------|----------------------------|
| `<key>.pem` | RFC-3820 x509 proxy | GSI handshake to a `root://` origin |
| `<key>.token` | WLCG bearer token | ztn login to `root://`, or `Bearer` header to HTTP |
| `<key>.s3` | access-key / secret-key / region | SigV4 signing to an S3 backend |
| `<key>.keyring` | CephX keyring | per-user RADOS connection to Ceph |

### The naming scheme

- The **principal** is the DN (GSI), the token `sub`, or the S3 access-key id.
- The **key** is the principal verbatim when it is filesystem-safe
  (`[A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}`, never starting with `.` or `-`), otherwise
  `x5h-` + the first 32 hex chars of `SHA256(principal)`. DNs always take the hash form.
- The file is `<cred_dir>/<key>.<ext>`, and the server logs the derived key on every
  fallback/deny so an operator knows exactly which file to provision. Offline:
  `printf '%s' "$PRINCIPAL" | sha256sum | cut -c1-32`.
- **Precedence** is `.pem` > `.token` > `.s3` > `.keyring`, strictly mutually exclusive —
  and an *expired* `.pem` hard-declines rather than silently downgrading to a weaker kind
  (a deliberate anti-downgrade rule with its own test).

The selection logic lives in `src/fs/backend/ucred.c`: `brix_sd_ucred_principal()` derives
the principal, `brix_sd_ucred_key()` derives the key, `brix_sd_ucred_resolve()` resolves a
`<dir>/<key>.<ext>` and checks expiry, and `brix_sd_ucred_select()` walks the candidate
keys. None of it touches nginx runtime, so it compiles in the ngx-free build and is
unit-testable in isolation.

---

## 5. The gate — the sole checkpoint

All policy lives in one function, `brix_vfs_backend_cred()` (`src/fs/vfs/vfs_cred.c`), with
the data-plane and namespace paths sharing one decision body, `vfs_backend_cred_decide()`,
so they can never drift. It is reached before every origin-touching open and has exactly
five terminal outcomes:

| Situation | Outcome | Metric |
|-----------|---------|--------|
| No cred dir configured (feature off) | `NGX_OK`, use service cred | — |
| Valid user cred + driver supports it | `NGX_OK`, present user cred | `cred_select_user` |
| No/expired cred, `fallback=allow` | `NGX_OK`, service cred + INFO log | `cred_select_fallback` |
| Backend can't scope a cred, `fallback=allow` | `NGX_OK`, service cred + WARN | `cred_select_fallback` |
| No/expired cred (or unscopable), `fallback=deny` | **`NGX_ERROR` · EACCES · before any open** | `cred_select_deny` |

The gate is **proto-indexed** for metrics (mirroring the existing `brix_metric_cache_result`),
so it bumps `brix_cred_select_{user,fallback,deny}_total` from inside the VFS without any
per-server plumbing. Labels are `{proto}` only — never a DN, key, or path — honoring the
low-cardinality rule.

> **Feature-off is byte-identical.** Every new path is gated on `storage_cred_dir != NULL`.
> With no directive set, `brix_vfs_ctx_init()` (which memzeros the ctx) leaves the fields
> zero, the gate returns immediately with `use_cred=0`, the forwarders degrade to the plain
> slot, the journal cred is zeroed, and the ns-forwarder refusals never fire. An existing
> deployment sees no behavioral change whatsoever — verified across all three phases.

The two directives that drive it, owned once on the shared config preamble
(`src/core/config/shared_conf.h`, registered in `http_common.c` for HTTP and the stream
module table for `root://`):

```nginx
brix_storage_credential_dir       /etc/brix/creds;   # directory of per-identity credential files
brix_storage_credential_fallback  deny;              # allow (default) | deny
```

---

## 6. Forwarders and the leaf-unwrap

The storage-driver vtable gained optional `*_cred` slots — `open_cred`, `staged_open_cred`,
and eleven namespace variants (`stat_cred`, `unlink_cred`, `rename_cred`, `mkdir_cred`,
`setattr_cred`, `server_copy_cred`, the four xattr variants, `opendir_cred`). A driver that
can't scope identity leaves them `NULL`. Between the VFS and the driver sits a family of
inline forwarders that encode the routing rule in one place:

```c
static ngx_inline brix_sd_obj_t *
brix_sd_open_maybe_cred(brix_sd_instance_t *inst, const char *path, int flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err)
{
    if (cred != NULL && inst->driver->open_cred != NULL)          /* driver can scope → use it */
        return inst->driver->open_cred(inst, path, flags, mode, cred, err);

    if (cred != NULL && cred->fallback_deny                       /* deny: refuse rather than  */
        && inst->driver->open_cred == NULL                        /* silently use the service  */
        && inst->driver->open != NULL) {                          /* credential                */
        *err = EACCES;
        return NULL;
    }
    return inst->driver->open(inst, path, flags, mode, err);      /* allow / feature-off       */
}
```

That middle branch — the **refuse-rather-than-downgrade** clause — is defense in depth: in
deny mode, a per-user op whose driver lacks the `_cred` slot must not quietly fall through
to the service credential. It was added to all twelve forwarders (the `setattr` one was
initially missed and caught in review).

### Why the leaf-unwrap exists

The common production export is *decorated*: a write-stage tier (`sd_stage`) and/or
read-cache tier (`sd_cache`) wraps the real backend. Those decorators forward namespace ops
to their source via the **plain** vtable slots — they have no `_cred` slots. So dispatching
a cred-scoped ns op on the top instance would hit the decorator's plain relay and
**silently drop the credential**.

The fix is `brix_vfs_ns_leaf()`: for a cred-scoped op, unwrap the decorator chain
(`brix_sd_stage_source_instance` / `brix_sd_cache_source_instance`) to the leaf backend
instance and dispatch `*_maybe_cred` there. The decorators are pure pass-through for
namespace ops, so bypassing them is semantically identical — but now the leaf's `_cred` slot
is actually reached. The non-cred path is unchanged (still dispatches on the top instance so
the cache's cinfo short-circuit is preserved). This one gap was the subtlest bug in the
whole feature (§10).

---

## 7. The four hard problems

The original scope named four things that could not be stubbed. Each got a real answer.

### 1 · Session lifecycle and cost

The fear was that per-user credentials would force per-identity origin connection pools.
Investigation killed the fear: `sd_xroot` already opens a fresh origin connection +
handshake for every `driver->open()` — sessions are per-open, not pooled. So the credential
became a per-open field on the synthetic fill-task the origin client already builds
(`brix_cache_fill_t.cred_x509_proxy` / `cred_bearer` / `cred_principal`). No pool, no keying,
no new lifecycle.

Ceph was the exception (§9): librados binds the CephX user at cluster-connect time, so it
*did* need a per-identity connection cache — which is where the two memory-safety bugs lived.

### 2 · Async write-back ownership

A davs/S3 PUT can stage locally and flush to the origin later — detached from the request,
possibly after a restart. The flusher has no request, no identity, no ctx. So the owning
identity is **persisted in the durable stage-journal record**. A new POD type
`brix_stage_cred_t { char key[128]; char principal[512]; char dir[1024]; uint8_t deny; }`
was appended as the **last** member of the on-disk record `brix_sreq_t` — append-only, so a
pre-feature journal still decodes (via a size-tolerant `brix_sreq_decode()` that accepts
both `sizeof(brix_sreq_t)` and `offsetof(brix_sreq_t, cred)`) and replays on the service
credential, exactly its old behavior. At flush time `stage_engine_run()` **re-resolves** the
credential from `key + dir`, which is also what makes expiry checked at the moment of use.

### 3 · Credential expiry

A proxy can lapse between open and flush. Expiry is therefore checked **twice**: at
request-open by the gate, and again at flush time by the re-resolution. A deny-mode flush
whose credential has permanently lapsed does *not* silently fall back to the service account
— it fails loudly, books a `result=denied` line in the xfer audit ledger, and (after a cap)
dead-letters the record rather than looping forever (§10).

### 4 · Identity plumbing without globals

The identity was already on `brix_vfs_ctx_t.identity` for davs and S3 — the auth layer
populated it and never used it below. The work was threading it the last hop into the
driver, and binding the cred-dir policy alongside it. No new global was introduced; the one
global-ish structure in the whole feature is the per-worker delegation-id store (§8), which
is a documented lazy-init per-worker singleton.

---

## 8. Every surface that needed wiring

The gate is one function; reaching it from every operation that can touch a remote origin
was the bulk of the work. Each surface builds a VFS ctx — the pattern is always *init the
ctx with the identity, then bind the cred policy* — and a surface that built the ctx but
forgot the bind was, invariably, an identity leak (§10).

| Surface | What it needed | Phase |
|---------|----------------|-------|
| davs / S3 data plane (GET/PUT) | Identity + bind at the read/write ctx sites | 1 |
| Write-back staging & flush | Owner recorded in the journal; re-resolve at flush | 1 |
| Namespace ops (stat/rm/mkdir/rename/xattr) | 11 `_cred` slots + the leaf-unwrap gate | 2 |
| `root://` stream (xrdcp/xrdfs) | Stream directives; identity from the session ctx | 2 |
| Remote serve-offload (zero-copy GET) | Deny-gate on the event loop; cred copied into the worker-thread ctx | 2 (fix) |
| `root://` directory listing | A new `kXR_dirlist` origin wire client + `opendir_cred` | 3 |
| WebDAV MOVE / COPY, S3 CopyObject, LOCK | Bind the omitted ctx; ctx-bound rename over the pool-less one | 2 (fix) |
| Delegation capture | Upload endpoint + GridSite two-step; store to the cred dir | 2 / 3 |
| SigV4 → x509 minting | Opt-in mint CA; mint a short-lived proxy on cred-miss | 2 |

### Credential capture — closing the loop

Selection needs a file to select. Two opt-in mechanisms *write* into the same credential
directory that selection reads:

- **Delegation** (`src/protocols/webdav/delegation.c`). A GSI-cert client uploads its own
  RFC-3820 proxy to `/.well-known/brix-delegation`, or runs the standard two-step GridSite
  handshake: `GET .../request` → the server mints a keypair + CSR (via
  `brix_gsi_build_pxyreq`), holds the private key in a per-worker CSPRNG-keyed store bound to
  the client's DN → `PUT .../<id>` returns the client-signed cert, which the server assembles
  (`brix_gsi_assemble_proxy`). Either way the proxy is validated —
  **cryptographically chain-verified against the frontend's trusted CA**
  (`delegation_chain_trusted()` → `brix_gsi_verify_chain`), not merely DN-string-matched —
  and stored at `<cred_dir>/<key>.pem`. Phase-1 selection then transparently picks it up.
  Enabled by `brix_delegation_endpoint on` (default off).

- **Minting** (`src/fs/backend/cred_mint.c`). When a mint CA is configured
  (`brix_storage_credential_mint_ca <cert> <key>`) and an identity has no provisioned proxy,
  the gate mints a short-lived EC-P256 proxy whose subject encodes the principal, signed by
  the mint CA, cached in the cred dir with a refresh window. This gives an S3 access key —
  which has no native x509 — a per-user origin identity. It is off by default and shifts
  trust to the frontend's mint CA (which the origin must be configured to trust), a tradeoff
  documented prominently.

---

## 9. The backend drivers

Each leaf driver speaks exactly one origin auth protocol and reads only the credential kind
it understands.

| Driver | Backend | Reads kind | Presents as |
|--------|---------|------------|-------------|
| `sd_xroot` | `root://` origin | `x509_proxy`, `bearer` | GSI handshake / ztn login |
| `sd_remote` | S3 (`storage_backend s3://`) | `s3_ak` / `s3_sk` / `s3_region` | SigV4 signing per open |
| `sd_http` | HTTP / cvmfs origin | `bearer` | `Authorization: Bearer` header |
| `sd_ceph` | Ceph / RADOS | `ceph_keyring` / `ceph_user` | per-user CephX connection |

For `sd_xroot`, `sd_remote`, and `sd_http` the per-user credential is a per-open field — the
origin session (or the SigV4 signer, or the auth header) is already built per open, so it
just reads the cred's value. For each, a *wrong-kind* credential in deny mode (e.g. a `.s3`
file provisioned against an xroot export) refuses with `EACCES` rather than downgrading to
the service account.

The `sd_xroot` origin bootstrap (`src/fs/cache/origin_protocol.c`) consults the per-open
credential **before** the static service branches: if `t->cred_x509_proxy` is set it
presents that via `brix_cache_origin_auth_gsi`; if `t->cred_bearer` is set it presents that
via `brix_cache_origin_auth_ztn`; and a per-user credential whose kind the origin doesn't
advertise **fails** rather than falling through to the service credential.

> **Ceph was the one that fought back.** librados binds the CephX user at *cluster-connect*
> time, not per-op — so a per-user credential needs a whole new `rados_t` connection, not
> just a field. `sd_ceph_open_cred` resolves a connection from a bounded, per-`(user,keyring)`
> LRU cache; a cache miss creates one, connects as that CephX user, and **pins** it to the
> open object. This is buildable and testable only inside the repo's librados-devel container
> (`tests/ceph/build_in_container.sh`) against a live Ceph demo cluster
> (`tests/ceph_harness.sh`) — which is why it was *almost* shipped as "design only," and
> exactly where two real memory-safety bugs lived (§10). The negative test is the proof: a
> request bearing a *read-only* user's keyring has its write **denied at RADOS** — real
> per-user CephX enforcement, not admin-for-everyone. See
> `tests/ceph/run_sd_ceph_cred_live.sh`.

---

## 10. Bugs found and fixed

A security feature is only as good as the review that hunts its holes. Every bug below was
caught by adversarial review, reproduced by a test, and fixed — not documented and shipped.
They are the most instructive part of the record.

### Critical · Path traversal in the credential key

- **Symptom** — a token `sub` of `..` passed the "filesystem-safe" filter, so the resolver
  built `<cred_dir>/../.pem` — a read one directory above the credential dir.
- **Root cause** — the fs-safe charset allowed a leading `.`; `.` and `..` are valid under it.
- **Fix** — reject a leading `.` in `brix_sd_ucred_key`'s fs-safe test; such principals fall
  through to the always-safe `x5h-`SHA256 hash form.

### Critical · Decorator dropped the credential on namespace ops

- **Symptom** — on a stage/cache-decorated export (the common write-back config), a user's
  stat/rename/delete authenticated to the origin as the *service* account, not the user.
- **Root cause** — the ns dispatch targeted the top instance (a decorator), whose plain ns
  relay forwards to the source without the cred. The initial test masked it because the
  test's service credential *was* user A's proxy.
- **Fix** — `brix_vfs_ns_leaf()` unwraps decorators to the leaf backend for cred-scoped
  dispatch. And the test was strengthened to use a *distinct* service DN (`CN=SVC Proxy`), so
  it can no longer hide the difference.

### Important ×5 · Handlers that built the ctx but forgot the bind

- **Symptom** — WebDAV MOVE, WebDAV COPY, S3 CopyObject, WebDAV LOCK (xattrs), and the remote
  serve-offload GET each reached the origin under the service credential on the allow path —
  and in the offload case, a deny-mode read was never gated at all (the largest read-side
  hole).
- **Root cause** — each built a VFS ctx *with* identity but omitted
  `brix_vfs_ctx_bind_backend_cred`; MOVE additionally used the pool-less, credential-free
  `brix_vfs_rename_path`; the offload ran `driver->open` on a worker thread with no gate.
- **Fix** — bind the cred at each site; switch MOVE to the ctx-bound `brix_vfs_rename` (which
  routes through the ns gate); for the offload, run the deny-gate on the event loop *before*
  submitting the thread task and copy the cred into the worker-thread ctx (a detached-state
  copy into fixed buffers, not a borrowed pointer). Also required extending `vfs_copy.c` with
  the same leaf-unwrap so `server_copy` reaches the leaf.

### Important · Delegation trusted a self-asserted DN

- **Symptom** — both delegation forms validated the delegated proxy by a *string* match of
  its self-reported subject DN against the client — with no cryptographic proof the proxy
  chained to a trusted CA. The authenticated owner could store a self-signed proxy for their
  own slot.
- **Root cause** — the assembly primitive only proved possession of the server-issued key;
  the caller added no chain verification.
- **Fix** — `delegation_chain_trusted()` runs the same `brix_gsi_verify_chain` the
  client-cert auth path uses, against the frontend's `ca_store`, in **both** delegation paths
  before storing. A DN-spoofed self-signed proxy is now rejected 403 — verified by a rogue-CA
  test in both suites.

### Memory · Critical · Ceph connection use-after-free under eviction

- **Symptom** — on a busy multi-user Ceph export (>8 concurrent identities), a long-lived
  open's cached RADOS connection could be LRU-evicted and freed while an object was still
  reading/writing on its ioctx — dereferencing freed memory.
- **Root cause** — the open object held a raw `rados_ioctx_t`; the cache had no refcount;
  `sd_ceph_close` was a no-op; the LRU generation bumped only on cache lookups, never on
  live-handle I/O.
- **Fix** — refcount-**pin** the connection: the open object holds the `sd_ceph_conn_t*`,
  eviction skips pinned slots (falling back to a transient uncached connection when all are
  pinned), and `sd_ceph_close` unpins with deferred destroy. Proven by a test that holds a
  handle open through >8 evictions and does byte-exact I/O — no crash.

### Memory · Critical · Ceph transient connection leak

- **Symptom** — under >8 *simultaneous* held-open credentialed handles, each extra
  "transient" (all-slots-pinned) connection leaked a mon session + socket fds — the fd count
  staircased upward.
- **Root cause** — the deferred-destroy `doomed` flag was never actually set on the transient
  connection, so its final unpin never freed it, and it was never in the cache table for
  cleanup to find.
- **Fix** — mark the transient connection `doomed` at birth so its last unpin frees it. A
  leak-regression test cycles >8 simultaneous transient opens and asserts a flat fd count
  (112 across five cycles) — proven, not claimed.

### Liveness · Deny-mode flush retried forever

- **Symptom** — a deny-mode write-back whose credential was permanently missing/expired
  re-drove on every scheduler tick and every restart — an unbounded loop.
- **Root cause** — the denied terminal kept the durable record for retry, like a transient
  network error.
- **Fix** — a dead-letter: after an attempt/age cap the denied record moves to
  `<journal>/deadletter/` with a loud error and stops re-driving. The write is preserved for
  operator recovery and never flushed under the wrong identity.

> **The pattern behind the bugs.** Almost every defect was the same shape: *a credential
> silently substituted for the service account somewhere the identity was supposed to travel*
> — a decorator relay, an unbound ctx, an unpinned connection, an unverified chain. None was a
> cross-user impersonation; the origin's own re-authentication was the backstop. But each
> broke the "as the user" promise on the allow path, or the "deny before origin" promise. The
> review discipline that found them — adversarial verification, a distinct-service-DN test,
> reproduction before acceptance — is what makes the invariant real rather than aspirational.

---

## 11. Design decisions and rationale

**Per-open credential, not a session key.** Because `sd_xroot` sessions were already
per-open, the credential is a per-open value rather than a pooled per-identity session. This
avoided an entire connection-pool subsystem and its lifecycle. The cost — a handshake per
open — was already being paid.

**Selection, not delegation, in Phase 1.** Phase 1 *selected* an admin-provisioned
credential from a directory rather than capturing a delegated one. Delegation capture (the
harder, stateful problem) was deferred and built on top — the upload endpoint and the
two-step GridSite flow both simply *write into the directory Phase 1 reads*, so the two
halves compose without coupling.

**The struct that grew from two fields to five (and the lesson).** The SD credential started
as a lean two-field struct (proxy + principal) — sufficient for the data plane. But the
write-back path needs to persist *key*, *dir*, and *deny* so a detached flush can
re-resolve, and the driver's only per-op channel is the cred struct. The two-field version
was a premature simplification that had to be corrected mid-feature. The lesson: when a value
must survive to a detached consumer, design the struct for that consumer up front, not for
the nearest caller.

**Mutually-exclusive kinds, resolved by precedence.** Rather than a tagged union or a kind
enum threaded everywhere, the gate fills exactly one kind's fields and NULLs the rest; each
driver reads only its own. The anti-downgrade rule — an expired `.pem` refuses rather than
falling to `.token`/`.s3` — prevents an attacker (or a misconfiguration) from getting a
weaker credential accepted where a stronger one lapsed.

**Re-resolve at flush, don't cache the resolved path.** The durable journal stores the *key*,
not a resolved proxy path or its bytes. The flush re-resolves. This is what makes
expiry-at-use real: a credential valid at PUT time but lapsed by flush time is caught,
because the check happens when the bytes actually move — not when they were queued.

**Refuse over silently-fall-back, everywhere.** The forwarder refusal, the wrong-kind driver
refusal, the deny-gate, the delegation chain-verify — all share one stance: in a mode that
forbids service fallback, an ambiguous or unscopable situation **fails closed**. A credential
system that silently downgrades under stress is worse than one that refuses, because the
downgrade is invisible.

**The gate is the one checkpoint.** Serve, fill, flush, and namespace helpers were all proven
credential-free, so `brix_vfs_backend_cred()` is the sole place a credential decision is
made. One function to audit, one place deny is enforced, one place metrics are booked.
Consolidation is the security property.

---

## 12. How it was proven

Three tiers of tests, each answering a different question.

**Unit — is the logic correct in isolation?** Standalone C tests against build-tree objects:
credential selection and the four-kind precedence (`test_ucred`, including the path-traversal
and anti-downgrade cases), durable-record forward/backward compatibility (`test_sreq_compat`),
x509 minting (`test_cred_mint`), the delegation-id store's cross-client refusal and one-shot
semantics (`test_delegation_store`), and the flush dead-letter caps (`test_flush_deadletter`).

**End-to-end — does the identity actually reach the origin?** Fleet-based e2e stands up its
own GSI origin and davs/`root://` frontend, and — crucially — uses a **distinct service DN**
so an assertion of "the origin logged user A's DN" genuinely distinguishes the user
credential from the service one. The suites
(`tests/run_user_backend_cred*.sh`, `tests/run_delegation_*.sh`) prove PUT/GET/MOVE/COPY/
rename/checksum/dirlist as the user, deny blocking a no-cred user before any origin data op,
allow-mode fallback, expiry refusal, delegation round-trips (including a rogue-CA rejection),
and async-flush + restart-replay authenticating as the owner.

**Live — does per-user enforcement actually hold at a real backend?** Ceph runs against a
live single-node cluster in the librados-devel container, with real CephX users provisioned
via `ceph auth`. The load-bearing assertion is negative: a request carrying a *read-only*
user's keyring has its write **denied at RADOS**, and the object is provably unmodified. That
is the difference between "we set a keyring" and "the backend enforces it."

> **Verification discipline.** Every task's build and tests were re-run and confirmed
> independently, not trusted from a report — including after the shared build tree was
> disturbed by concurrent work. Reviews ran adversarially (find the hole, reproduce it, then
> fix), and no fix was accepted on assertion alone: the UAF fix had to survive a >8-eviction
> reproduction, the leak fix a flat-fd-count reproduction.

---

## 13. Limits and follow-ups

What the feature deliberately does *not* do, stated honestly:

- **S3 per-user is unit-covered, not live-e2e'd** — there is no S3 origin with per-user IAM
  identities in the test fleet, so the SigV4-override path is proven by unit tests and the
  existing S3 signing suite, not an end-to-end two-keypair run.
- **The two-step delegation store is per-worker** — a multi-worker deployment wants sticky
  routing so the `getProxyReq` and `putProxy` of one handshake reach the same worker that
  holds the ephemeral private key.
- **Token principals key on `sub` alone** — two issuers sharing a subject would share a
  credential; a multi-issuer site needs an `iss|sub` scheme or authorization gating.
- **Some pre-flight existence probes still stat under the service credential** — a metadata
  read, never file data, and deny is still enforced at the actual operation; a documented,
  bounded nuance.

Everything the original scope called "out of scope" was ultimately built: delegation capture
(both forms), SigV4→x509 minting, per-user credentials for the non-xroot backends including a
live-tested Ceph path, `root://` stream identity, namespace-op scoping, bearer tokens,
observability, and the dead-letter. The feature closes the loop it set out to close — the
credential no longer stops at the front door.

---

*Reference implementation across `src/fs/backend/`, `src/fs/vfs/`, `src/fs/cache/`,
`src/fs/xfer/`, and the protocol handlers. Implementation plans and per-task review ledgers
are under `docs/superpowers/plans/` and `.superpowers/sdd/pubc/`.*
