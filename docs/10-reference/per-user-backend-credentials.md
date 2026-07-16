# Per-User Backend Credentials

When a `davs://`, S3, or `root://` request authenticates as user U and reads
from or writes to a remote origin (`brix_storage_backend root://…` or an
HTTP(S) origin) through the VFS, the origin session for that request can
authenticate as U's own identity — an admin-provisioned x509 proxy, a
provisioned WLCG bearer token, a proxy U delegates itself over HTTPS, or (opt
-in) a short-lived proxy minted on the fly — instead of always riding the
static service credential.

This page documents the feature as it exists after **Phase 1** (x509 proxies,
HTTP data-plane only), **Phase 2** (namespace ops, bearer tokens, root://
stream, self-service delegation, minting, metrics, and flush dead-lettering),
and **Phase 3** (root:// stream minting, root:// remote dirlist, `.s3`
per-user S3 credentials, the full GridSite two-step delegation handshake, a
LOCK deny→403 status fix, and defensive forwarder hardening).
Every claim below was checked directly against source; see
[Key Source Files](#key-source-files) for the exact files.

---

## Supported

| Capability | Since | Notes |
|---|---|---|
| Per-user x509 proxy for HTTP data-plane opens (GET/PUT fill) | Phase 1 | `davs://`/S3 → `sd_xroot` origin |
| Per-user x509 proxy for `root://` stream data-plane opens (read/write/truncate/rename/checksum/fattr) | Phase 2 T6 | Directives are also registered on the stream `server{}` block — see [Directives](#directives). `kXR_mkdir` binds the credential too, but `sd_xroot` has no `mkdir`/`mkdir_cred` slot at all, so mkdir against a remote `root://`-backed export cannot succeed regardless of credential mode (driver-capability gap, not a cred gap) |
| Opt-in short-lived proxy minting for `root://` stream data-plane opens | Phase 3 T1 | `brix_storage_credential_mint_ca`/`_mint_ttl` are now registered on the stream `server{}` block too (`src/protocols/root/stream/module.c:203-215`, setter `brix_conf_set_stream_mint_ca`), and `brix_vfs_ctx_bind_backend_mint()` is called from the stream data-plane opens: `src/protocols/root/read/open_resolved_file.c:886`, `src/protocols/root/write/truncate.c`, `src/protocols/root/query/checksum_qcksum.c`. A `root://` client with a bearer-only identity and no pre-provisioned `.pem` can now be minted a proxy exactly as an HTTP client can — minting is no longer HTTP-only. Same [trust warning](#minting-trust-warning) applies |
| Per-user credential for `root://` remote **dirlist** (`kXR_dirlist` → remote origin) | Phase 3 T2 | `sd_xroot` now implements `opendir`/`readdir`/`closedir` + `opendir_cred` and advertises `BRIX_SD_CAP_DIRS` (`src/fs/backend/xroot/sd_xroot.c:590-631`, `sd_xroot_ns.c:545-687`), driving a real `kXR_dirlist` wire client `brix_cache_origin_dirlist()` (`src/fs/cache/origin_ns.c:514-579`). Dirlist against a `brix_storage_backend root://…` export now works end-to-end and is credential-scoped. (`mkdir`/`setattr` on such an export remain a driver gap — see [Remaining limitations](#remaining-limitations--follow-ups)) |
| Per-user `.s3` credential (access-key/secret-key/region) for an S3-backed remote origin | Phase 3 T3 | A third credential file kind `<key>.s3` (3 lines: ak / sk / region, region optional → `us-east-1`) parsed by `ucred_read_s3()` (`src/fs/backend/ucred.c:202-258`) and resolved after `.pem`/`.token` (`ucred.c:398-415`). New `s3_ak`/`s3_sk`/`s3_region` fields on `brix_sd_cred_t` (`src/fs/backend/sd.h:155-165`). Consumed via `sd_remote`'s `open_cred` (`src/fs/backend/remote/sd_remote.c:162-174`), which re-inits the SigV4 signer per open with the user's keys instead of the export's static access-key/secret-key. Precedence `.pem > .token > .s3`, mutually exclusive; an expired `.pem` still hard-declines. **Unit-tested only** (`tests/c/test_ucred.c` S3 section) — no S3-origin e2e yet (see [Remaining limitations](#remaining-limitations--follow-ups)) |
| Per-user `.keyring` CephX credential for a Ceph/RADOS-backed remote origin (`sd_ceph`) | Ceph-peruser | A fourth credential file kind `<key>.keyring` — a standard CephX keyring as emitted by `ceph auth get-or-create`, containing a `[client.NAME]` section — parsed by `ucred_read_keyring()` (`src/fs/backend/ucred.c:283-`) and resolved after `.pem`/`.token`/`.s3` (`ucred.c:512-525`). Stores the keyring **path** (never the secret key contents) plus the bare CephX user id in the new `ceph_keyring`/`ceph_user` fields on `brix_sd_cred_t` (`src/fs/backend/sd.h:166-169`). Consumed via `sd_ceph`'s `open_cred` (`src/fs/backend/rados/sd_ceph.c:1338-`), which authenticates to RADOS as that CephX user through a bounded 8-slot LRU cache of per-`(user, keyring)` `rados_t` connections (`SD_CEPH_CRED_CONN_CACHE_MAX`); connections are refcount-pinned by open handles so an in-use connection is never evicted, and a transient uncached connection is used (and freed on close) when every slot is pinned. Precedence `.pem > .token > .s3 > .keyring`, mutually exclusive; an expired `.pem` still hard-declines. Wrong-kind-in-deny-mode → `EACCES`, consistent with the other backends. Gated on `BRIX_HAVE_CEPH` (librados-devel) at build time; **live-tested against a real Ceph cluster in the repo's Ceph build container**, not in the host CI suite (`tests/ceph/run_sd_ceph_cred_live.sh` — see [sd_ceph per-user credentials](#sd_ceph-per-user-credentials)) |
| Full GridSite two-step delegation (`getProxyReq`/`putProxy`) | Phase 3 T4 | Adds the standard two-step handshake alongside the Phase 2 T8 proxy-upload form: GET `/.well-known/brix-delegation/request` returns a server-generated CSR + a delegation-id; the client signs the CSR with its own key and PUTs the signed proxy to `/.well-known/brix-delegation/<id>` (`src/protocols/webdav/delegation.c`). Both forms perform full cryptographic chain-of-trust verification via `brix_gsi_verify_chain()`/`X509_verify_cert()` (not just DN string match) before storing; the two-step form additionally proves key possession (`EVP_PKEY_eq`). Reuses the existing `brix_delegation_endpoint on` directive. See [Two-step delegation](#self-service-delegation-t8-upload--t4-two-step) |
| WebDAV LOCK deny → `403` (was `500`) | Phase 3 T1 | When the per-user backend credential gate denies a lock-state xattr write against a *remote-backed* export, `src/protocols/webdav/lock.c:583-619` now maps the resulting `EACCES`/`EPERM` to `403 Forbidden` (distinguished by `brix_webdav_backend_instance(conf,…) != NULL`). A local-POSIX-export `EACCES` from the impersonation broker mid-op still maps to `500` — see [Remaining limitations](#remaining-limitations--follow-ups) |
| Per-user credential for namespace ops (stat/unlink/xattr/rename; DELETE/MKCOL/GET/HEAD/PROPFIND pre-flight) against a remote origin | Phase 2 T1 | Via `brix_vfs_ns_leaf()` + the `*_cred` vtable slots `sd_xroot` implements (`stat`/`unlink`/`rename`/`server_copy`/xattr — **not** `mkdir`/`setattr`/`opendir`, a pre-existing driver gap); see [namespace-ops nuance](#namespace-ops-nuance) for the probe/MOVE paths that are NOT yet cred-scoped |
| Per-user bearer token (`<key>.token`, WLCG JWT) as a credential kind | Phase 2 T2 | `.pem` still wins if both exist; an *expired* `.pem` hard-declines rather than falling through to `.token` — see [Naming scheme](#credential-directory-naming-scheme) |
| `sd_http` per-open bearer credential (read/`pread` only) | Phase 2 T7 | HEAD/stat/PUT-commit/DELETE still ride the instance's static bearer header |
| Self-service proxy-upload delegation endpoint | Phase 2 T8 | `POST`/`PUT /.well-known/brix-delegation`, GSI-cert-authenticated only |
| Opt-in short-lived proxy minting | Phase 2 T9 | EC P-256, signed by an operator-configured mint CA; **shifts trust to the frontend — see the [trust warning](#minting-trust-warning)** |
| Prometheus counters for the credential-select decision | Phase 2 T3 | `brix_cred_select_{user,fallback,deny}_total{proto}` |
| Durable dead-lettering of a permanently-denied async flush | Phase 2 T4 | `<journal_dir>/deadletter/<reqid>.req` after 5 attempts or 24h |
| WebDAV MOVE cred-bound | Phase 2 follow-up | `src/protocols/webdav/move.c`'s `webdav_move_execute_cred()` performs the real rename through the ctx-bound `brix_vfs_rename()` (not the pool-less `brix_vfs_rename_path()`), so a MOVE against a remote-backed export presents the requesting user's credential; a denied gate maps to 403 |
| WebDAV COPY (file, data-plane) cred-bound | Phase 2 follow-up | `src/protocols/webdav/copy.c` binds `brix_vfs_ctx_bind_backend_cred()` (+ opt-in mint) before `brix_vfs_copy()`'s underlying `server_copy` |
| S3 CopyObject cred-bound | Phase 2 follow-up | `src/protocols/s3/copy.c`'s `s3_copy_vfs_ctx()` binds cred + mint for both source and destination; falls back to the service credential only when no per-user S3 cred is provisioned (S3 has no per-user backend identity concept yet — correct allow-fallback, not a gap) |
| WebDAV LOCK xattr ops cred-bound | Phase 2 follow-up | `src/protocols/webdav/prop_xattr.c` binds `brix_vfs_ctx_bind_backend_cred()` for lock-state xattr reads/writes against a remote-backed export (mint intentionally not bound here — see [Remaining limitations](#remaining-limitations--follow-ups) for the LOCK status-code note) |
| Remote serve-offload GET (read-side) cred-bound | Phase 2 follow-up | `src/protocols/shared/http_serve_offload.c`'s `brix_http_serve_offload_remote()` runs the credential gate on the event loop *before* posting the worker-thread job — a denied identity gets `EACCES`/403 and the origin is never opened. On allow, the resolved credential is detached-copied into the offload thread ctx and presented via `brix_sd_open_maybe_cred()`. Wired at `webdav/get.c` and `s3/object.c`; `cvmfs`'s offload call (`src/protocols/cvmfs/handler.c`) passes `vctx=NULL` by design — cvmfs is a transparent, anonymous public cache with no per-user identity concept, so the gate is intentionally skipped there |

---

## Directives

| Directive | Args | Default | Scope |
|---|---|---|---|
| `brix_storage_credential_dir` | `<path>` | `/dev/shm/brix-creds` (tmpfs; created 0700 at config time; explicit `""` = feature off) | HTTP (main/srv/loc) **and** stream (`server{}`) |
| `brix_storage_credential_fallback` | `allow \| deny` | `allow` | HTTP (main/srv/loc) **and** stream (`server{}`) |
| `brix_storage_credential_mint_ca` | `<ca_cert.pem> <ca_key.pem>` | unset (minting off) | HTTP (main/srv/loc) **and** stream (`server{}`) — Phase 3 T1 |
| `brix_storage_credential_mint_ttl` | `<seconds>` | `3600` | HTTP (main/srv/loc) **and** stream (`server{}`) — Phase 3 T1 |
| `brix_delegation_endpoint` | `on \| off` | `off` | HTTP location (WebDAV) only |

Source: `src/core/config/http_common.c` (`brix_http_common_commands[]`, all
`BRIX_HTTP_ALL_CONF` = `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF`
except the delegation flag, which is WebDAV-only in
`src/protocols/webdav/module.c`); `src/protocols/root/stream/module.c`
(`ngx_stream_brix_commands[]`, `NGX_STREAM_SRV_CONF`) registers its own copy
of `brix_storage_credential_dir`/`_fallback` **and, as of Phase 3 T1,
`brix_storage_credential_mint_ca`/`_mint_ttl`** (lines 203-215; the mint-CA
setter `brix_conf_set_stream_mint_ca` mirrors HTTP's `brix_conf_set_mint_ca`,
including config-time PEM validation), all writing into the same shared
`common.storage_credential_*` fields. Defaults are enforced in
`src/core/config/shared_conf.h` (`ngx_conf_merge_str_value`/`_uint_value`) and
`src/protocols/webdav/config.c` (`delegation_endpoint`, `ngx_conf_merge_value`
default `0`).

**`brix_storage_credential_mint_ca` is opt-in but no longer HTTP-only (Phase 3
T1).** The mint-CA/mint-TTL directives are now on both the HTTP and stream
directive tables, and the VFS bind that arms minting
(`brix_vfs_ctx_bind_backend_mint()`) is called from the HTTP data-plane
(`src/protocols/webdav/get.c`, `put.c`, `src/protocols/s3/util.c`) **and** the
`root://` stream data-plane (`src/protocols/root/read/open_resolved_file.c:886`,
`src/protocols/root/write/truncate.c`, `src/protocols/root/query/checksum_qcksum.c`).
A `root://` client with a bearer-only identity and no pre-provisioned proxy is
now minted a short-lived proxy exactly as an HTTP client is. The same
[trust warning](#minting-trust-warning) applies — configure the mint CA only
after the origin has been updated to trust it.

### `brix_storage_credential_fallback`

| Value | Behaviour |
|---|---|
| `allow` (default) | Fall back to the static service credential; emit an `INFO` log line naming the principal and the expected key. |
| `deny` | Refuse the request immediately; emit an `ERR` log line; map to `EACCES` → HTTP 403 / `kXR_NotAuthorized`. The origin is never contacted under the wrong identity. |

An existing-but-expired `.pem` is also refused under `deny` (logged as
`EXPIRED`).

---

## Credential-Directory Naming Scheme

Unchanged from Phase 1.

### Principal string

| Auth type | Principal |
|---|---|
| GSI / x509 | The parsed cert DN (`identity->dn`). Example: `/DC=org/DC=doegrids/OU=People/CN=Alice 12345` |
| Bearer token (WLCG/SciToken) | The `sub` claim (`identity->subject`). |
| S3 SigV4 | The SigV4 access-key id (`identity->subject`). |

### Lookup key candidates

1. **Literal principal** — only when it matches
   `[A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}` (never true for a GSI DN).
2. **Hash form** — `x5h-` + the first 32 lowercase hex chars of
   `SHA256(principal)`.

The key must not start with `.` (path-traversal safety). `BRIX_UCRED_KEY_MAX`
is 128 bytes (`src/fs/backend/ucred.h`).

### File path and kind precedence

```
<brix_storage_credential_dir>/<key>.pem      # x509 proxy (RFC 3820), tried FIRST
<brix_storage_credential_dir>/<key>.token    # WLCG bearer, tried only if .pem is ABSENT
<brix_storage_credential_dir>/<key>.s3        # S3 ak/sk/region, tried only if .pem AND .token are ABSENT (Phase 3 T3)
<brix_storage_credential_dir>/<key>.keyring   # CephX keyring, tried only if .pem, .token, AND .s3 are ABSENT (ceph-peruser)
```

`brix_sd_ucred_resolve()` (`src/fs/backend/ucred.c:349-`) implements this
order (all four kinds are mutually exclusive):

1. Check `<key>.pem`. Valid (unexpired, parseable) → **use it**, done.
2. `.pem` **present but expired** → **hard-decline**. Neither `.token`,
   `.s3`, nor `.keyring` is consulted even if it exists — silently promoting
   to a bearer, S3, or CephX key would change the presented identity without
   operator intent.
3. `.pem` **absent** (not expired-and-absent — genuinely missing) → probe
   `<key>.token`. Valid bearer → use it (`out->is_bearer = 1`).
4. `.token` also absent/unparseable → probe `<key>.s3` (Phase 3 T3). A
   well-formed `.s3` → use it (`out->is_s3 = 1`).
5. `.s3` also absent/unparseable → probe `<key>.keyring` (ceph-peruser). A
   well-formed keyring (first `[client.NAME]` section header found) → use it
   (`out->is_ceph = 1`). Otherwise decline (falls to the fallback/deny
   policy).

The `.s3` file is three lines (`ucred_read_s3()`, `src/fs/backend/ucred.c:202-258`):

```
AKIAEXAMPLEACCESSKEY     # line 1: access-key id
wJalrXUtnFEMI/K7MDENG…   # line 2: secret access key (never logged)
us-east-1                # line 3: region — optional; empty/absent → "us-east-1"
```

The `.keyring` file is a standard CephX keyring, exactly as emitted by
`ceph auth get-or-create` (`ucred_read_keyring()`,
`src/fs/backend/ucred.c:283-`):

```ini
[client.bob]
    key = AQD…base64-secret…==
    caps mon = "allow r"
    caps osd = "allow rwx pool=xrdtest"
```

`ucred_read_keyring()` scans for the **first** `[client.NAME]` section header
and stores the bare id (`bob`, no `client.` prefix — librados's
`rados_create()` re-adds the prefix itself) plus the keyring file's own
**path**; the secret `key =` line is never parsed or copied into
`brix_sd_cred_t` — librados reads the keyring file directly.

A bearer credential carries no notAfter check on the frontend side — the
origin enforces the token's own `exp` claim when it validates the
`Authorization: Bearer` header. An `.s3` credential likewise carries no
frontend expiry — the S3 origin authenticates each SigV4-signed request. A
`.keyring` credential carries no frontend expiry either — the Ceph cluster
enforces the CephX entity's own caps and any cluster-side rotation.

For S3 access keys and simple JWT subjects that match the safe charset, the
key is the literal principal, so a per-user S3 credential is typically at
`<access-key-id>.s3` (e.g. `AKIAEXAMPLE.s3`). A per-user Ceph credential is
provisioned at `<cred_dir>/<key>.keyring`, where `<key>` follows the same
principal → key-derivation scheme as every other kind (see
[Lookup key candidates](#lookup-key-candidates)); the CephX identity itself
(`ceph auth get-or-create client.<user> ...`) must already exist at the
cluster — the frontend only *selects* it, it never mints CephX entities.

### Discovering the key for a principal

```bash
curl -s --cert proxy.pem --key proxy.pem https://front.site.example/test.txt
grep 'key=' /var/log/nginx/error.log | tail -1
# brix: no per-user backend credential for principal="/DC=…/CN=Alice" key=x5h-3a7f… …
cp alice_proxy.pem /etc/brix/user-creds/x5h-3a7f….pem
```

Or offline:

```bash
printf '%s' "$PRINCIPAL" | sha256sum | cut -c1-32
# Prepend "x5h-" and add ".pem" or ".token"
```

For S3 access keys and simple JWT subjects that match the safe charset, the
key is the literal principal (e.g. `AKIAEXAMPLE.pem`).

---

## Namespace ops (Phase 2 T1)

The namespace-op cred vtable (`src/fs/backend/sd.h`) declares slots for
`stat_cred`/`unlink_cred`/`mkdir_cred`/`rename_cred`/`setattr_cred`/
`{get,list,set,remove}xattr_cred`/`server_copy_cred`/`opendir_cred`, all
dispatched via `brix_vfs_ns_leaf()` (`src/fs/vfs/vfs_internal.h`) so a
namespace op reaches the leaf backend's cred slot even through a decorator
(stage/cache) chain. **`sd_xroot` (`src/fs/backend/xroot/sd_xroot.c`)
implements a SUBSET**: `stat_cred`, `unlink_cred`, `rename_cred`,
`server_copy_cred`, all four xattr `*_cred` slots, **and, as of Phase 3 T2,
`opendir`/`readdir`/`closedir` + `opendir_cred`** (`sd_xroot.c:590-631`,
`sd_xroot_ns.c:545-687`) — advertising `BRIX_SD_CAP_DIRS`. **It still
implements no `mkdir_cred`, `setattr_cred` — and no plain (non-cred)
`mkdir`/`setattr` either**, so `mkdir`/`chmod`(setattr) against a
`root://`-backed remote origin remain a **driver-capability gap** predating
credentials, not merely uncovered by them. Where a cred slot IS implemented,
it is gated by the same `brix_vfs_ns_cred()` allow/deny/fallback decision as
the data-plane gate, including the Phase 2 T3 metrics.

Call sites confirmed cred-bound (call `brix_vfs_ctx_bind_backend_cred()`
before the VFS op): `src/protocols/webdav/get.c`, `put.c` (both the write-open
*and* the PUT pre-flight ETag/existence probe), `namespace.c` (DELETE/MKCOL),
`resource.c` (GET/HEAD/PROPFIND stat); `src/protocols/s3/util.c`,
`put_aio.c`, `put_chunk.c`, `put_finalize.c`.

### Namespace-ops nuance

Two distinct, verified gaps remain, of differing severity — not one
uniform "namespace ops ride the service credential" limitation:

1. **Several pre-flight existence probes run entirely on the service
   credential**, because their `brix_vfs_ctx_t` is never bound via
   `brix_vfs_ctx_bind_backend_cred()`: `webdav_move_probe()` in `move.c`,
   the equivalent probe in `copy.c`, and probes in `lock.c`/`tpc.c`/
   `search.c`, plus most S3 probe call sites (`list_walk.c`, `copy.c`,
   `multipart_*.c`, `post_object.c`, `put.c`'s secondary probes). On the
   `root://` stream side, the read-path's own lower-level probe helper
   (`brix_open_probe()` in `src/protocols/root/read/open_resolved_file.c`,
   used for write-target/symlink/dir pre-checks) is unrelated to
   `brix_vfs_probe`/`brix_vfs_ctx_t` entirely and is unconditionally
   identity-less by design — `tests/run_user_backend_cred_root.sh` documents
   this explicitly as expected behavior (the tested property there is that a
   denied user's *data* never reaches the origin, not that the origin sees
   zero traffic). None of these probe gaps let file data or a namespace
   mutation move under the wrong identity — only a pre-flight stat is
   affected; the mutations themselves (MOVE's rename via
   `webdav_move_execute_cred()`, file COPY's server-side copy) are now
   cred-bound — see [Supported](#supported). **The main WebDAV PUT
   existence probe is the one exception that IS fixed**: it calls
   `brix_vfs_ctx_bind_backend_cred()` (Phase 2), though it still does not
   call `brix_vfs_ctx_bind_backend_mint()` the way the real staged write
   does — so a bearer-only identity that would succeed via minting on the
   real write can see a `DECLINED` (service-cred) outcome on the pre-flight
   probe. Closing every remaining probe call site consistently is a
   follow-up.
2. **`mkdir`/`chmod` against a remote `root://`-backed export are not
   covered** — see the driver-capability gap noted above. This predates
   Phase 2 and is unrelated to credentials. (`root://` dirlist **is** now
   covered as of Phase 3 T2 — see [`root://` stream support](#root-stream-support-phase-2-t6--phase-3-t1t2).)

---

## `root://` stream support (Phase 2 T6 + Phase 3 T1/T2)

`brix_storage_credential_dir`/`_fallback` are registered on the stream
`server{}` block (`src/protocols/root/stream/module.c`,
`NGX_STREAM_SRV_CONF`) and threaded into the same shared
`common.storage_credential_dir`/`_fallback` fields the HTTP plane uses.
`src/protocols/root/read/open_resolved_file.c` and
`src/protocols/root/write/op_table.c` bind the session's `ctx->identity`
(the authenticated GSI/token identity — no longer hardcoded `NULL`) plus the
export's `storage_credential_dir`/`_fallback` before opening the origin
session, so `kXR_open`/read/write/`kXR_truncate`/`kXR_mv`/checksum/fattr
against a `brix_storage_backend root://…` origin authenticate as the
`root://` client's own identity (subject to the same allow/deny policy as
HTTP).

**Phase 3 T1 — stream minting.** `brix_storage_credential_mint_ca`/`_mint_ttl`
are now stream directives too, and `brix_vfs_ctx_bind_backend_mint()` is
called from the stream opens (`open_resolved_file.c:886`,
`write/truncate.c`, `query/checksum_qcksum.c`), so a bearer-only `root://`
identity with no pre-provisioned proxy can be minted one — minting is no
longer HTTP-only (see [Directives](#directives)).

**Phase 3 T2 — remote dirlist.** `sd_xroot` now implements
`opendir`/`readdir`/`closedir` + `opendir_cred` and advertises
`BRIX_SD_CAP_DIRS` (`sd_xroot.c:590-631`, `sd_xroot_ns.c:545-687`). It drives
a real `kXR_dirlist` wire client, `brix_cache_origin_dirlist()`
(`src/fs/cache/origin_ns.c:514-579`), which packs a `ClientRequestHdr` with
`requestid = htons(kXR_dirlist)`, sends it to the origin, and loops on the
`kXR_oksofar`/`kXR_ok` streaming reply to accumulate the directory names.
A `kXR_dirlist` against a `brix_storage_backend root://…` export now works
end-to-end and is credential-scoped through `opendir_cred`.

Edges that remain: `mkdir`/`chmod` still need the missing `sd_xroot`
`mkdir`/`setattr` driver slots (see
[namespace-ops nuance](#namespace-ops-nuance)); the stream read path's own
`brix_open_probe()` pre-check is identity-less by design (see above).

---

## HTTP Backend Per-User Bearer (Phase 2 T7)

`sd_http` (`src/fs/backend/http/sd_http.c`) implements `open_cred`: when the
VFS gate selects a `.token` credential for the requesting user, the per-open
object presents `cred->bearer` as its own `Authorization: Bearer <token>`
header instead of the instance's static bearer directive.

- `sd_http_open_common()` is the shared open path; `sd_http_open()` (plain)
  passes `cred=NULL`, `sd_http_open_cred()` passes the gate's cred. The bearer
  bytes are copied into the per-open object's own buffer (not the borrowed
  pointer), so they remain valid for the object's whole lifetime.
- `sd_http_pread()` — the only per-object I/O path that sends the header —
  prefers the per-open header, else falls back to the instance's static one.
- HEAD-for-size, staged PUT commit, and DELETE remain on the static header in
  Phase 2 T7 — only `pread` is credential-scoped.
- If `cred->x509_proxy` is set but `cred->bearer` is NULL (an x509 cred routed
  to an HTTP-backed export), `sd_http` cannot use it (no client-cert
  transport in this driver) and silently falls back to plain/static behavior.

### S3-backed remote origin per-user credential (Phase 3 T3)

`sd_s3` per-user credentials **are now implemented** via the `sd_remote`
wrapper. The S3 SigV4 transport (`src/fs/backend/s3/sd_s3.c`) is unchanged;
the per-user `open_cred` slot lives on `sd_remote`
(`src/fs/backend/remote/sd_remote.c:162-174`, registered at the vtable's
`.open_cred` field), which wraps `sd_s3`. When the VFS gate resolves a `.s3`
credential for the requesting user, `sd_remote_open_cred()` re-inits the
SigV4 signer for that open with the user's `s3_ak`/`s3_sk`/`s3_region`
(`sd_remote_open_impl()` → `sd_s3_open_read`/`_write` → `sd_s3_sign()` →
`brix_sigv4_signing_key()`) instead of the export's static access-key/secret
-key/region. If no per-user `.s3` credential is provisioned, it falls back to
the static export credential (`cred == NULL || s3_ak == NULL`). The IAM user
at the S3-compatible object store must already exist — provisioning that
identity is a deployment prerequisite outside this repo's control.

Test coverage is **unit-only** (`tests/c/test_ucred.c`, S3 section —
valid/invalid parse, region default, both precedence orderings, resolve-by
-key). There is **no S3-origin end-to-end nginx-level test** yet (unlike the
x509/token/root modes), a deliberately-accepted follow-up.

### Ceph-backed remote origin per-user credential (sd_ceph)

`sd_ceph` (`src/fs/backend/rados/sd_ceph.c`) **implements per-user CephX
credentials** via the `open_cred` vtable slot (`brix_sd_ceph_driver.open_cred
= sd_ceph_open_cred`, `sd_ceph.c:1589`). When the VFS gate resolves a
`.keyring` credential for the requesting user (see
[File path and kind precedence](#file-path-and-kind-precedence)),
`sd_ceph_open_cred()` authenticates to RADOS **as that CephX user** instead
of the export's static service credential, via a bounded per-`(user,
keyring)` connection cache (`SD_CEPH_CRED_CONN_CACHE_MAX = 8` slots,
`sd_ceph.c:230`) of live `rados_t`/ioctx pairs:

- Each cache entry is `rados_connect()`-ed once for that CephX entity and
  reused across that user's subsequent opens; a cache miss connects and
  inserts (evicting the LRU-oldest **unpinned** entry if the cache is full).
- Entries are **refcount-pinned** by every open object handle bound to them
  (`sd_ceph_obj_state_t.conn`) and released on `sd_ceph_close`; the LRU never
  destroys a pinned (in-use) connection — eviction skips pinned slots, and a
  pinned slot chosen to free a table slot is marked `doomed` and removed from
  the table without being destroyed (destruction happens when its last open
  handle closes).
- If every cache slot is pinned when a new user needs a connection, a fresh
  **uncached** connection is created for that one open (not inserted into the
  table, pinned for the object's lifetime, destroyed on close) so a
  legitimate concurrent identity beyond the cache bound still succeeds
  instead of failing the open.
- With no per-user keyring (`cred == NULL`), the driver falls through to the
  existing service `rados_t` exactly as before this feature.

Every raw byte op (`pread`/`pwrite`/`ftruncate`/`fstat`) on a cred-scoped
handle is keyed off the **open object's own** ioctx (not the export's), so
the open stays scoped to that user for its whole lifetime. `sd_ceph` does
**not** implement `staged_open_cred` — only the direct `open_cred` slot; a
staged/cache-wrapped export falls back to the same policy as other drivers
lacking that slot.

Test coverage: **live-tested against a real Ceph cluster**
(`tests/ceph/run_sd_ceph_cred_live.sh`), run inside the repo's Ceph build
container (`tests/ceph/build_in_container.sh`) against a
`tests/ceph_harness.sh` demo cluster — **not** part of the host CI suite,
since `sd_ceph`'s vtable block is gated on `BRIX_HAVE_CEPH`
(librados-devel), which is not installed on the host. The live test
provisions `client.bob` (rwx), `client.readonly` (r-only), and ten extra
read-only users `client.u0`..`client.u9`, and verifies: a per-user write as
`bob` succeeds byte-exact; a write attempted as the read-only user is
**denied at RADOS itself** (real per-user CephX enforcement at the cluster,
not admin-for-everyone); a held-open handle survives >8-connection eviction
pressure from the ten extra users without a use-after-free; and the process
fd count stays flat under >8 simultaneous transient opens (no leak). The
full design/build/operator-prerequisite writeup is in
[sd_ceph per-user credentials](#sd_ceph-per-user-credentials).

---

## Self-Service Delegation (T8 upload + T4 two-step)

`brix_delegation_endpoint on` (default `off`, WebDAV location only) exposes
the delegation endpoints under `/.well-known/brix-delegation`
(`src/protocols/webdav/dispatch.c` routes the paths; handler in
`src/protocols/webdav/delegation.c`). Two forms share this one directive:

- **Proxy-upload (Phase 2 T8)** — `PUT`/`POST /.well-known/brix-delegation`:
  the client already holds its own proxy and uploads the whole chain.
- **GridSite two-step (Phase 3 T4)** — `GET .../request` then
  `PUT .../<id>`: the server generates a CSR, the client signs it, so the
  client's proxy private key never has to leave its own host as a full
  proxy. See [Two-step (GridSite) flow](#two-step-gridsite-flow-phase-3-t4).

### Proxy-upload flow (Phase 2 T8)

**Flow:**

1. Require a **GSI/x509-client-certificate-authenticated** request
   (`ctx->verified && !ctx->token_auth && ctx->dn[0] != '\0'`) — bearer-token
   auth is rejected outright (no certificate chain to delegate from).
2. Read the whole body (cap 64 KiB) as a PEM-concatenated cert chain.
3. Find the end-entity cert (the one entry `brix_px_classify()` reports as
   `BRIX_PX_NONE`, i.e. not itself a proxy).
4. **Expiry check first**: any cert in the chain (proxy or EEC) with a
   past `notAfter` → `400 Bad Request`.
5. **DN match**: the EEC's subject DN (`brix_x509_oneline`, same
   normalization as `ctx->dn`) must equal the authenticated client's DN
   exactly → mismatch is `403 Forbidden` (a client may only upload a proxy
   for its own identity; checked *after* expiry so an expired+mismatched
   upload doesn't leak whether it names another identity).
6. Derive the credential key via `brix_sd_ucred_key(ctx->dn, …)` and
   atomically write the *entire uploaded PEM* (not just the EEC) to
   `<storage_credential_dir>/<key>.pem` — temp file
   `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW 0600`, write, fsync, `rename()`.
7. `201 Created` on success; the very next davs/S3 request from that same
   identity picks up the freshly-stored proxy via ordinary Phase-1 selection.

This is a **proxy-UPLOAD** delegation (the client already holds and simply
uploads its own proxy). The full GridSite `getProxyReq`/`putProxy` two-step
is now also implemented — see below.

> **Chain-of-trust (both forms).** Before storing any credential, the
> uploaded/assembled chain is verified cryptographically against the
> location's configured CA store via `delegation_chain_trusted()`
> (`delegation.c:296-325`) → `brix_gsi_verify_chain()` →
> `X509_verify_cert()` with `X509_V_FLAG_ALLOW_PROXY_CERTS`. The DN-equality
> check runs **after** this PKIX verification, so a client cannot plant a
> self-signed cert whose subject string merely spoofs its own DN. A location
> with no CA store (`conf->ca_store == NULL`) refuses to store rather than
> trust blindly.

### Two-step (GridSite) flow (Phase 3 T4)

Gated by the **same** `brix_delegation_endpoint on` directive (no new
directive). The standard GridSite `getProxyReq`/`putProxy` handshake, adapted
to plain HTTP (`src/protocols/webdav/delegation.c`):

1. **GET `/.well-known/brix-delegation/request`**
   (`webdav_delegation_request_handle`, `delegation.c:884-946`). Requires the
   same GSI/x509-client-cert authentication as the upload form. The server
   generates a **fresh private key** and a CSR for a proxy of the
   authenticated client, mints an unguessable 128-bit `RAND_bytes`
   delegation-id, and returns the CSR PEM as the body with the id in an
   `X-Brix-Delegation-Id` header. **The fresh private key never leaves the
   worker that generated it** (never serialized, never written to disk).
2. The client signs the CSR with its own end-entity key and assembles a
   signed proxy cert.
3. **PUT `/.well-known/brix-delegation/<id>`**
   (`webdav_delegation_put_handle`, `delegation.c:1258-1332`) with the
   signed proxy in the body. The server:
   - looks up **and removes** the id (one-shot — see below);
   - rechecks the id's bound `client_dn` against the authenticated client's
     DN (cross-client → `403`);
   - assembles the delegated credential via `brix_gsi_assemble_proxy()`
     (`src/auth/gsi/proxy_req.c`), which **proves key possession** by
     requiring `EVP_PKEY_eq(signed-proxy-pubkey, stored-request-key) == 1`
     (`proxy_req.c:598-599`) — only a client that received *this* CSR can
     satisfy it;
   - runs the same `brix_gsi_verify_chain()` chain-of-trust verification as
     the upload form;
   - atomically stores the assembled proxy at
     `<storage_credential_dir>/<key>.pem`.

**Binding, one-shot, and TTL.** Pending handshakes live in a fixed-capacity
(`BRIX_DELEG_STORE_CAP = 256`) per-worker table of `{id, fresh EVP_PKEY*,
client_dn, expires_at}` (`delegation.c:482-507`). `brix_deleg_store_take()`
(`delegation.c:648-678`) frees the entry on **every** terminal outcome
(match, DN-mismatch, or expired), so an id can be consumed at most once —
a determined attacker gets exactly one guess per id. The lifetime is
`BRIX_DELEG_TTL_SEC = 600` seconds (`delegation.c:480`), enforced lazily by
sweeping expired entries on every store `put`/`take` (no background timer).

**Multi-worker caveat.** The pending-handshake table is **per-worker
in-process memory, NOT SHM** (deliberately — the fresh private key must never
cross a process boundary). A `getProxyReq` and its matching `putProxy`
therefore **must land on the same worker**. For a single-worker deployment
this is automatic; a multi-worker deployment needs sticky routing (an L7
proxy keyed on client IP / TLS session, or a client that reuses the same
connection for both steps). See
[Remaining limitations](#remaining-limitations--follow-ups).

---

## Opt-in Minting (Phase 2 T9)

`brix_storage_credential_mint_ca <ca_cert.pem> <ca_key.pem>` (2 args, both
config-time-validated — `nginx -t` fails loudly on unparseable PEM material)
plus `brix_storage_credential_mint_ttl <seconds>` (default `3600`). When
configured, an identity with **no pre-provisioned proxy** (a bearer-only
identity: an S3 access key, or a WLCG token with no matching `.pem`) is
minted a short-lived EC P-256 x509 proxy, signed by the mint CA, and cached
at `<storage_credential_dir>/<key>.pem` for reuse until it nears expiry
(`src/fs/backend/cred_mint.c`, `mint_cached_pem_ok()` reuses an existing PEM
with more than a small refresh window of life left — no re-signing on every
request in steady state).

**Mechanics:** subject `/O=brix-minted/CN=<sanitized principal>`, issuer =
the mint CA's subject, `notBefore=now`, `notAfter=now+ttl`, signed with
`X509_sign(…, EVP_sha256())`. Minting is attempted at most once per
credential-gate decision, only when the backend driver can actually use a
per-user credential (`cap_ok`); a mint failure falls through to the ordinary
deny/fallback path unchanged.

### Minting trust warning

**Configuring `brix_storage_credential_mint_ca` means the frontend signs
per-user x509 identities with this CA's key. The remote origin MUST be
configured to trust this CA** for the minted credential to be usable there —
minting **shifts a piece of trust-root authority to the nginx-xrootd
frontend itself**. This is fundamentally different from Phase 1/T2's
model, where the frontend only ever *selects among* pre-provisioned
credentials it never had the power to mint. Off by default; enable only
when the origin's trust configuration has been updated to match.

**Minting is wired for both HTTP and `root://` stream (Phase 3 T1)** — from
`webdav/get.c`, `webdav/put.c`, `s3/util.c` on the HTTP plane and from
`root/read/open_resolved_file.c`, `root/write/truncate.c`,
`root/query/checksum_qcksum.c` on the stream plane (see
[Directives](#directives) and [`root://` stream
support](#root-stream-support-phase-2-t6--phase-3-t1t2)).

---

## Async Ownership Design (Flush-Time Credential + Dead-Letter)

Staged writes (`brix_stage_flush async`) are durable: the journal record on
disk survives a crash, and the owning identity travels with it
(`brix_stage_cred_t`, the final/append-only member of `brix_sreq_t` so old
records decode with a zeroed cred).

At flush time (`src/fs/xfer/stage_engine.c`):

1. `brix_sd_ucred_resolve(cred->dir, cred->key, &ru)` re-reads and re-checks
   the credential (expiry re-evaluated at flush, not at submit time).
2. Found-and-valid → the origin session uses the per-user credential.
3. Missing/expired + `deny=1` → the flush is refused (`BRIX_XFER_DENIED`);
   the ledger line carries `result=denied principal="<DN>"`; **the attempt
   count is bumped and the dead-letter cap evaluated** (below).
4. Missing/expired + `deny=0` → the flush proceeds on the service credential
   with a `WARN` log.

### Flush dead-letter (Phase 2 T4)

`stage_deny_terminal()` bumps `rec->attempts`, persists it, then checks
**either** cap:

```c
#define BRIX_STAGE_DENY_MAX_ATTEMPTS 5
#define BRIX_STAGE_DENY_MAX_AGE_SEC  (24 * 3600)
```

Below both caps, the record stays in the active journal for the next
scheduler tick or restart-reconcile pass (`WARN`-logged). Once **either**
cap is reached, `stage_journal_move_to_deadletter()` renames the record to
`<journal_dir>/deadletter/<reqid>.req` (creating that subdirectory `0700` on
demand) and emits a loud `NGX_LOG_ERR` tombstone naming the reqid,
principal, key, and destination. A dead-lettered write is **never** flushed
under the wrong identity — dead-letter means *stop retrying*, not *fall
back to the service credential*.

**Operator recovery** for a dead-lettered record: either (a) provision the
missing/renewed credential at the expected `<key>.pem`/`.token` path and
move the `.req` file back from `<journal_dir>/deadletter/` into
`<journal_dir>/` so the scheduler picks it up again, or (b) accept the loss
and remove the dead-lettered record (the staged bytes remain on local disk
under the stage directory until then — nothing is silently discarded).

**Legacy journal records** (written before this feature shipped) decode
with a zeroed `cred` via `brix_sreq_decode()`'s dual-size acceptance and
replay on the service credential, preserving pre-feature semantics.

---

## sd_ceph per-user credentials

**Status: IMPLEMENTED and live-tested against a real Ceph cluster,
conditionally compiled.** `sd_ceph` implements the `open_cred` vtable slot
(`sd_ceph.c:1589`); the feature is wired end-to-end from the `.keyring`
credential file through the VFS gate to a per-user RADOS connection. It is
compiled only when the frontend build has librados (`BRIX_HAVE_CEPH`); on a
build without librados-devel the Ceph driver's data-plane vtable block does
not compile in at all (unrelated to this feature — `sd_ceph` requires
librados regardless of per-user credentials).

### Build gate: `BRIX_HAVE_CEPH`

`./config` compile-probes for `<rados/librados.h>` + `-lrados` and only
defines `-DBRIX_HAVE_CEPH=1` on success; without the devel headers installed
the entire librados-backed vtable block (`sd_ceph.c` under `#if
BRIX_HAVE_CEPH`) — including `open_cred` — does not compile in, and the
Ceph driver row in `sd_registry.c` is skipped too. The host dev environment
for this repo does not have `librados-devel` installed by default, so Ceph
support (per-user or otherwise) is built and exercised via
`tests/ceph/build_in_container.sh`, a dedicated container image with
librados-devel, against a `tests/ceph_harness.sh` demo cluster — **not** the
host CI/PR suite.

### Credential file format: `<key>.keyring`

The fourth credential file kind, resolved after `.pem`/`.token`/`.s3` (and
subject to the same "expired `.pem` hard-declines, never falls through"
precedence rule — see
[File path and kind precedence](#file-path-and-kind-precedence)). The file is
a standard **CephX keyring**, exactly as the Ceph tooling emits it — so an
operator provisions it with the ordinary `ceph auth get-or-create
client.<user>` workflow:

```ini
[client.alice]
    key = AQD…base64-secret…==
    caps mon = "allow r"
    caps osd = "allow rwx pool=brixpool namespace=alice"
```

`ucred_read_keyring()` (`src/fs/backend/ucred.c:283-`, mirroring
`ucred_read_s3()`) scans for the **first** `[client.NAME]` section header and
extracts the bare entity id (`alice`, no `client.` prefix — librados's
`rados_create()` re-adds the prefix). `brix_sd_cred_t` carries
`ceph_keyring` (the keyring file's own **path** — never its secret contents)
and `ceph_user` (the bare id) (`src/fs/backend/sd.h:166-169`). The per-user
CephX **caps** live at the cluster, not in this file — the keyring only
carries the entity name + secret needed to authenticate as it, and librados
itself reads the secret straight out of the keyring file at
`rados_connect()` time.

### `open_cred` design: per-`(user, keyring)` `rados_t`, LRU-cached

Ceph differs fundamentally from S3 and cannot copy the `sd_s3` pattern.
**librados binds identity at cluster-connect time, not per-I/O.** The CephX
entity name and keyring are supplied before `rados_connect()`; every ioctx
and every read/write on that connection then runs as that entity. There is
no per-request credential override the way SigV4 re-signs each S3 request.

Consequently `sd_ceph_open_cred()` does **not** swap keys on the shared
service `rados_t` (that would race every other in-flight op and change the
identity cluster-wide for the process). Instead (`sd_ceph.c:1120-1420`):

- A **bounded LRU cache of per-`(user, keyring)` `rados_t`/ioctx pairs**
  (`SD_CEPH_CRED_CONN_CACHE_MAX = 8` slots, `sd_ceph.c:230`) lives on the
  driver instance state. Each entry is `rados_connect()`-ed once as that
  user's CephX entity and reused across that user's subsequent opens; a new
  distinct user pays one connect, and the LRU cap bounds the number of live
  cluster handles (each holds sockets + `MonClient` state).
- `sd_ceph_open_cred()` resolves the requesting user's handle from the cache
  (connecting + inserting on a miss), opens the export pool/namespace ioctx
  on **that** handle, and returns the per-open object bound to it — so the
  object's reads/writes authenticate as the user's CephX entity.
- Cache entries are **refcount-pinned** by every open object handle bound to
  them (`sd_ceph_obj_state_t.conn`), released in `sd_ceph_close`. The LRU
  never destroys a pinned (in-use) connection — eviction always skips pinned
  slots; a pinned slot chosen as the LRU victim to free a table slot is
  marked `doomed` and removed from the table **without** being destroyed
  (destruction happens when its last open handle's `sd_ceph_close` drops the
  refcount to zero). This closes a UAF the naive design would have had.
- If every cache slot is pinned when a new user needs a connection, a fresh
  **uncached** connection is created for that one open (not inserted into
  the table, pinned for the object's lifetime, destroyed on close), so a
  legitimate concurrent identity beyond the cache bound still succeeds
  instead of failing the open.
- With no per-user keyring (`cred == NULL`), the driver falls through to the
  existing service `rados_t` exactly as before this feature.

`sd_ceph` implements only `open_cred`, not `staged_open_cred`.

### Live test coverage

`tests/ceph/run_sd_ceph_cred_live.sh` runs inside the Ceph build container
against a `tests/ceph_harness.sh` cluster. It provisions `client.bob` (`mon
"allow r" osd "allow rwx pool=xrdtest"`), `client.readonly` (`osd "allow r
pool=xrdtest"`), and ten extra read-only users `client.u0`..`client.u9` (used
to force eviction pressure against the 8-slot connection cache while `bob`'s
write handle stays open), and verifies:

- A per-user write as `bob` succeeds and reads back byte-exact.
- A write attempted as `readonly` is **denied at RADOS itself** — real
  per-user CephX enforcement at the cluster, not an admin credential serving
  every user.
- A handle held open across more than 8 other users' opens (via `u0..u9`)
  survives cache eviction pressure without a use-after-free.
- Process fd count stays flat under more than 8 simultaneous transient opens
  by distinct users (no connection-cache leak).

### Operator prerequisites (outside this repo)

1. **`librados-devel`** (and `libradosstriper-devel` if the striper path is
   wanted) present at build time so `./config` sets `BRIX_HAVE_CEPH=1`.
2. **Per-user CephX identities provisioned at the cluster** —
   `ceph auth get-or-create client.<user>` with the appropriate pool/namespace
   caps. The frontend only *selects* an already-existing identity; it never
   mints CephX entities (unlike x509 minting, there is no Ceph analogue here).
3. The keyring file placed at `<storage_credential_dir>/<key>.keyring` for the
   principal, using the same key-derivation scheme as every other kind.

---

## Observability

### Metrics (Phase 2 T3)

Three per-protocol Prometheus counters, exported on `/metrics`
(`src/observability/metrics/unified.c`):

| Metric | Meaning |
|---|---|
| `brix_cred_select_user_total{proto="…"}` | A per-user credential was resolved and used. |
| `brix_cred_select_fallback_total{proto="…"}` | No usable per-user credential; fell back to the service credential (`fallback=allow`, or the driver can't scope a session to a user cred). |
| `brix_cred_select_deny_total{proto="…"}` | Refused (`fallback=deny`) — mapped to `EACCES`/403/`kXR_NotAuthorized`. |

Labels are `proto` only (low-cardinality, per repo invariant #8 — no DNs,
keys, or paths). Incremented from the five terminal outcomes in
`src/fs/vfs/vfs_cred.c`'s shared `vfs_backend_cred_decide()` — the same
decision body serves both the data-plane and namespace gates, so both are
reflected in one counter family. **Flush-time denial is not counted here**
— it is observable only via the xfer audit ledger (below), since a flush
denial is a distinct terminal outcome (dead-letter track), not a live
request's credential-select decision.

### xfer audit ledger

Every durable transfer emits one line via `brix_xfer_ledger_record()`
(`src/fs/xfer/xfer_ledger.c`) in the form:

```
… kind=<k> dir=<d> result=<r> bytes=<n> errno=<e> principal=<P> path="<path>"
```

A denied async flush appears as `result=denied principal="<DN>"`.

### Log lines

| Channel | Example |
|---|---|
| `error_log` INFO | `brix: no per-user backend credential for principal="<P>" key=<K> - falling back to the service credential` |
| `error_log` WARN | `brix: backend "<name>" cannot scope a session to a user credential - using the service credential for "<P>"` |
| `error_log` ERR | `brix: per-user backend credential EXPIRED\|missing for principal="<P>" key=<K> dir="<D>" (fallback=deny) - refusing` |
| `error_log` NOTICE (mint) | `brix: cred_mint: minted proxy for principal="<P>" key=<K> ttl=<T>s` |
| `error_log` INFO (delegation) | `brix_delegation: stored proxy for key=<K>` |
| `error_log` WARN (delegation) | `brix_delegation: DN mismatch — authenticated as "<DN>", uploaded proxy is for a different identity` |
| `error_log` ERR (dead-letter) | `xrootd stage: flush DEAD-LETTERED (reqid=<R> principal="<P>" key=<K> dst="<D>" attempts=<N> age=<S>s) - credential permanently missing/expired in deny mode; stage copy retained in deadletter/ for operator recovery` |

---

## Worked Configuration Examples

All four examples below are distilled from real, currently-passing test
configs (`tests/run_user_backend_cred.sh`, `run_user_backend_cred_ns.sh`,
`run_user_backend_cred_root.sh`, `run_delegation_upload.sh`).

### 1. Per-user x509, deny mode (davs)

```nginx
http {
    server {
        listen 8444 ssl;
        ssl_certificate         /etc/brix/hostcert.pem;
        ssl_certificate_key     /etc/brix/hostkey.pem;
        ssl_client_certificate  /etc/grid-security/certificates/ca.pem;
        ssl_verify_client       optional;
        ssl_verify_depth        4;

        location / {
            brix_webdav             on;
            brix_allow_write        on;
            brix_auth_cert           on;

            brix_export              /data/f/export;
            brix_storage_backend     root://origin.site.example:1094;
            brix_storage_credential  origin;          # static service credential

            brix_storage_credential_dir      /data/creds;
            brix_storage_credential_fallback deny;
        }
    }
}
```

### 2. Bearer `.token` credentials

Same shape as (1); provision `<key>.token` (a raw JWT, one line, no `.pem`
present for that key) under the same `brix_storage_credential_dir`. No
separate directive is needed — `.token` is just the other file kind
`brix_sd_ucred_resolve()` tries.

### 3. `root://` stream (Phase 2 T6)

```nginx
stream {
    server {
        listen 127.0.0.1:11094;
        brix_export /data/o/root;
        # origin server block …
    }

    server {
        listen 127.0.0.1:11095;
        brix_export               /data/f/export;
        brix_storage_backend      root://127.0.0.1:11094;
        brix_storage_credential   origin;
        brix_storage_credential_dir      /data/creds;
        brix_storage_credential_fallback deny;   # or allow
    }
}
```

`brix_storage_credential_fallback` only accepts `allow`/`deny` — `nginx -t`
rejects any other value on both the HTTP and stream directive tables.

### 4. Self-service delegation endpoint

```nginx
location / {
    brix_webdav               on;
    brix_allow_write          on;
    brix_auth_cert             on;

    brix_export                /data/f/export;
    brix_storage_backend       root://origin.site.example:1094;
    brix_storage_credential    origin;
    brix_storage_credential_dir      /data/creds;
    brix_storage_credential_fallback deny;

    brix_delegation_endpoint on;   # default off
}
```

A GSI-authenticated client can now:

```bash
# 1. Upload its own proxy once:
curl -s --cert alice_proxy.pem --key alice_proxy.pem \
     --data-binary @alice_proxy.pem \
     https://front.site.example/.well-known/brix-delegation
# -> 201 Created; <cred_dir>/<alice's key>.pem now exists

# 2. Every subsequent request authenticates to the origin as Alice:
curl -s --cert alice_proxy.pem --key alice_proxy.pem \
     https://front.site.example/some/path
```

### 5. Opt-in minting

```nginx
location / {
    brix_webdav               on;
    brix_allow_write          on;
    brix_auth_token            on;    # e.g. bearer-only identities (S3/JWT)

    brix_export                /data/f/export;
    brix_storage_backend       root://origin.site.example:1094;
    brix_storage_credential    origin;
    brix_storage_credential_dir      /data/creds;
    brix_storage_credential_fallback deny;

    # Opt-in: mint a short-lived proxy for identities with no pre-provisioned
    # credential. The ORIGIN must be configured to trust mint-ca.pem.
    brix_storage_credential_mint_ca  /etc/brix/mint-ca.pem /etc/brix/mint-ca-key.pem;
    brix_storage_credential_mint_ttl 3600;   # default shown
}
```

Minting is covered by a standalone C unit suite
(`tests/c/test_cred_mint.c`, `tests/c/run_cred_mint.sh`) exercising
`brix_cred_mint()` directly; there is not yet an end-to-end nginx-level test
for this mode (unlike modes 1–4 above, which all have passing e2e shell
tests).

---

## Remaining Limitations / Follow-ups

| Limitation | Detail |
|---|---|
| **sd_ceph per-user credentials — container-only test scope** | Implemented and live-tested (`tests/ceph/run_sd_ceph_cred_live.sh`), but only inside the repo's Ceph build container against the `tests/ceph_harness.sh` demo cluster — the host dev environment lacks `librados-devel`, so `BRIX_HAVE_CEPH` is undefined on the host and the feature does not run in the host CI/PR suite. See [sd_ceph per-user credentials](#sd_ceph-per-user-credentials). |
| **sd_s3 per-user credential — no S3-origin e2e** | The `.s3` per-user path (Phase 3 T3) is implemented and unit-tested (`tests/c/test_ucred.c`), but there is no end-to-end nginx-level test signing an actual S3 origin with a per-user `.s3` credential (unlike the x509/token/root modes). Deliberately-accepted follow-up. |
| **Two-step delegation is per-worker (multi-worker sticky routing)** | The Phase 3 T4 pending-handshake store is per-worker in-process memory, not SHM (the fresh proxy private key must never cross a process boundary). A `getProxyReq` and its matching `putProxy` must therefore hit the same worker; multi-worker deployments need sticky routing. Not a gap — a deliberate security constraint — but an operational requirement to document. See [Two-step (GridSite) flow](#two-step-gridsite-flow-phase-3-t4). |
| **WebDAV LOCK write-path status code (local-POSIX-export case)** | The per-user backend credential gate denial on a *remote-backed* export now maps to `403` (Phase 3 T1, `lock.c:583-619`). But a `500` remains for the **impersonation-broker mid-op `EACCES`** on a *local POSIX* export (no backend instance, `brix_webdav_backend_instance(conf,…) == NULL`): the underlying broker `EACCES`/`EPERM` is not remapped to `403`. The op IS blocked in both cases — only the local-export status code is imprecise. Follow-up in `lock.c`. |
| **Remaining pre-flight probes on the service credential** | Existence-probe call sites `webdav_move_probe()` in `move.c`, the equivalent in `copy.c`, and probes in `lock.c`/`tpc.c`/`search.c`, plus most S3 probe sites (`list_walk.c`, `copy.c`, `multipart_*.c`, `post_object.c`), and `root://`'s own `brix_open_probe()` in `open_resolved_file.c` never bind a credential to their context, so those specific stats run on the service credential even in `deny` mode. No file *data* or namespace mutation is ever performed under the wrong identity — MOVE's rename and file COPY's server-side copy are cred-bound (see [Supported](#supported)), and the data-plane opens are gated correctly; only these pre-flight stats are unscoped. The WebDAV PUT pre-flight probe IS cred-bound (Phase 2), but not mint-bound, so it can disagree with the real write for a to-be-minted identity. Closing every remaining probe site uniformly is a follow-up. |
| **`sd_xroot` mkdir/setattr (driver gap)** | No plain or `_cred` vtable slot exists for `mkdir` or `setattr`(chmod) on the `root://` remote-origin driver — predates credentials, unrelated to this feature, but blocks `mkdir`/`chmod` against any `brix_storage_backend root://…` export regardless of credential mode. (`opendir`/dirlist is **no longer** in this gap — closed by Phase 3 T2.) |
| **Pre-flight existence probes that are intentionally service-cred** | Any probe that is a pure stat-only, no-data operation (e.g. some collection-existence checks ahead of a cred-bound mutation) may legitimately stay on the service credential by design — see the per-probe notes above; this is distinct from an unclosed gap. |
| **Token `sub`-only principal** | Two issuers sharing the same `sub` value share a credential file; no `iss|sub` compound scheme yet (unchanged from Phase 2). |
| **DN 1024-byte buffer** | `ctx->dn` (`ngx_http_brix_webdav_req_ctx_t.dn`) is a fixed `char[1024]`; a DN longer than that truncates. Informational — no known real-world DN approaches this length. |
| **`sanitize_cn` permissive charset (minting)** | The minted-proxy CN sanitizer accepts a broad character set when deriving `/CN=<sanitized principal>` from an arbitrary bearer `sub`/DN; informational, not a known exploit, flagged for future tightening. |

---

## Key Source Files

| File | Role |
|---|---|
| `src/fs/backend/ucred.h` / `ucred.c` | Principal extraction, key derivation, `.pem`/`.token`/`.s3`/`.keyring` (Phase 3 T3 `ucred_read_s3()`; ceph-peruser `ucred_read_keyring()`) selection + precedence, PEM expiry check. |
| `src/fs/backend/cred_mint.h` / `cred_mint.c` | Phase 2 T9: opt-in EC P-256 proxy minting + atomic cache write. |
| `src/protocols/webdav/delegation.c` / `delegation.h` | Phase 2 T8 proxy-upload **and** Phase 3 T4 GridSite two-step (`getProxyReq`/`putProxy`) handlers, the per-worker pending-handshake store, and `delegation_chain_trusted()` chain-of-trust verification for both forms. |
| `src/protocols/root/stream/module.c` | Stream directive registrations: `brix_storage_credential_dir`/`_fallback` (Phase 2 T6) **and** `_mint_ca`/`_mint_ttl` (Phase 3 T1, setter `brix_conf_set_stream_mint_ca`). |
| `src/protocols/root/read/open_resolved_file.c`, `write/truncate.c`, `query/checksum_qcksum.c` | Phase 3 T1: `root://` stream data-plane `brix_vfs_ctx_bind_backend_mint()` call sites (stream-side minting). |
| `src/fs/backend/xroot/sd_xroot_ns.c` | Phase 3 T2: `sd_xroot` `opendir`/`readdir`/`closedir` + `opendir_cred`. |
| `src/fs/cache/origin_ns.c` | Phase 3 T2: `brix_cache_origin_dirlist()` — the `kXR_dirlist` wire client to a remote `root://` origin. |
| `src/fs/backend/remote/sd_remote.c` | Phase 3 T3: `sd_remote_open_cred()` — re-inits the SigV4 signer per open with the user's `.s3` `ak`/`sk`/`region`, wrapping `sd_s3`. |
| `src/fs/backend/rados/sd_ceph.c` | Ceph/RADOS driver (`#if BRIX_HAVE_CEPH`); implements the `open_cred` vtable slot (`sd_ceph_open_cred`) — per-user CephX auth via a bounded 8-slot per-`(user,keyring)` `rados_t` connection LRU (see [sd_ceph per-user credentials](#sd_ceph-per-user-credentials)). No `staged_open_cred`. |
| `src/fs/vfs/vfs_cred.c` | The single shared credential-gate decision body (`vfs_backend_cred_decide`) for both data-plane (`brix_vfs_backend_cred`) and namespace (`brix_vfs_ns_cred`) gates; mint-attempt integration; Phase 2 T3 metric emission. |
| `src/fs/vfs/vfs_internal.h` | `brix_vfs_ns_leaf()` — resolves to the leaf driver instance for namespace-op cred dispatch. |
| `src/core/config/http_common.c` | `brix_storage_credential_dir`/`_fallback`/`_mint_ca`/`_mint_ttl` directive registrations (HTTP). |
| `src/protocols/root/stream/module.c` | `brix_storage_credential_dir`/`_fallback` directive registrations (stream). |
| `src/protocols/webdav/module.c` | `brix_delegation_endpoint` directive registration. |
| `src/core/config/shared_conf.h` | Backing fields + init + merge defaults on `ngx_http_brix_shared_conf_t`. |
| `src/fs/backend/sd.h` | `brix_sd_cred_t` (incl. Phase 3 T3 `s3_ak`/`s3_sk`/`s3_region`), every `*_cred` vtable slot (`open_cred`, `stat_cred`, `rename_cred`, `*xattr_cred`, `opendir_cred`; `mkdir_cred`/`setattr_cred` still unimplemented for `sd_xroot`), and the `brix_sd_*_maybe_cred` inline forwarders — Phase 3 T1 hardens all ~13 forwarders to refuse (`errno=EACCES`) when `cred!=NULL && fallback_deny && driver->op_cred==NULL && driver->op!=NULL` (a defensive no-op today, since no shipping driver has that shape). |
| `src/fs/backend/xroot/sd_xroot.c` | `sd_xroot`'s `open_cred`/`staged_open_cred`/`stat_cred`/etc. implementations; Phase 3 T2 adds `opendir`/`readdir`/`closedir`/`opendir_cred` + `BRIX_SD_CAP_DIRS` (vtable at lines 590-631). |
| `src/fs/backend/http/sd_http.c` | Phase 2 T7: `open_cred` — per-open bearer header for `pread`. |
| `src/fs/xfer/stage_engine.h` / `stage_engine.c` | `brix_stage_cred_t`, journal record cred field, flush-time re-resolve, dead-letter caps + move-to-`deadletter/`. |
| `src/observability/metrics/metrics.h` / `unified.c` | `cred_select_{user,fallback,deny}_total[proto]` SHM counters + Prometheus export. |
| `src/fs/xfer/xfer_ledger.c` | Durable-transfer audit ledger (`result=denied principal=…`). |
| `src/protocols/webdav/move.c` | `webdav_move_execute_cred()` — cred-bound real rename via ctx-based `brix_vfs_rename()`. |
| `src/protocols/webdav/copy.c` | Cred+mint-bound pre-copy probe and data-plane `brix_vfs_copy()`/`server_copy`. |
| `src/protocols/s3/copy.c` | `s3_copy_vfs_ctx()` — cred+mint-bound S3 CopyObject (source and destination). |
| `src/protocols/webdav/prop_xattr.c` | Cred-bound LOCK-state xattr read/write against a remote-backed export. |
| `src/protocols/shared/http_serve_offload.c` / `.h` | Event-loop deny-gate before remote serve-offload posts to the worker thread; per-user credential detached-copied into the offload thread ctx and presented via `brix_sd_open_maybe_cred()`. Wired at `webdav/get.c`, `s3/object.c`; `cvmfs/handler.c` passes `vctx=NULL` by design. |
| `tests/run_user_backend_cred.sh` | E2E: data-plane HTTP, deny/allow/expiry/async-replay/audit-ledger. |
| `tests/run_user_backend_cred_ns.sh` | E2E: namespace ops (stat/mkdir/rename/unlink/xattr) cred-scoping. |
| `tests/run_user_backend_cred_root.sh` | E2E: `root://` stream data-plane + namespace cred-scoping. |
| `tests/run_delegation_upload.sh` | E2E: self-service delegation upload (success/DN-mismatch/expired/endpoint-off). |
| `tests/c/test_ucred.c` (S3 section) | C unit: `.s3` credential parse, region default, `.pem`/`.token`/`.s3` precedence, resolve-by-key (Phase 3 T3 — unit-only; no S3-origin e2e yet). |
| `tests/ceph/run_sd_ceph_cred_live.sh` | Ceph-container live e2e: provisions `client.bob`/`client.readonly`/`client.u0..u9` CephX users, verifies per-user RADOS write, cluster-enforced deny for a read-only user, held-handle survival under >8-connection LRU eviction pressure, and flat fd count under >8 concurrent transient opens. Runs inside `tests/ceph/build_in_container.sh` against `tests/ceph_harness.sh`; not part of the host CI/PR suite (needs `BRIX_HAVE_CEPH`). |
| `tests/c/run_cred_mint.sh` / `test_cred_mint.c` | C unit: minting (EC P-256 generation, signing, cache reuse, atomic write). |
| `tests/c/run_ucred_tests.sh` | C unit: principal derivation, key derivation, `.pem`/`.token` select/resolve. |
| `tests/c/run_sreq_compat.sh` | C unit: legacy vs full journal record decode. |
