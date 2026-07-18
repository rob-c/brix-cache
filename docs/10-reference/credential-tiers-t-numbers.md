# The "T-number" credentials decoded — T4, T6, T8 and friends

**Status: source-verified 2026-07-16.** This page decodes the `T<n>` shorthand
that has grown around the per-user backend credential machinery, documents
every credential *kind* and every *acquisition path* into the credential
store, and records in detail what was discovered (and fixed) about the T4
GridSite two-step form on 2026-07-16.

Companion pages:
- [per-user-backend-credentials.md](per-user-backend-credentials.md) — the
  full feature reference (directives, gates, metrics, limitations).
- [arc-ce-httpg-front-proxy.md](../05-operations/arc-ce-httpg-front-proxy.md)
  — a worked deployment that consumes these credentials as an ARC-CE
  forwarding proxy.

---

## 1. What a "T-number" actually is (read this first)

The T-numbers are **not** a credential type system. They are **task IDs from
the per-user-backend-credentials work programme**, one sequence per phase —
and because the tasks that shipped user-visible credential features are the
ones people talk about, a handful of them ("T8 upload", "T4 two-step") have
become de-facto names for those features.

Two consequences worth internalising:

1. **The same number means different things in different phases.** There is a
   Phase 2 T4 (flush dead-lettering) *and* a Phase 3 T4 (GridSite two-step
   delegation). When someone says "the T4 credential" they always mean
   **Phase 3 T4**; when they say "T8" they always mean **Phase 2 T8**. No
   other collisions are in colloquial use, but check the phase column below
   before trusting a bare number.
2. **Not every T-number is a credential.** Several are metrics, status-code
   fixes, or plumbing. The full decoder:

### Phase 1 (no T-numbers)
x509 `.pem` proxies for the **HTTP data plane only** (`davs://`/S3 front →
`root://` origin GET/PUT fill). Established the store, the `x5h-` keying and
the `allow|deny` fallback gate.

### Phase 2 T-numbers

| ID | What it is | Credential-relevant? |
|----|------------|---------------------|
| **T1** | Per-user credential for **namespace ops** (stat/unlink/xattr/rename; DELETE/MKCOL/GET/HEAD/PROPFIND pre-flight) via `brix_vfs_ns_leaf()` + `*_cred` vtable slots | consumption path |
| **T2** | **`.token` credential kind** — per-user WLCG bearer JWT as a stored credential file | credential kind |
| **T3** | Prometheus counters `brix_cred_select_{user,fallback,deny}_total{proto}` | no (observability) |
| **T4** | Durable **dead-lettering** of permanently-denied async flushes (`<journal>/deadletter/<reqid>.req`) | no (plumbing) — **do not confuse with Phase 3 T4** |
| **T5** | (not in colloquial use — see the phase plan in `docs/superpowers/plans/` if you need the gap-fill tasks) | — |
| **T6** | **`root://` stream data-plane consumption** — per-user x509 proxy presented on stream opens (read/write/truncate/rename/checksum/fattr) | consumption path |
| **T7** | `sd_http` per-open **bearer** credential (read/`pread` only; other verbs ride the static instance header) | consumption path |
| **T8** | **Self-service proxy-upload delegation endpoint** — `PUT`/`POST /.well-known/brix-delegation` | acquisition path (§4) |
| **T9** | **Opt-in short-lived proxy minting** — EC P-256 signed by an operator mint CA | acquisition path (§6) |

### Phase 3 T-numbers

| ID | What it is | Credential-relevant? |
|----|------------|---------------------|
| **T1** | Minting extended to the `root://` **stream** (`brix_storage_credential_mint_ca/_ttl` on `server{}`); also the LOCK deny→403 fix | acquisition scope widening |
| **T2** | Per-user credential for `root://` remote **dirlist** (`sd_xroot` `opendir_cred` + real `kXR_dirlist` wire client) | consumption path |
| **T3** | **`.s3` credential kind** — per-user access-key/secret-key/region for S3-backed origins | credential kind |
| **T4** | **GridSite two-step delegation** (`getProxyReq`/`putProxy`) — the standard grid delegation handshake | acquisition path (§5) |

### Outside the T-sequences

| Name | What it is |
|------|------------|
| Ceph-peruser | **`.keyring` credential kind** — per-user CephX keyring for `sd_ceph` RADOS origins |
| native GSI wire delegation | `kXGS_pxyreq`/`kXGC_sigpxy` over the `root://` stream (phase-57 §F6) — same crypto primitives as T4, different transport; feeds the **TPC pull**, not the credential store |
| T14, T22 | red herrings — cvmfs/VFS proxy-mode task IDs from *other* work programmes; nothing to do with credentials |

---

## 2. The credential store — where every path converges

Whatever the acquisition path, the result lands in one place: the directory
named by `brix_storage_credential_dir`, one file per user identity. The
directive **defaults to `/dev/shm/brix-creds`** — a RAM-backed (tmpfs)
directory, so delegated private keys never persist across a reboot and never
land on real disk — created 0700/worker-owned at config time
(`brix_shared_credential_dir_ensure`, `src/core/config/shared_conf.h`); an
unusable path emits a startup `[warn]` naming the fix but never blocks
startup. Explicit `""` turns the per-user store off.

```
                    brix_storage_credential_dir/
                    ├── alice@site.org.pem            <- literal principal key
                    ├── x5h-3f1c9a....pem             <- hashed-DN key (x509 users)
                    ├── x5h-77ab02....token           <- WLCG bearer JWT
                    ├── x5h-9c44de....s3              <- ak / sk / region (3 lines)
                    └── x5h-b012f3....keyring         <- CephX keyring
```

**Key derivation** (`brix_sd_ucred_key`, `src/fs/backend/ucred.c`): if the
principal matches `[A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}` it is used literally;
otherwise (every x509 DN, since it contains `/` and `=`):

```
key = "x5h-" + sha256(oneline_DN)[:32]      # first 32 hex chars
```

Python equivalent, used throughout the test suites:

```python
"x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]
```

**Kind precedence** for one key, strictly mutually exclusive:

```
<key>.pem  >  <key>.token  >  <key>.s3  >  <key>.keyring
   |
   +-- an EXPIRED .pem hard-declines: it does NOT fall through to .token
```

**The gate** (`brix_storage_credential_fallback`): `allow` (default) falls
back to the export's static service credential when no per-user file exists;
`deny` refuses the operation (`EACCES` → 403). `deny` is what makes the store
authoritative — use it whenever impersonation-by-service-credential would be
a security problem.

### 2.1 What a complete `.pem` looks like — and why "complete" matters

Every downstream consumer loads the certificate chain **and the private key
from the same single file**:

```
   x5h-<hash>.pem
   ┌──────────────────────────────────┐
   │ -----BEGIN CERTIFICATE-----      │  <- RFC 3820 proxy cert (leaf)
   │ ...                              │
   │ -----END CERTIFICATE-----        │
   │ -----BEGIN CERTIFICATE-----      │  <- EEC (user cert), + any
   │ ...                              │     intermediate chain
   │ -----END CERTIFICATE-----        │
   │ -----BEGIN PRIVATE KEY-----      │  <- THE PROXY'S PRIVATE KEY.
   │ ...                              │     Without this block the file
   │ -----END PRIVATE KEY-----        │     can authenticate NOTHING.
   └──────────────────────────────────┘
```

PEM readers make this layout safe in both directions: a cert-reader
(`PEM_read_bio_X509` loop, nginx `proxy_ssl_certificate`) stops cleanly at
the key block; a key-reader (`PEM_read_bio_PrivateKey`,
`proxy_ssl_certificate_key`, `cache_origin_load_proxy_key`) skips the cert
blocks. Block *order* therefore doesn't matter to consumers — T8 stores
`cert,key,chain` (whatever the user uploaded, typically `arcproxy` order)
while T4 and the native wire path emit `cert,chain,key`; both work.

---

## 3. Acquisition paths — the map

Five ways a credential gets into (or is synthesized for) a user session:

```
                                       ┌────────────────────────────────┐
 (0) operator drops files by hand ────►│                                │
                                       │                                │
 (T8) user UPLOADS own proxy ─────────►│   brix_storage_credential_dir  │
      PUT /.well-known/brix-delegation │      <key>.pem / .token /      │
                                       │        .s3 / .keyring          │
 (T4) user SIGNS server CSR ──────────►│                                │
      GET  .../request  -> CSR + id    └───────────────┬────────────────┘
      PUT  .../<id>     <- signed proxy                │ read at request time
                                                       ▼
 (T9) frontend MINTS a fresh proxy ──────────► synthesized in-memory,
      (mint CA + TTL, per request)             never needs a stored file
                                                       │
 (F6) native GSI wire delegation ────────────► per-connection ctx only   │
      kXGS_pxyreq / kXGC_sigpxy                (feeds the TPC pull;      │
      over root:// stream                       NOT the credential dir)  │
                                                       ▼
                                     consumers: T1 ns-ops, T2/.token,
                                     T6 root stream, T7 http bearer,
                                     .s3/.keyring open_cred, TPC pull,
                                     $brix_delegated_cred back leg (ARC)
```

Trust/exposure comparison — the most important table on this page:

| Path | Whose key signs the proxy | Does a private key cross the wire? | Key stored server-side? | Trust shift |
|------|--------------------------|-----------------------------------|------------------------|-------------|
| (0) operator | user's (pre-made proxy) | no (out of band) | yes, whole proxy | operator handles user keys |
| **T8 upload** | user's own key (client-side `arcproxy`/`voms-proxy-init`) | **yes — the proxy's private key travels inside the EEC-authenticated TLS session** | yes, verbatim | user consciously hands the gateway a bounded-lifetime credential |
| **T4 two-step** | user signs a **server-generated** CSR | **no** — only the CSR and the signed cert travel | yes (server-side key + signed cert) | classic GridSite: key never leaves its generator |
| **T9 minting** | the **frontend's mint CA** | no | no (synthesized per request) | **largest shift**: backends must trust the frontend's CA to assert any user |
| F6 wire | user signs server CSR (in-protocol) | no | per-connection memory only | same crypto as T4, scoped to one TPC |

---

## 4. T8 — proxy-upload delegation (Phase 2 T8)

The simple form: the user already has a proxy (made client-side with their
own key) and deposits it whole.

```
 user (holds EEC key + a fresh proxy)                nginx/brix front
 ────────────────────────────────────                ─────────────────
        │                                                   │
        │ 1. TLS handshake, client cert = EEC               │
        │    (NOT the proxy — see below)                    │
        │◄─────────────────────────────────────────────────►│
        │                                                   │
        │ 2. PUT /.well-known/brix-delegation               │
        │    body = full proxy PEM (cert+KEY+chain)         │
        │──────────────────────────────────────────────────►│
        │                                                   │ 3. parse chain
        │                                                   │ 4. PKIX-verify vs
        │                                                   │    cafile / cadir
        │                                                   │ 5. EEC DN == ctx->dn
        │                                                   │    (STRICT equality)
        │                                                   │ 6. store VERBATIM ->
        │                                                   │    <x5h-key>.pem
        │ 7. 201 Created                                    │
        │◄──────────────────────────────────────────────────│
```

Handler: `src/protocols/webdav/delegation.c` (T8 sections). Enabled by
`brix_delegation_endpoint on` inside a location that also has `brix_webdav
on`, **`brix_allow_write on`** (a read-only export 403s the PUT before
delegation dispatch — empirically rediscovered every time), `brix_webdav_auth
required`, `brix_webdav_cafile` (or `brix_webdav_cadir` for a hashed CA
directory), and `brix_storage_credential_dir`.

Two properties discovered the hard way, now encoded as security-negative
tests in `tests/test_arc_httpg_proxy.py`:

- **The upload must be EEC-authenticated, not proxy-authenticated.** The
  WebDAV GSI auth keeps the *full* leaf DN in `ctx->dn` — for a proxy that is
  `<EEC DN>/CN=<serial>` — and step 5's strict equality against the uploaded
  chain's EEC DN then fails → 403. This is deliberate: it pins the uploader
  to the long-lived identity.
- **The stored file is byte-for-byte what the user sent**, so the private key
  block survives (the chain *parse* used for verification simply skips it).
  That's why T8 credentials always worked downstream.

## 5. T4 — GridSite two-step delegation (Phase 3 T4), and the 2026-07-16 fix

The standard grid delegation handshake (same shape as GridSite/gLite
`getProxyReq`/`putProxy`, myproxy, HTCondor-CE): the private key for the new
proxy is generated **server-side** and never crosses the wire in either
direction.

```
 user (holds EEC key)                                nginx/brix front
 ─────────────────────                               ─────────────────
        │                                                   │
        │ 1. GET /.well-known/brix-delegation/request       │
        │──────────────────────────────────────────────────►│
        │                                                   │ 2. generate fresh
        │                                                   │    keypair REQKEY
        │                                                   │    + CSR; park
        │                                                   │    (id, ctx->dn,
        │                                                   │    REQKEY) in the
        │                                                   │    per-worker
        │                                                   │    delegation table
        │ 3. 200: body = CSR,                               │    (TTL 600s,
        │    X-Brix-Delegation-Id: <id>                     │     one-shot)
        │◄──────────────────────────────────────────────────│
        │                                                   │
        │ 4. sign CSR with OWN key                          │
        │    (openssl x509 -req -CA usercert                │
        │     -CAkey userkey -copy_extensions copy)         │
        │                                                   │
        │ 5. PUT /.well-known/brix-delegation/<id>          │
        │    body = signed proxy + EEC chain                │
        │──────────────────────────────────────────────────►│
        │                                                   │ 6. take(id): 404
        │                                                   │    unknown, 410
        │                                                   │    expired, 403 if
        │                                                   │    ctx->dn != owner
        │                                                   │ 7. assemble:
        │                                                   │    pubkey(proxy) ==
        │                                                   │    pubkey(REQKEY)?
        │                                                   │    (proof of
        │                                                   │     possession)
        │                                                   │ 8. PKIX + expiry +
        │                                                   │    EEC-DN checks
        │                                                   │    (same as T8)
        │ 9. 201 Created                                    │ 10. store credential
        │◄──────────────────────────────────────────────────│
```

Handlers: `src/protocols/webdav/delegation.c` (routing, id table, PUT
handler); crypto primitives shared with the native wire path in
`src/auth/gsi/proxy_req.c` (build CSR), `proxy_req_sign.c` (client-side sign,
used by tests), `proxy_req_assemble.c` (assemble).

### 5.1 The discovery: T4 stored a credential with no private key

Found 2026-07-16 while building the ARC-CE forwarding-proxy lab. Empirically:
a two-step-delegated `x5h-*.pem` contained the proxy cert and chain but **no
key block**, so it could not complete any downstream TLS handshake — the
credential store's entire purpose. Root cause in
`brix_gsi_assemble_proxy()`:

```
        BEFORE (broken)                          AFTER (fixed 2026-07-16)
 ┌───────────────────────────┐            ┌───────────────────────────┐
 │ verify pubkey(proxy)      │            │ verify pubkey(proxy)      │
 │        == pubkey(REQKEY)  │            │        == pubkey(REQKEY)  │
 │                           │            │                           │
 │ out = proxy ‖ chain       │            │ out = proxy ‖ chain ‖     │
 │       (REQKEY used only   │            │       PEM(REQKEY)         │
 │        for the check,     │            │       (key serialized     │
 │        then freed!)       │            │        into the blob,     │
 └───────────────────────────┘            │        temp cleansed)     │
   stored file: certs only                └───────────────────────────┘
   -> cannot authenticate                   stored file: complete
      ANYTHING downstream                   -> real mTLS handshakes work
```

Why it went unnoticed: the *native* `root://` wire-delegation consumer
(`src/auth/gsi/delegation.c`, `kXGC_sigpxy`) had privately worked around it —
it called assemble only as a verification step, threw the output away, and
hand-built `proxy+chain+key` itself for the TPC pull. The WebDAV T4 handler
(written later, Phase 3) trusted assemble's output and stored it as-is.

The fix moved key serialization *into* `brix_gsi_assemble_proxy` (output is
now `proxy ‖ chain ‖ key`, certs first so cert-readers stop cleanly at the
trailing key block) and deleted the native path's hand-rolled duplicate.
Regression coverage:

- `src/auth/gsi/proxy_req_unittest.c` — assembled credential must contain
  exactly the 2 certs **plus** a private key that `EVP_PKEY_eq`-matches the
  request key (run via `tests/test_gsi_proxy_crypto.py`).
- `tests/test_delegation_t4_credential.py` +
  `tests/configs/nginx_t4_delegation_handshake.conf` — end-to-end: run the
  two-step against a real nginx, assert the stored PEM holds proxy+chain+KEY
  with the key matching the proxy cert, then **complete a real mTLS
  handshake** using only the stored file against a verifier server, and prove
  the pre-fix on-disk form (certs stripped of the key) cannot even load as a
  client credential.
- `tests/test_cmd_delegation_twostep.py` — the pre-existing flow/rejection
  matrix (wrong owner 403, unknown id 404, garbage 400, untrusted EEC 403,
  endpoint-off inert), still green.

### 5.2 T4 vs T8 — when to use which

| | T8 upload | T4 two-step |
|---|---|---|
| user's proxy private key crosses the wire | yes (inside EEC-authed TLS) | **no** |
| client tooling needed | anything that can PUT a file | CSR signing (openssl / arcproxy-style delegation) |
| proxy lifetime control | whatever the user minted | whatever the user signs into the cert (server suggests via CSR) |
| proof of key possession | implicit (they sent the key) | explicit (`EVP_PKEY_eq` vs CSR pubkey) |
| standardness | brix-specific convenience | GridSite-compatible shape |

Both land in the same store, pass the same PKIX/expiry/DN validation, and are
indistinguishable to consumers.

## 6. T9 — minting (the "no stored file" path)

With `brix_storage_credential_mint_ca <cert> <key>` +
`brix_storage_credential_mint_ttl`, a request whose identity has **no**
stored credential can have a short-lived EC P-256 proxy synthesized on the
fly, signed by the operator's mint CA. Nothing is written to the credential
dir. **Trust warning**: the origin must trust the mint CA, which means the
frontend can assert *any* identity — this inverts the delegation trust model
(T4/T8: user empowers gateway; T9: gateway empowers itself). Phase 3 T1
extended minting to the `root://` stream listener.

## 7. Consumption — who reads these credentials

| Consumer | T-label | Mechanism |
|----------|---------|-----------|
| HTTP data-plane origin opens (davs/S3 → remote origin) | Phase 1 | `sd_xroot` open with `.pem` |
| namespace ops (stat/unlink/rename/xattr/…) | Phase 2 T1 | `brix_vfs_ns_leaf()` → `*_cred` vtable slots |
| `root://` stream data-plane | Phase 2 T6 | stream `server{}` directives, cred bound at open |
| HTTP-origin bearer reads | Phase 2 T7 | `.token` → per-open Authorization header |
| remote dirlist | Phase 3 T2 | `opendir_cred` → wire `kXR_dirlist` |
| S3-origin SigV4 | Phase 3 T3 | `.s3` → per-open signer re-init |
| RADOS/CephX | Ceph-peruser | `.keyring` → per-user `rados_t` (LRU-cached) |
| TPC pull | F6 | in-memory assembled credential (not the store) |
| **generic nginx back leg** (ARC-CE front proxy) | — | `proxy_ssl_certificate(_key) $brix_delegated_cred` — the variable re-derives the x5h store key from the verified chain's EEC DN, works because the stored file is complete |

That last row is the pattern the ARC-CE lab uses and the reason the T4 gap
was user-visible: `proxy_ssl_certificate_key $brix_delegated_cred` needs the
key block in the resolved file. See
[arc-ce-httpg-front-proxy.md](../05-operations/arc-ce-httpg-front-proxy.md).

---

## 8. Quick reference

```
T-number cheat card (colloquial meanings)
─────────────────────────────────────────
 "T8"  = Phase 2 T8  = proxy-UPLOAD delegation  (user's key travels, stored verbatim)
 "T4"  = Phase 3 T4  = GridSite TWO-STEP        (server-side key, CSR signed by user)
 "T9"  = Phase 2 T9  = MINTING                  (frontend CA synthesizes, trust shift!)
 "T6"  = Phase 2 T6  = root:// stream CONSUMES the store
 "T2"  = Phase 2 T2  = .token credential kind   (WLCG bearer)
 "T7"  = Phase 2 T7  = http-origin bearer consumption (reads only)
 P3 T2 = remote dirlist consumption
 P3 T3 = .s3 credential kind
 P2 T1 = namespace-op consumption
 P2 T3/T4, P3 T1     = metrics / dead-letter / mint-scope plumbing (NOT credentials)
 T14, T22            = unrelated (cvmfs proxy-mode task IDs)

 stored file kinds:  .pem > .token > .s3 > .keyring   (expired .pem hard-declines)
 key derivation:     literal principal, else x5h- + sha256(oneline DN)[:32]
 complete .pem:      proxy cert + chain + PRIVATE KEY   (all three, one file)
```
