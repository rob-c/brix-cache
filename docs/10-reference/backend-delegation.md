# Backend credential delegation — capability matrix

Reference for the phase-70 delegation seam: which credential *mechanisms* exist,
which `brix_backend_delegation` *modes* drive them, and which storage *backends*
can consume the result. Companion to
`docs/refactor/phase-90-plan-phase-remainder-register.md` §2 (open work) and
`docs/refactor/phase-70-full-credential-delegation.md` (original design).

## Modes

`brix_backend_delegation <mode>` (HTTP plane: `src/core/config/http_common.c:226`;
root:// stream mirror: `src/protocols/root/stream/module.c:217`; enum
`brix_cred_mode` in `src/fs/backend/sd.h`):

| Mode | Meaning | Status |
|---|---|---|
| `select` (default) | Pick a pre-provisioned per-user credential from `brix_storage_credential_dir` | LANDED |
| `passthrough` | Forward the front door's own credential (x509 proxy PEM or WLCG bearer) verbatim to the origin | LANDED |
| `exchange` | Trade the subject bearer for a backend-audienced token (RFC 8693) via the configured endpoint; no endpoint ⇒ documented fallback to verbatim forward (§5.4) | LANDED |
| `delegate` | Origin-protocol delegation performed by the backend leg itself | Partial — exists for TPC; not VFS-driven for non-TPC clients (P90-70.8) |
| `mint` | Mint a short-lived per-user credential from the configured mint CA (`brix_storage_credential_mint_ca`) | LANDED |
| `auto` | Best available of the above for the backend | LANDED (resolves through the same gate) |

Failure policy is uniform (`brix_vfs_deleg_deny`, `src/fs/vfs/vfs_deleg.c`):
with `storage_cred_deny` set, any missing/invalid/unacceptable live credential
is an immediate EACCES **before origin contact**; without it, the request falls
back to the service credential with `use_cred=0` — a wrong identity is never
forwarded.

## Mechanisms

| Mechanism | Entry point | Status |
|---|---|---|
| x509 proxy PEM (grid format: proxy cert · private key · issuing chain) | `brix_vfs_deleg_proxy` → 0600 temp via `brix_proxy_gsi_write_pem_temp`, pool-cleanup unlink+scrub. In-gate RFC-3820 chain re-verify against the capture site's CA store (P90-70.4, `brix_vfs_deleg_set_ca_store`) | LANDED |
| WLCG bearer token | `brix_vfs_deleg_bearer` (verbatim forward) | LANDED |
| RFC 8693 token exchange | `brix_token_exchange` (`src/auth/token/exchange.h`) driven from `brix_vfs_deleg_exchange` when `exchange` mode has an endpoint | LANDED |
| S3 STS AssumeRole | `brix_s3_sts_assume` (`src/auth/s3/sts.h`); gate hook `brix_vfs_deleg_sts_cred` is call-ready but **not driven** (no capture-site conf bind) | DEFERRED (P90-70.1) |
| krb5 GSS forward to origin | `brix_krb5_deleg_to_origin` (`src/auth/krb5/forward.h`); hook `brix_vfs_deleg_krb5_token` call-ready, **not driven** | DEFERRED (P90-70.2) |
| SSS keytab identity injection | `brix_vfs_deleg_sss` (`src/fs/vfs/vfs_deleg.c`): when the bag carries **no** forwardable bytes, assert the caller's authenticated principal to the origin via an in-process SSS mint signed with `brix_backend_sss_keytab` (`brix_sss_build_proxy_credential` at origin bootstrap). Fail-closed: no identity → `FAIL_MISSING`; principal over the 63-byte SSS NAME TLV bound → `FAIL_MATERIALISE` (never truncated); SSS-refusing backend → `FAIL_KIND`. Proven bytes (PEM/bearer) always win over injection | LANDED (P90-70.3) |

### `brix_backend_sss_keytab <path>` (HTTP + stream planes)

Arms SSS identity injection for the export. The setter
(`brix_conf_set_backend_sss_keytab`, `src/core/config/helpers.c`) load-validates
the keytab at config time via `brix_sss_load_keytab` — a missing, non-private
(not 0400/0600), or unparseable keytab fails `nginx -t`. At request time the
delegation gate re-issues an SSS credential asserting the **caller's**
principal (DN preferred, else subject), signed with this keytab; the keytab's
own principal never acts at the origin, and per-user injection never falls back
to a service credential on `kXR_authmore` or a missing origin `sss` advert.
Stamped onto the VFS ctx by `brix_proto_deleg_stamp_conf`
(`src/protocols/shared/deleg_wire.c`) at all three front doors; reachable under
`passthrough`/`exchange` modes (the bag-routed modes). Note: async cache-flush
legs re-resolve credentials outside this gate and are out of scope here.

### `brix_backend_token_exchange_endpoint <url>` — load-validated

The RFC-8693 exchange client (`src/auth/token/exchange.c`) pins libcurl to
HTTPS-only (a subject token plus the client secret ride every request), so the
setter (`brix_conf_set_backend_tx_endpoint`, `src/core/config/http_common.c`,
P90-70.8) rejects at `nginx -t` time anything that could never be reached or
would corrupt the request: non-`https://` schemes, host-less URLs, and
whitespace/control bytes (the value is spliced into `CURLOPT_URL` verbatim).
Before this, an `http://` endpoint parsed fine and only surfaced as every
EXCHANGE delegation fail-closing at first use. Remaining phase-70 §6 load
validation (STS endpoint, KDC realm) lands with the P90-70.1/.2 conf binds —
those directives do not exist yet.

## Capture sites (where the live credential enters the bag)

| Front door | Capture | CA store stamped for the in-gate re-verify |
|---|---|---|
| WebDAV/HTTP | TLS client-cert delegation + `X-Brix-Delegate-Proxy` channel (`src/protocols/webdav/access.c::webdav_vfs_bind_deleg`) | `conf->ca_store` at `conf->verify_depth` |
| root:// | inline `kXRS_x509_fullproxy` bucket (`gsi_promote_fullproxy`; bind in `src/protocols/root/path/op_path.c`) | `conf->gsi_store` at depth 0 (matches login-path verify) |
| gsiftp | GSI delegation forwarded to a `root://` backend, upstream authenticates AS the user (phase-82 P82.9, `docs/refactor/phase-82-gridftp-gateway.md`) | via the root:// leg |

Client-side note: our native client emits `kXRS_x509_fullproxy` when
`XRD_DELEGATEFULLPROXY` is set (verified/hardened as P90-70.5; sender
`gsi_add_fullproxy_bucket` in the shared kernel
`src/auth/gsi/gsi_core_cresp_util.c`, so every libxrdproto linker gets it) —
strictly off by default, guarded proxy-file open (O_NOFOLLOW, regular file,
euid-owned, `/tmp/x509up_u<uid>` fallback). Stock xrootd clients do not emit
it; live e2e proof: `tests/test_fullproxy_passthrough.py`.

## Backend acceptance (`driver->cred_accept`, phase-71 gate)

The dispatcher denies **before origin contact** when the live credential kind is
not in the leaf backend's accept mask (`brix_sd_cred_accept(brix_vfs_ns_leaf())`,
`src/fs/backend/sd_registry.c:196`):

| Backend driver | Accepts |
|---|---|
| `sd_xroot` | `BEARER \| PROXY_PEM \| SSS` |
| `sd_http` | `BEARER \| PROXY_PEM` |
| `sd_remote` | `BEARER \| PROXY_PEM` |
| `sd_pblock` | `IDENTITY` (name-bound identity record, no forwarded secret) |
| all others (posix, rados, block, cache, frm, stage, …) | `NONE` — delegation denied/falls back; local backends act as the service identity |

## Tests

- Gate unit: `tests/c/deleg_gate_test.c` (runner `deleg_gate` in
  `tests/cmdscripts/c_auth_units.py`) — trusted-chain materialise + scrub,
  no-store back-compat, rogue-CA and garbage-PEM denies, setter guards, and the
  SSS-injection cases (caller asserted; no-identity / over-bound / kind denies;
  proven-bytes precedence; bag-allocating `brix_vfs_deleg_set_sss`).
- Live matrix: `tests/test_cmd_fwd_matrix_live.py` (`tests/cmdscripts/fwd_matrix_live.py`)
  — passthrough good path + wrong-identity deny end-to-end.
- gsiftp delegation: `tests/test_gridftp_delegate_xrootd.py`.
- Full-proxy passthrough live e2e (opt-in accept over TLS · default-off ·
  cleartext reject) + kernel source contract: `tests/test_fullproxy_passthrough.py`.
- Exchange-endpoint load validation: `tests/test_tx_endpoint_load_validation.py`.
- S3 STS endpoint load validation: `tests/test_sts_endpoint_load_validation.py`.
- S3 STS exchange seam unit: `tests/c/sts_units_test.c` (runner `sts_units` in
  `tests/cmdscripts/c_auth_units.py`) — links the real `sts_http.o` XML parser +
  `sts_sign.o` SigV4 builder against the production `ngx_snprintf`/crypto, on
  canned responses and fixed inputs (no network, no wall clock): well-formed
  AssumeRole/GetSessionToken parse + build, a stable 64-hex signature, and the
  fail-closed paths — unparseable body, missing/empty secret, over-tight output
  buffers, and a hostile oversized secret field bounded (canary) within the
  caller's buffer, never leaking a partial secret.
  (http+https accepted — SigV4 never transmits the secret; scheme-less /
  host-less / control-byte rejected at `nginx -t`).
