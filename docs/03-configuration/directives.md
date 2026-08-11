# Configuration directive reference

Reference for the most commonly-used `brix_*` directives — name, context, type, default, and what each one actually does. For a single-table summary of the most-used directives, see [quick-reference.md](quick-reference.md). Some advanced features are summarized in their subsystem docs first; for example, health checks live in [`src/net/upstream/README.md`](../../src/net/upstream/README.md), traffic mirroring in [`src/net/mirror/README.md`](../../src/net/mirror/README.md), and advanced rate/bandwidth/concurrency limits in [`src/net/ratelimit/README.md`](../../src/net/ratelimit/README.md).

[← Configuration overview](config-reference.md)

## Directives

## Unified storage grammar

Three rules cover all four protocols (`brix_root`, `brix_webdav`, `brix_s3`, `brix_cvmfs`):

- **`brix_<proto> on;`** — per-location enable. One directive activates the protocol handler.
  Only one protocol may be enabled per location or per port.
- **Unified storage directives** — registered once by `ngx_http_brix_common_module` (HTTP
  plane) and by the stream module (stream plane); valid at `http|server|location` (or
  stream `main|server`); merged main→srv→loc so a `server{}` block can configure storage
  once and every brix location inherits it: `brix_export`, `brix_storage_backend`,
  `brix_cache_store`, `brix_cache_root`, `brix_cache_verify`, `brix_cache_max_object`,
  `brix_cache_evict_at`, `brix_cache_evict_to`, `brix_cache_index_cache`, `brix_cache_meta`,
  `brix_cache_slice_size`, `brix_cache_prefetch`, `brix_cache_prefetch_window`,
  `brix_cache_only_if_cached`, `brix_cache_uvkeep`, `brix_cache_max_bytes`,
  `brix_stage`, `brix_stage_store`, `brix_stage_flush`, `brix_thread_pool`.
- **Bare `brix_*` cross-protocol directives** — one spelling that works identically on
  every plane (registered once by the common owner and adopted into each protocol conf).
  Storage/lifecycle: `brix_allow_write`, `brix_read_only`,
  `brix_read_only_public` (stream only), `brix_compress`, `brix_ktls`,
  `brix_metrics`, `brix_health`, `brix_credential`, `brix_upload_resume`, `brix_stage_dir`,
  `brix_zip_access`, `brix_pblock_block_size`. Authorization / trust (phase-101 W4):
  `brix_require_vo`, `brix_protbind`, `brix_pwd_file`, `brix_macaroon_secret`,
  `brix_token_jwks`, `brix_token_issuer`, `brix_token_audience`, `brix_token_clock_skew`,
  `brix_token_config`, `brix_trusted_ca`, `brix_trusted_ca_dir`, `brix_crl`, `brix_crl_mode`,
  `brix_signing_policy`, `brix_vomsdir`, `brix_voms_cert_dir`. HTTP-TPC SSRF policy:
  `brix_tpc_allow_local`, `brix_tpc_allow_private`, `brix_tpc_source_guard`,
  `brix_tpc_source_allow`, `brix_tpc_require_source_size`, `brix_tpc_verify_checksum`.
  Per-request identity (phase-101 W6): the `brix_idmap*` family.

The only remaining per-protocol directive families are behavior specific to one protocol
(`brix_cvmfs_*`, `brix_scvmfs_*`, `brix_s3_*` auth, `brix_webdav_*` TPC-transport/CORS, …).

> **Renamed a prefixed directive?** Every phase-101 old→new spelling (the de-prefixings
> above plus the W6 role renames — `brix_ocsp`, `brix_dashboard_scan_*`, `brix_idmap*`,
> the CA/trust quartet) is listed in
> [migration-unified-grammar.md](migration-unified-grammar.md). Old names are hard-removed:
> nginx reports a stock `unknown directive`, never a silent alias.

---

### `brix_root on|off`

**Required (stream).** Enables the XRootD (`root://`) protocol handler for this server block.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;       # ← this activates the module
        brix_export /data;
    }
}
```

Without `brix_root on`, nginx ignores all other `brix_*` directives in the block.

---

### `brix_export <path>`

**Default:** `/`

The filesystem directory that clients see as their root (`/`). Every path a client requests is resolved relative to this directory. Paths that try to escape using `..` or symlinks are rejected.

```nginx
brix_export /data/store;   # clients see /data/store as "/"
```

A client requesting `/mc/sample.root` gets `/data/store/mc/sample.root` on disk.

---

### `brix_allow_write on|off`

**Default:** `off`

Whether clients may write, delete, rename, or create directories. Off by default so read-only servers are safe without any extra configuration.

Write operations that require this flag: `kXR_pgwrite`, `kXR_write`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`. A write request to a server where this is `off` returns `kXR_fsReadOnly`.

```nginx
brix_allow_write on;   # allow uploads and deletes
```

---

### `brix_read_only on|off`

**Default:** `off`

Forces the server read-only. Unlike leaving `brix_allow_write` off, this is
applied at **config-merge time** by `brix_shared_apply_read_only()`: it sets
`allow_write` off *before* any token scope is consulted, so a write scope in a
WLCG token, a `brix_allow_write on` later in the same block, or a directive
inherited from an enclosing scope cannot re-open the surface. The override is
announced in the error log at startup rather than applied silently.

Mutually exclusive with [`brix_manager_mode`](#brix_manager_mode-onoff): a
manager redirects path mutations to a data node *before* the local write gate
runs, so the pair would not produce a read-only endpoint. `nginx -t` refuses it
at `[emerg]`.

```nginx
brix_read_only on;     # nothing on this listener can be mutated
```

See [Read-Only Public `root://` Gateway](read-only-root-gateway.md) for the
opcode-by-opcode evidence.

---

### `brix_read_only_public on|off`

**Default:** `off` · **stream (`root://`) plane only**

The public-gateway posture. **Implies `brix_read_only`** — the finaliser turns
it on, so every write gate keyed on `allow_write` covers a public gateway
without knowing this directive exists — and *additionally* refuses the
`kXR_query` infotypes that describe the **server** rather than a path the client
may already read:

| Refused (`kXR_NotAuthorized`) | Still answered |
|---|---|
| `kXR_QStats` (1), `kXR_Qspace` (5), `kXR_Qvisa` (8), `kXR_QFSinfo` (10) | `kXR_QPrep` (2), `kXR_Qcksum` (3), `kXR_Qxattr` (4), `kXR_Qckscan` (6), `kXR_QFinfo` (9) |

Listing, stat, open, read and streaming are untouched, so an anonymous client
can still browse and stream data.

`kXR_Qconfig` (7) is **filtered per key** rather than refused: the protocol's own
capability list and limits (`chksum`, `readv`, `readv_ior_max`, `readv_iov_max`,
`pio_max`, `bind_max`, `fattr`, `tpc`, `tpcdlg`, `cmpread`, `cmpwrite`,
`xrdfs.ext`, `brix.substreams`) still answer, so `xrdcp` capability negotiation
and vector-read tuning work exactly as on a plain `brix_read_only` gateway. The
keys that describe the **deployment** — `version` and `role` — are withheld and
echoed like an unknown key. The `public_safe` column in the descriptor table
defaults to withheld, so a key added later fails closed. See
[§6.3 of the gateway page](read-only-root-gateway.md#63-kxr_qconfig-deployment-identity-withheld-protocol-capability-kept).

```nginx
brix_read_only_public on;   # read-only AND non-disclosing
```

---

### `brix_upload_resume on|off`

**Default:** `on`

Controls upload staging. When on, a fresh write open (`kXR_new`/overwrite) is
**not** written to its final path — the server streams the bytes to a
deterministic, identity-keyed **staging partial file** and **atomically renames
it onto the destination on a clean `kXR_close`**. Readers never observe a
half-written file, and a client that disconnects mid-transfer can reconnect and
**resume in place** (the partial is preserved, not discarded). With it `off`,
fresh uploads are still staged when the client sets POSC (`kXR_posc`) but are not
resumable. A pure in-place update (`kXR_open_updt` with no create) always writes
directly, never through a staging file.

```nginx
brix_upload_resume on;   # stage + atomically move uploads into place (default)
```

---

### `brix_stage_dir <path>`

**Default:** unset (stage alongside the destination file)

Directory for upload staging partials. By default the staging file is created in
the **same directory** as the destination, so the commit `rename(2)` is atomic on
the same filesystem. Point this at a dedicated fast device (e.g. NVMe) to absorb
in-flight uploads there; when the stage dir is on a *different* filesystem than
the storage, the commit transparently falls back to copy-then-rename (still
atomic at the destination). Must resolve within a path the worker can write.

```nginx
brix_stage_dir /srv/fast/upload-staging;
```

---

### `brix_posc_persist <auto|manual|off> [hold <time>]`

**Default:** `auto` (no grace period)

The XRootD `ofs.persist` analog. A hard crash (SIGKILL, power loss) during a
non-staged write leaves a `<final>.xrd-tmp.<pid>.<rand>` temp orphaned in the
export tree. At worker startup BriX reaps such orphans whose owner process is
**dead**, while keeping any whose owner is still **alive** (an in-flight write of
a draining worker during a reload). This directive governs that recovery:

- **`auto`** — reap dead-owner orphans (the historical, default behaviour).
- **`manual`** / **`off`** — **keep** orphans in place for an operator to inspect
  or recover manually. (BriX POSC is temp+fsync+rename with no separate tracked
  POSC-state database, so `manual` and `off` both mean "do not auto-reap".)
- **`hold <time>`** — a grace period. Under `auto`, an orphan is reaped only once
  it has been idle at least `<time>` (measured from its mtime), so a temp whose
  writer is about to reconnect and resume is not removed out from under it. A
  temp with a future mtime (clock skew) is treated as fresh and kept.

The reaper runs once at worker-0 startup, so the policy is **node-global**: the
last `brix_posc_persist` in the configuration wins, and a server block without
the directive never overrides one that has it. Changing a running node's policy
requires an explicit directive — a reload that *removes* it keeps the last
explicit value until the next full restart (the fail-safe direction: orphans are
kept, never wrongly deleted).

```nginx
brix_posc_persist manual;              # keep crash orphans for manual recovery
brix_posc_persist auto hold 1h;        # reap, but spare orphans younger than 1h
```

---

### `brix_auth none|gsi|token|both`

**Default:** `none`

Authentication mode:

- `none` — accept any username, no credentials required
- `gsi` — require a valid x509 proxy certificate (see [Authentication](../06-authentication/auth-overview.md))
- `token` — require a valid WLCG/JWT bearer token using the `ztn` security protocol
- `both` — accept either GSI or bearer-token credentials on the same listener

```nginx
brix_auth gsi;
```

---

### `brix_authdb <path>` — native u/g/p authorization

**Context:** stream `server{}` (`brix_root`) · HTTP `location` (`brix_webdav`)

Path to a native `u/g/p/a` authorization-rule file (per-DN/VO/host-CIDR ACLs,
6 privilege bits, longest-prefix match). On the stream (`root://`) plane this is
the engine entry; the runtime engine is chosen by `brix_authdb_engine`
(`native` default / `xrdacc`). On the **HTTP** plane bare `brix_authdb` is the
**native** engine, enforced by the WebDAV access phase for READ methods — reach
the XrdAcc engine on HTTP via `brix_acc_authdb` instead (phase-101 W5). See
[XrdAcc authorization](../06-authentication/authorization-xrdacc.md) and the
[migration guide](migration-unified-grammar.md#phase-101-authdb-engine-split-2026-08--w5).

```nginx
# stream: engine chosen by brix_authdb_engine
brix_authdb        /etc/brix/authdb;
brix_authdb_engine xrdacc;           # stream-only tuner spelling

# HTTP (WebDAV): bare name = native u/g/p engine
location /dav/ { brix_webdav on; brix_authdb /etc/brix/authdb; }
```

---

### `brix_acc_authdb <path>` — XrdAcc engine (HTTP)

**Context:** HTTP `location`/`server{}`/`http{}` (all brix HTTP protocols)

The XrdAcc-engine entry point on the HTTP planes (WebDAV/S3/cvmfs), with tuners
`brix_acc_format` (`native|xrdacc`), `brix_acc_audit`
(`none|deny|grant|all`), `brix_acc_refresh <secs>`, and the OS/host resolution
family (`brix_acc_gidlifetime`, `brix_acc_pgo`, `brix_acc_resolve_hosts`, …).
On the stream reference plane the equivalents keep the `brix_authdb_*` spellings
(phase-101 W5: prefix names the engine on HTTP).

```nginx
location /s3/ { brix_s3 on; brix_s3_bucket b;
    brix_acc_authdb /etc/brix/authdb;
    brix_acc_format xrdacc;
    brix_acc_audit  all;
    brix_acc_refresh 60;
}
```

---

### `brix_gsi_verify_depth <n>`

**Default:** `0` (unlimited)

Cap the maximum X.509 chain depth accepted when verifying a client's GSI
proxy/certificate at `root://` login — the `xrd.tlsca verdepth` analog. `<n>` is
passed to `X509_STORE_CTX_set_depth`, so a client presenting a chain with more
than `<n>` intermediate CAs is rejected. `0` (the default) imposes no limit from
BriX's side (OpenSSL's built-in ceiling still applies), byte-identical to a
server without the directive. Use it to bound absurdly deep proxy/intermediate
chains on a GSI listener.

```nginx
brix_gsi_verify_depth 4;
```

---

### `brix_protbind <host-template> [none | [only] <protocol>...]`

**Default:** none (every peer gets the `brix_auth` set)
**Context:** `stream { server { … } }`

Per-host authentication policy — the BriX equivalent of XRootD's
`sec.protbind`. Each occurrence appends one rule; at connection time the
**first** rule whose template matches the peer wins, so specific templates must
come before the `*` catch-all. Protocol names are `gsi`, `ztn` (alias `token`),
`sss`, `unix`, `krb5`, `host` and `pwd`.

- `<protocol>...` — offer these protocols first, then the remaining protocols of
  the `brix_auth` base set
- `only <protocol>...` — offer exactly these and nothing else
- `none` — this peer authenticates anonymously

Host templates follow XRootD's `XrdOucNList` rules: at most one `*`, matched
case-insensitively against the peer's reverse-DNS name, falling back to its IP
literal. Reverse DNS is only performed when at least one rule has a non-`*`
template, and the result is cached for the life of the connection.

The resolved set drives all three stages consistently: the `kXR_protocol`
capability reply, the `&P=…` blocks of the `kXR_login` security token (emitted
in the rule's order — an arbitrary ordered multi-protocol token, not just the
`both` composition), and the `kXR_auth` credential-type gate, which re-checks
membership because a client may offer any credtype regardless of what was
advertised.

Naming a protocol in a rule pulls the listener into that protocol's startup
configuration, so its prerequisites (`brix_certificate`, `brix_token_jwks`,
`brix_sss_keytab`, …) are validated at config time rather than failing the
first handshake.

```nginx
brix_protbind mon.example.org none;          # monitoring probes: anonymous
brix_protbind *.farm.local only unix;        # on-site: unix only
brix_protbind * gsi ztn;                     # everyone else: GSI, then tokens
```

See [`brix_webdav_protbind`](#brix_webdav_protbind-host-template-none--only-protocol)
for the HTTP/WebDAV face of the same policy.

---

### `brix_tls on|off`

**Default:** `off`

Enables XRootD's in-protocol TLS upgrade on a normal `root://` listener. When a
client advertises `kXR_ableTLS`, the server replies with `kXR_haveTLS` and
upgrades the same TCP connection to TLS before `kXR_login` / `kXR_auth`
continue.

Requires `brix_certificate` and `brix_certificate_key`.

Use this on a plain `listen 1094;` style listener. Do not combine it with
`listen ... ssl` on the same stream server; that `roots://` mode is already
encrypted from the first byte. Full details: [tls.md](tls-config.md).

```nginx
server {
    listen 1095;
    brix_root on;
    brix_export /data;
    brix_auth gsi;
    brix_certificate     /etc/grid-security/hostcert.pem;
    brix_certificate_key /etc/grid-security/hostkey.pem;
    brix_trusted_ca      /etc/grid-security/certificates/ca.pem;
    brix_tls on;
}
```

---

### `brix_tls_ciphers <list>`

**Default:** empty (OpenSSL defaults)

Pin the OpenSSL cipher list on the `root://` in-protocol TLS context — the
`xrd.tlsciphers` analog, with the same scope and semantics as nginx's own
`ssl_ciphers` directive (`SSL_CTX_set_cipher_list`, governing TLSv1.2 and below;
TLSv1.3 cipher suites stay OpenSSL's defaults). Empty (the default) leaves the
OpenSSL defaults untouched.

A list that matches **no** ciphers this build can offer is a hard configuration
error (`nginx -t` fails) rather than a silent fallback to the OpenSSL defaults —
so a typo can never leave the listener quietly more permissive than intended.

```nginx
brix_tls on;
brix_tls_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
```

Governs only the TLSv1.2-and-below cipher list. To restrict the **TLSv1.3**
suites — which is where a modern connection actually negotiates — use
`brix_tls_ciphersuites`.

---

### `brix_tls_ciphersuites <list>`

**Default:** empty (OpenSSL defaults)

Pin the **TLSv1.3** cipher-suite list on the `root://` in-protocol TLS context
(`SSL_CTX_set_ciphersuites`) — the companion to `brix_tls_ciphers`, which governs
only TLSv1.2 and below. Because TLSv1.3 is the default protocol on any modern
client/OpenSSL, this is the knob that actually restricts a present-day
connection's ciphers. Suite names use the TLSv1.3 spelling
(`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, …). Empty (the
default) leaves OpenSSL's defaults untouched.

As with `brix_tls_ciphers`, a list matching **no** suites this build can offer is
a hard configuration error (`nginx -t` fails), never a silent fallback.

```nginx
brix_tls on;
brix_tls_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

---

### `brix_tls_reuse on|off`

**Default:** `on`

Controls TLS session resumption on the `root://` in-protocol TLS context — the
`xrootd.tlsreuse` analog. `on` (the default) leaves the OpenSSL/nginx behaviour
untouched. `off` disables **both** the server session cache and TLS session
tickets, so every connection performs a full handshake — use it where
per-connection forward secrecy matters and no resumption state should be
retained (or replayable). Governs only the root:// TLS context; the HTTP side is
controlled by nginx's own `ssl_session_cache` / `ssl_session_tickets`.

```nginx
brix_tls on;
brix_tls_reuse off;
```

---

### `brix_tls_require none|[all|login|session|data|tpc|-<cap>]...`

**Default:** `none`

Per-capability TLS gating (the stock `xrootd.tls` policy). Each named
capability must arrive over a TLS-encrypted connection; a cleartext request
that exercises a required capability is refused with `kXR_TLSRequired`
(`root://`) or `403` (WebDAV / S3):

- `login` — `kXR_login` / `kXR_auth` themselves
- `session` — every post-login operation (locks the whole session, like stock)
- `data` — data-plane transfers (read/readv/pgread/write/writev/pgwrite;
  HTTP GET/PUT bodies)
- `tpc` — third-party-copy opens (native `tpc.*` opens and WebDAV `COPY`)
- `all` — all four; `-<cap>` subtracts one (e.g. `all -tpc`); `none` (alone)
  disables gating

Tokens fold left-to-right. The enforced mask is advertised to `root://`
clients as `kXR_tlsLogin`/`kXR_tlsSess`/`kXR_tlsData`/`kXR_tlsTPC` bits in
the `kXR_protocol` reply, so conformant clients upgrade pre-emptively instead
of eating a refusal. Available on the stream server and every HTTP plane
(WebDAV, S3). Finer-grained than the `brix_min_sec_level` session floor: a
`data`-only mask leaves cleartext metadata (stat/dirlist) untouched.

```nginx
brix_tls_require session data;   # cleartext may login; nothing else
```

---

### `brix_signing_required on|off`

**Default:** `off`

Makes `brix_security_level` **fail-closed** on a session that cannot sign
requests at all.

`brix_security_level` (`none|compatible|standard|intense|pedantic`) says which
opcodes must arrive wrapped in a `kXR_sigver` envelope. Producing that
signature needs a session key, and **only GSI establishes one** — an `sss`,
`ztn`, `krb5`, `unix`, `host` or anonymous session has no key material to sign
with. Historically such a session skipped the level check entirely and was
served unsigned, silently: an operator who set `brix_security_level intense`
on a token listener got *no* tamper protection and nothing in the log said so.

That gap is now always **visible** and optionally **closed**:

- **off** (default) — the request is still served unsigned, but the session
  logs one `WARN` naming the configured level and stating that requests are
  being `accepted UNSIGNED`. One line per session, not per request.
- **on** — the request is refused with `kXR_NotAuthorized`
  (`"request signing required but this session cannot sign"`), so the
  directive means what it reads like it means.

Off by default because turning it on rejects **every** client whose auth
protocol does not sign — including stock clients using `sss`/`ztn`/`krb5` —
which is a deployment decision, not a safe default. Turn it on when the
listener is GSI-only and you want the signing level to be load-bearing.

Session state-machine opcodes (`login`, `protocol`, `auth`, `endsess`, `ping`,
`sigver`, `bind`) stay exempt at every level, exactly as they do for a
signing-capable session — so this can never lock out the handshake itself.

> **Note:** this closes the *silent-bypass* half of the gap. Actually deriving
> a signing key for `sss`/`krb5` (both carry key material, and stock signs
> `sss`) is a wire change requiring matched client and server derivation, and
> is tracked separately in the parity audit §5.2.

```nginx
brix_auth             gsi;
brix_security_level   intense;
brix_signing_required on;      # unsignable sessions are refused, not waved through
```

---

### `brix_ztn_cleartext on|off`

**Default:** `off`

Stock XRootD refuses `ztn` (bearer-token) authentication over a cleartext
connection: a bearer token is replayable by any on-path observer. BriX
matches that default — a cleartext `kXR_login` on a token listener drops the
`ztn` offer (refusing the login outright when no other protocol remains), and
a cleartext `kXR_auth` with a `ztn` credential is refused with
`kXR_TLSRequired`. `brix_ztn_cleartext on` opts a listener back into
cleartext ztn for lab and test rigs that drive the raw wire without TLS.
Never enable it on a production listener.

```nginx
brix_ztn_cleartext on;   # lab only: raw cleartext ztn drivers
```

---

### `brix_certificate <path>`

Path to the server's PEM certificate file. Required when `brix_auth gsi` or `brix_auth both`.

```nginx
brix_certificate /etc/grid-security/hostcert.pem;
```

---

### `brix_certificate_key <path>`

Path to the server's PEM private key file. Required when `brix_auth gsi` or `brix_auth both`.

```nginx
brix_certificate_key /etc/grid-security/hostkey.pem;
```

---

### `brix_trusted_ca <path>`

Path to a PEM file containing the CA certificate (or bundle of CA certificates) that the server trusts for verifying client proxy certificates. Required when `brix_auth gsi` or `brix_auth both`.

See [pki.md](../06-authentication/pki-config.md) for CA bundle layout and hash symlink setup.

```nginx
brix_trusted_ca /etc/grid-security/certificates/ca.pem;
```

---

### `brix_crl <path>`

Path to a PEM CRL file or a directory containing CRLs. Directory mode scans `*.pem` and grid-style `*.r0` through `*.r9` files. When configured, GSI verification enables OpenSSL CRL checks for the full certificate chain.

See [pki.md](../06-authentication/pki-config.md) for CRL distribution point conventions and hash symlinks.

```nginx
brix_crl /etc/grid-security/certificates;
```

---

### `brix_crl_reload <seconds>`

**Default:** `0` (disabled)

How often each worker reloads `brix_crl` and rebuilds its GSI trust store. A failed reload keeps the previous store in place.

```nginx
brix_crl_reload 300;  # reload CRLs every five minutes
```

---

### `brix_token_jwks <path>`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation. Used when `brix_auth token` or `brix_auth both` is configured.

```nginx
brix_token_jwks /etc/tokens/jwks.json;
```

---

### `brix_token_issuer <string>`

Expected JWT `iss` claim. Tokens from other issuers are rejected.

```nginx
brix_token_issuer "https://idp.example.com";
```

---

### `brix_token_audience <string>`

Expected JWT `aud` claim. Tokens for other services are rejected.

```nginx
brix_token_audience "my-storage";
```

---

### `brix_access_log <path>|off`

**Context:** stream `server`, HTTP `main`/`server`/`location`

**Default:** `off`

File path for the brix access log. Stream root:// locations write the legacy
per-operation access lines here. HTTP WebDAV/S3/CVMFS locations use the same
file handle for correlated `SESS` lifecycle audit lines when
`brix_session_log` is enabled. See [Metrics & logging](../08-metrics-monitoring/monitoring-guide.md) for the log format and examples.

```nginx
brix_access_log /var/log/nginx/brix_access.log;
```

The file is opened `O_APPEND` so it is safe to share across multiple nginx worker processes. Rotate with `kill -USR1 $(cat /run/nginx.pid)`.

---

### `brix_session_log on|off`

**Context:** stream `server`, HTTP `main`/`server`/`location`

**Default:** `on`

Controls correlated `SESS` lifecycle audit lines. When enabled, sessions write
CONNECT/AUTH/ATTEMPT/RESULT/XFER/END records into the existing
`brix_access_log` stream with a per-session ID.

```nginx
brix_session_log on;
```

Disable this only when the extra lifecycle lines are not wanted; the regular
per-operation access log is controlled separately by `brix_access_log`.

---

### `brix_dashboard on|off`

**Context:** HTTP `location`

**Default:** `off`

Enables the HTTPS monitoring dashboard on the HTTP `/brix/` location. The
dashboard serves an embedded browser page and a JSON snapshot endpoint. Use it
for live operator checks; keep Prometheus scraping `/metrics` for long-term
metrics storage.

```nginx
server {
    listen 8443 ssl;

    location /brix/ {
        brix_dashboard on;
        brix_dashboard_password "change-me";
    }
}
```

The page is available at `/brix/`, the login form at `/brix/login`, and the
compatibility JSON endpoint at `/brix/transfers`. Versioned JSON is available
under `/brix/api/v1/`, including `/snapshot`, `/transfers`, `/events`,
`/history`, `/cache`, and `/cluster`. Serve this location only over TLS and
restrict it to an admin network because it exposes active file paths, client
addresses, and authenticated identities. See
[Metrics & logging](../08-metrics-monitoring/monitoring-guide.md#https-monitoring-dashboard)
for the full dashboard setup.

---

### `brix_dashboard_password <string>`

**Context:** HTTP `location`

**Default:** unset

Password required by the HTTPS monitoring dashboard login form.

```nginx
brix_dashboard_password "change-me";
```

Always set this directive in production. If it is omitted, the dashboard
location is treated as unauthenticated. The session cookie is marked `Secure`,
`HttpOnly`, and `SameSite=Strict`.

---

### `brix_dashboard_session_ttl <time>`

**Context:** HTTP `location`

**Default:** `8h`

Controls the signed dashboard session cookie lifetime. Values use nginx time
syntax.

```nginx
brix_dashboard_session_ttl 4h;
```

---

### `brix_dashboard_cookie_path <path>`

**Context:** HTTP `location`

**Default:** `/brix`

Sets the `Path` attribute on the dashboard session cookie. The value must be a
non-empty absolute path and cannot contain control characters or semicolons.

```nginx
brix_dashboard_cookie_path /brix;
```

---

### `brix_dashboard_idle_threshold <time>`

**Context:** HTTP `location`

**Default:** `5s`

Marks an active dashboard row as `idle` when no bytes have moved for this
duration.

```nginx
brix_dashboard_idle_threshold 5s;
```

---

### `brix_dashboard_stalled_threshold <time>`

**Context:** HTTP `location`

**Default:** `60s`

Marks an active dashboard row as `stalled` when no bytes have moved for this
duration. The value must be greater than or equal to
`brix_dashboard_idle_threshold`.

```nginx
brix_dashboard_stalled_threshold 60s;
```

---

### `brix_dashboard_cluster_stale_after <time>`

**Context:** HTTP `location`

**Default:** `90s`

Marks manager registry entries as stale in `/brix/api/v1/cluster` and the
dashboard cluster panel when their heartbeat age exceeds this duration.

```nginx
brix_dashboard_cluster_stale_after 90s;
```

---

### `brix_dashboard_users <path>`

**Context:** HTTP `location`

**Default:** unset

Loads an htpasswd-like users file for named dashboard operators. Each readable,
non-comment line has the form `username:password-hash`; system `crypt(3)` hashes
are accepted, and plaintext entries are supported for development fixtures. This
directive cannot be used together with `brix_dashboard_password`.

```nginx
brix_dashboard_users /etc/nginx/brix-dashboard.htpasswd;
```

The file is read during nginx config validation/startup. Dashboard audit events
record login success and failure by username, but never record passwords or
cookie values.

---

### `brix_thread_pool <name>`

**Default:** `default`

Name of the nginx thread pool used for async file I/O (reads and writes). Must match a `thread_pool` directive at the main config level (outside `stream {}`).

If the named pool does not exist, the module falls back to synchronous I/O and logs a notice. Synchronous I/O means a slow read blocks all other connections on the same worker process — fine for development, not for production. Read-through cache mode is stricter: `brix_cache on` requires a working thread pool because cache fills perform network and disk I/O.

```nginx
# At the top of nginx.conf, outside stream {}
thread_pool brix_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;
        brix_thread_pool brix_io;
    }
}
```

How many threads to use: a good starting point is one thread per disk spindle, or 4–8 for NVMe/SSD. The `max_queue` value caps how many pending I/O tasks can queue up before new requests start returning errors.

---

### `brix_ckscan_depth <n>`

**Default:** `32`

Maximum directory recursion depth for a single `kXR_Qckscan` request. Entries
below this depth are skipped without failing the scan.

```nginx
brix_ckscan_depth 32;
```

---

### `brix_ckscan_max_files <n>`

**Default:** `100000`

Maximum number of regular files returned by a single `kXR_Qckscan` request.
Additional files are skipped once the limit is reached.

```nginx
brix_ckscan_max_files 100000;
```

---

### `brix_oss_maxsize <size>`

**Default:** `0` (no cap)

The `oss.maxsize` create-size cap: refuse a root:// data write whose **end**
offset (offset + length) would push the file past this. Enforced across the
whole native write plane (`kXR_write` / `kXR_pgwrite` / `kXR_writev`), so a
client that omits or understates its `oss.asize` hint is still stopped at the
byte that would cross the limit; a refused write commits nothing. `0` keeps the
historical behaviour (no cap).

```nginx
brix_oss_maxsize 10g;
```

---

### `brix_oss_cgroup <name>`

**Default:** `default`

The space-group name the `kXR_Qspace` report advertises as `oss.cgroup` — the
label accounting tools key on. A single-partition site can name its group here;
the value is emitted verbatim into the `&`-joined `oss.*` report, so the name
may not contain a CGI-structural byte (`&`, `=`, space, or a control char) — a
name that does is refused at config parse. Multi-partition `oss.space` groups
and create-time CGI selection are not implemented.

```nginx
brix_oss_cgroup atlas-datadisk;
```

---

### `brix_oss_quota <size>`

**Default:** `-1` (unlimited)

The space quota the `kXR_Qspace` report advertises as `oss.quota` — the number
`xrdfs query space` and accounting tools display. A site migrating from a stock
`xrootd` server can restore its configured quota here so those tools see the same
value; unset, the report keeps the stock `-1` (unlimited). Accepts the usual size
suffixes (`k`/`m`/`g`); a malformed or negative value is refused at config parse.

This is **advertisement only** — BriX does not itself enforce the quota (there is
no write-time rejection when usage crosses it). Real per-space quota enforcement
is part of the larger multi-partition `oss.space` groups feature, not yet
implemented.

```nginx
brix_oss_quota 500g;
```

### `brix_oss_quota_enforce on|off`

**Default:** `off`

Makes `brix_oss_quota` load-bearing: a `kXR_write`/`writev`/`pgwrite` whose
length would push the export's usage past the quota is refused `kXR_overQuota`.
Usage comes from the same probe the `kXR_Qspace` report advertises — a backend
with a space slot (e.g. `pblock` with `?quota=`) answers from its catalog;
plain POSIX falls back to `statvfs` of the export's filesystem, which is
**conservative on a shared mount** (other tenants' usage counts against the
quota) and exact on a dedicated volume. The probe is cached for 5 seconds per
worker, so enforcement lags a fresh write by at most that much; a probe failure
never blocks writes. Off (the default), the quota stays advertisement-only.

```nginx
brix_oss_quota 500g;
brix_oss_quota_enforce on;
```

---

### `brix_sitename <name>`

**Default:** unset

The human-readable site/node identity for this server — the `all.sitename`
analog. A client reads it via `xrdfs query config sitename` (kXR_Qconfig), and it also
fills the `site="…"` attribute of the kXR_QStats `<statistics>` summary-
monitoring document that federation dashboards read. When unset, the Qconfig
`sitename` query echoes the key (stock's default-config behaviour) and the QStats
`site` attribute is empty, so leaving it out changes nothing.

```nginx
brix_sitename WLCG-Cache-AMS-01;
```

---

### `brix_checksum_default <algo>`

**Default:** `adler32`

The checksum algorithm used when a `kXR_Qcksum` request selects none of its own
(no `<algo>:` prefix and no `?cks.type=<algo>` opaque), and the algorithm
advertised **first** in the `xrdfs query config chksum` list — the entry clients
take as this server's preference when intersecting checksum preference lists.
The `xrootd.chksum` default analog: WLCG sites typically prefer `crc32c`, cloud
deployments `sha256`. Must be one of
`adler32`/`crc32`/`crc32c`/`crc64`/`crc64nvme`/`md5`/`sha1`/`sha256`; an
unrecognized value degrades to `adler32` at use rather than failing checksums. An
explicit per-request algorithm always overrides it.

```nginx
brix_checksum_default crc32c;
```

---

### `brix_admin_socket <path>`

**Default:** unset (no admin socket)

Opens a runtime admin unix socket (the `XrdXrootdAdmin` analog) for inspecting
and controlling live sessions without restarting the server. The socket speaks a
line-based text protocol (a documented divergence — stock's admin wire grammar is
unpublished):

| command | effect |
|---|---|
| `list` | `ok <n>` then one `<sessid-hex> <peer\|-> <dn\|->` line per connection on the worker |
| `disc <sessid-hex>` | disconnect that session gracefully (FIN — the client sees EOF) |
| `msg <sessid-hex> <text>` | deliver `<text>` to that client as an unsolicited `kXR_attn`/asyncms |
| `pause <sessid-hex> [<secs>]` | stop reading that session's requests (they back up via TCP backpressure; in-flight replies still drain); with `<secs>`, auto-resume after that many seconds |
| `cont <sessid-hex>` | resume a paused session and serve whatever backed up |
| `abort <sessid-hex>` | disconnect without ceremony (RST — the client sees `ECONNRESET`) |

Replies are `ok[ <detail>]` or `err <reason>`. The socket files are created mode
`0600` — **filesystem permission on the path is the entire privilege boundary**
(exactly like stock's `adminpath`), so place them in a root/operator-owned
directory. **Every worker serves its own socket**: worker 0 at the configured
`<path>`, worker *n* at `<path>.<n>` — each lists and controls exactly the
sessions its worker owns (a session lives on one worker), so an admin tool
sweeps the socket set; a targeted verb on the wrong worker's socket answers
`err unknown-or-not-local`. With `worker_processes 1` there is just the one
socket. Sessions are listed from connection setup (including mid-login),
matching the stock admin view. Note `pause` does not suspend any armed
read/idle deadlines — a session paused longer than `brix_read_timeout` (when
configured) is still reaped by it.

```nginx
brix_admin_socket /run/brix/admin.sock;
```

---

### `brix_webdav_html_listing on|off`

**Default:** `off`

Render an HTML directory index when a WebDAV `GET` targets a directory (the
XrdHttp *Listing* analog). Off — the stock *listingdeny* posture — returns
`403`. On enumerates the directory through the same impersonation-aware VFS
readdir seam PROPFIND uses (dotfiles and internal sidecars hidden, every name
HTML-escaped) and serves a `text/html` index of name / size / mtime.

```nginx
brix_webdav_html_listing on;
```

---

### `brix_webdav_listing_redirect <url>`

**Default:** unset

The *listingredir* analog: a `GET` on a directory `301`-redirects to
`<url>` with the request path appended, instead of listing. Checked **before**
`brix_webdav_html_listing`, so it wins when both are set.

```nginx
brix_webdav_listing_redirect https://browse.example.org/;
```

---

### `brix_max_delay <time>`

**Default:** `0` (off — the built-in 10 s staging poll interval)

The XrdHttp `http.maxdelay` analog. When a `GET` hits an object that is not yet
online — a nearline (tape) recall is in flight — BriX answers `202` "staging"
with a `Retry-After` telling the client how long to wait before polling again.
That interval is 10 seconds by default; this directive **caps** it, so a
deployment can tighten the recall poll cadence.

It only ever tightens: a value **≥ 10 s is a no-op** (the server never tells a
client to wait *longer* than it already intends), and `0` keeps the 10 s default.
Set it below 10 s when a fast-staging backend or an impatient client fleet wants
snappier polling.

```nginx
brix_max_delay 3s;   # poll every 3 s during a tape recall, not every 10 s
```

---

### `brix_ztn_maxsz <size>`

**Default:** `0` (no extra cap)

The ztn `-maxsz` analog: refuse a bearer credential longer than this **before**
any parse/JWKS/crypto work — an unauthenticated peer must not get to choose how
much validation CPU a single `kXR_auth` burns. `0` keeps the historical
behaviour (only the auth frame limit applies).

```nginx
brix_ztn_maxsz 64k;
```

---

### `brix_max_delay <time>`

**Default:** `60s` (stock `ofs.maxdelay`)

Clamp on the seconds any `kXR_wait` may tell a client to stall — staging
recalls, CMS SUPCount floor holds, memory backpressure. Enforced at the single
emission choke point (`brix_send_wait`), so every wait the server can produce
is covered. `0` disables the clamp (an explicitly configured long hold is
answered in full).

```nginx
brix_max_delay 60s;
```

---

### `brix_fsoverload_stall <time>`

**Default:** `1s`

The seconds a read or `readv` deferred by `brix_memory_budget` tells the client
to back off before retrying — the `xrootd.fsoverload` *stall* analog. `1s` is
the historical hardcoded value, so an unconfigured server is unchanged; raise
it to shed load harder under memory pressure. Still clamped by
`brix_max_delay` at the emission choke point.

```nginx
brix_fsoverload_stall 5s;
```

---

### `brix_fsoverload_redirect <host> <port>`

**Default:** unset (off — a memory overload *stalls* per `brix_fsoverload_stall`)

The `xrootd.fsoverload` *redirect* action. When a read or `readv` is deferred by
`brix_memory_budget`, instead of telling the client to back off and retry **here**
(the stall), redirect it to another server — offloading the read to a sibling that
has headroom. Set it to the host and port of another cache/data server in the
mesh; leaving it unset keeps the stall behaviour.

Both overload responses share one choke point, so `brix_max_delay` still bounds
any stall this server does emit. The grammar is two tokens — `<host> <port>`,
**not** `host:port` — a deliberate BriX spelling.

The redirect is only handed to a client that advertised the `kXR_readrdok` login
ability (it can follow a redirect that arrives *during* a read). A client that
did not — an older client, or BriX's own client, whose async engine does not
chase read redirects — instead gets the `brix_fsoverload_stall` back-off even
when this directive is set, so it is never handed a redirect it would mishandle.
The read is simply deferred here until the budget frees.

```nginx
brix_memory_budget       512m;
brix_fsoverload_redirect  cache-b.example.org 1094;   # offload, don't stall
```

---

### `brix_metrics_slowop <usec>`

**Default:** `0` (disabled)

Arm the OssStats-style **slow-op classifier**: any I/O operation whose measured
latency meets or exceeds `<usec>` **microseconds** is booked into the
`brix_io_slowop_total{proto,op}` counter on `/metrics`, and the armed threshold
is exported as the `brix_io_slowop_threshold_usec` gauge. `0` (the default)
disables classification entirely — no counter movement, byte-identical to a
server without the directive.

The threshold is stamped into the metrics shared-memory zone once per config
load, so it applies process-wide to every protocol's latency-sampled ops (the
same completions the `brix_io_latency_usec` histogram bins). The unit is
microseconds — not a time token — so a fine threshold is expressible. Requires
the metrics zone (an enabled server block). Only ops that file a latency sample
(the AIO data-plane completions) are eligible, matching the histogram's scope.

```nginx
brix_metrics_slowop 500000;   # book ops slower than 500 ms
```

---

### `brix_chkpnt_maxsz <size>`

**Default:** `104857604` (the protocol minimum `kXR_ckpMinMax`)

Largest file `kXR_chkpoint` `ckpBegin` will snapshot — the `ofs.chkpnt maxsz`
analog. `ckpBegin` refuses larger files with `kXR_overQuota`, and `ckpQuery`
reports the cap as `maxCkpSize`. A value below the protocol minimum is raised
to it at merge: `kXR_ckpMinMax` is the "minimum maximum" every server must
accept, so honoring a lower cap would refuse checkpoints a spec-conforming
client is entitled to.

```nginx
brix_chkpnt_maxsz 200m;
```

---

### `brix_vomsdir <path>`

Path to the directory containing VOMS server information (`.lsc` files), one per VO. Required when `brix_require_vo` is used. Requires `libvomsapi.so.1` at runtime (install `voms-libs` on EL9 or `libvomsapi1` on Debian/Ubuntu).

```nginx
brix_vomsdir /etc/voms;
```

---

### `brix_voms_cert_dir <path>`

Path to the hashed CA certificate directory used for verifying VOMS attribute certificates. Required when `brix_require_vo` is used.

```nginx
brix_voms_cert_dir /etc/grid-security/certificates;
```

---

### `brix_require_vo <path> <vo>`

Restricts access to `<path>` (and all descendants) to clients whose VO list includes `<vo>`. For GSI, the VO list comes from VOMS proxy attributes. For token authentication, `wlcg.groups` claims are mapped into the same VO list. Can be specified multiple times for different paths.

`brix_auth gsi`, `brix_auth token`, or `brix_auth both` must be enabled, and `libvomsapi.so.1` must be available at runtime. The directive also requires `brix_vomsdir` and `brix_voms_cert_dir` because the same ACL machinery is used for GSI and token groups.

```nginx
brix_require_vo /atlas atlas;   # only ATLAS members can access /atlas
brix_require_vo /cms   cms;     # only CMS members can access /cms
```

If a GSI client has no VOMS extensions, or a token client has no matching `wlcg.groups`, the VO list is empty and access to protected paths is denied.

---

### `brix_inherit_parent_group <path>`

When a file or directory is created under `<path>`, nginx automatically adjusts its GID and group permission bits to match the parent directory. This mimics the Linux `setgid` bit at the application layer, which is useful when the backing filesystem (e.g. CephFS) does not reliably propagate `setgid` across mounts.

```nginx
brix_inherit_parent_group /cms;   # keep /cms/* group-owned by cms group
```

What happens on each create:
- **File**: GID set to parent GID; group read/write bits copied from parent; group execute preserved if already set.
- **Directory**: GID set to parent GID; group rwx bits copied from parent; `S_ISGID` added if the parent has it.
- **Recursive mkdir (`kXR_mkdirpath`)**: policy applied to each newly created directory level.

---

### `brix_manager_map /prefix host:port`

Map requests for a path prefix to an external manager/redirector endpoint. When a `locate` or `open` request matches a configured prefix the server replies with an XRootD `kXR_redirect` (status `4004`). The redirect body format is a 4-byte big-endian port followed by the host name bytes (ASCII). Lookups use longest-prefix matching; prefixes are normalized by the module before comparison.

The `host:port` value may be an IPv4 address or an IPv6 literal using bracket notation (for example: `[::1]:1234`). See [Manager Mode](../05-operations/manager-mode.md) for full semantics and examples.

```nginx
brix_manager_map /maps backend.example.org:54321;
```

---

### `brix_upstream host:port`

Configures an upstream XRootD redirector to forward requests to when no local `brix_manager_map` prefix matches. The module connects to the specified host:port, performs a minimal XRootD handshake, and relays the client request (currently `kXR_locate`, `kXR_open`, and `kXR_stat`). Upstream responses are forwarded verbatim:

- `kXR_redirect` — forwarded to the client as-is
- `kXR_wait` — timer is scheduled; the request is retried after the specified delay (capped at 60 s)
- `kXR_waitresp` — forwarded to the client; the upstream sends an unsolicited reply when ready
- `kXR_ok` / `kXR_error` — forwarded to the client

Used together with `brix_manager_map` to build a two-tier topology: static prefix rules handle known paths, and the catch-all upstream handles anything else.

```nginx
brix_upstream redirector.example.org:1094;
```

---

### `brix_cache on|off`

**Default:** `off`

Enables read-through cache mode for native `root://` opens. In this mode, read opens are served from `brix_cache_export`. If the requested file is missing, nginx fetches the whole file from `brix_cache_origin` into a temporary part file, atomically renames it into place, and then opens the cached copy for the client.

Cache mode is currently direct-mode and defaults to read-only:
- A working nginx thread pool is required.
- The origin fetch is anonymous; authenticated origin fetches are not implemented.
- The origin should be a data server. Redirect-following is not implemented for cache fills.
- By default files are cached as whole files. Set `brix_cache_slice` to enable fixed-size partial/range slice caching.
- Cache eviction is best-effort and runs during cache fills when filesystem occupancy is above `brix_cache_eviction_threshold`.
- **Write-through mode** (optional): When enabled via `brix_write_through on`, dirty write handles are mirrored to an origin data server on `kXR_sync` or `kXR_close`.

### `brix_cache_slice <size>|off`

**Default:** `off`

Enables fixed-size slice caching for cache reads when `brix_cache on` is also
enabled. A read that touches a missing slice schedules a bounded origin fetch for
that slice and asks the client to retry with `kXR_wait`; later reads can serve
ready slices without fetching the whole origin object. The size must be `off`/`0`
or a positive multiple of 1 MiB.

```nginx
brix_cache_slice 128m;
```

### `brix_cache_prefetch <n>` / `brix_cache_prefetch_window <size>`

**Default:** `0` (off) / `8m`

Background block prefetch for the **unified slice cache** (`brix_cache_store` +
`brix_cache_slice_size`, any protocol plane). When a client reads a slice-cached
object sequentially, the serving engine issues a WILLNEED hint through the
storage-driver `read_advise` slot and the cache decorator fills the *absent
successor blocks* on a worker thread — so the next blocks are already local when
the reader gets there, instead of costing one synchronous origin round-trip
each (XrdPfc `pfc.prefetch` parity).

- `brix_cache_prefetch <n>` — max in-flight background fill jobs per worker
  (`0`–`64`; `0` disables the feature entirely: hints are discarded and no
  speculative origin read ever happens).
- `brix_cache_prefetch_window <size>` — how far speculation may run ahead of
  the read cursor (`0` = unbounded to end of object, otherwise ≥ `64k`). The
  window is a *rolling runway*: each handle keeps a prefetch frontier, so a
  long sequential stream is continuously topped up to at most `window` bytes
  ahead of the reader — never burst-then-starve, never re-posted.

Sequential detection lives in the engines: the `root://` read path suppresses
the hint on random access (disable-on-random parity), and the HTTP
memory-backed serve loop only speculates for requests of at least 1 MiB, so
small metadata GETs never amplify origin traffic. Jobs authenticate to the
origin with the credential captured at open, need the `default` nginx thread
pool, and skip blocks the foreground filled meanwhile. Observability:
`brix_cache_prefetch_jobs_total`, `brix_cache_prefetch_blocks_total`,
`brix_cache_prefetch_failures_total` on `/metrics`.

```nginx
brix_cache_store       posix:/var/cache/brix;
brix_cache_slice_size  1m;
brix_cache_prefetch    4;
brix_cache_prefetch_window 16m;
```

### `brix_cache_only_if_cached on|off`

**Default:** `off`

Serve **only** what this cache already holds. A read whose object is not a
cache hit is refused with `kXR_NotFound` instead of being filled from the
origin (XrdPfc `pfc.onlyifcached` parity).

The point is topology, not policy hygiene: a node in this mode contributes the
copies it has and never becomes an origin puller, so a client that asks for
something it does not hold gets a clean "not here" and fails over to another
replica — rather than making this node fetch across the WAN on its behalf.
The refusal is deliberately `kXR_NotFound` and not a server error, because a
client retries a server error against the *same* node but moves on from a
not-found.

Placement of the gate matters and is fixed:

- **after** the cache-hit test — an object that IS cached still serves normally;
- **before** the admission filter and before the fill / nearline-recall paths —
  otherwise a path the admission policy declined would still reach the source,
  which is exactly the bypass this mode exists to prevent.

Writes are never gated; they pass through as usual. A *partial* (slice) hit
counts as a miss — upstream's `minsize` / `minfrac` partial-hit thresholds are
not implemented.

### `brix_cache_uvkeep <time>`

**Default:** `0` (off — a never-verified entry is trusted until its normal TTL)

Bound how long a cached entry whose contents were **never verified** against the
origin may be trusted (XrdPfc `pfc.uvkeep` parity). Some fills carry no origin
digest to check against — a TLS-trusted whole-file or slice fill, for example —
and are committed with the cinfo `F_VERIFIED` flag clear. With `uvkeep` set, such
an entry that is older than `<time>` (measured from when the fill published it) is
treated as a **miss** on the next open, so the cache revalidates it against the
source before serving.

The knob only ever **adds** revalidation:

- a **verified** entry (contents checked against the origin digest) is never aged
  out by `uvkeep`;
- an unverified entry still **inside** the window serves from cache as usual;
- an entry with no recorded fill time (legacy) is exempt.

So the fail-safe direction is "revalidate more", never "serve something staler".
BriX's revalidation is a full refill through the miss path — stronger than a
conditional `HEAD` — so an origin unreachable at that point fails the open rather
than serving the unverified copy.

```nginx
brix_cache_uvkeep 30m;   # re-check a never-verified entry at least every 30 min
```

```nginx
brix_cache_store          posix:/var/cache/brix;
brix_cache_only_if_cached on;
```

### `brix_cache_cold_max_age <time>`

**Default:** `0` (off)

Age-based purge of **clean read-through fills**: a cached object nothing has
touched for longer than this is removed regardless of occupancy (XrdPfc
`pfc.purgecoldfiles` parity).

The watermark reaper (`brix_cache_high_watermark`) only runs once the
filesystem crosses its high-water mark, so on a roomy cache an object nobody
reads is kept forever. This horizon releases it. Losing it costs nothing: a
clean read-fill is re-fetchable from the origin, which is why only *clean*
fills are eligible — dirty write-back staging is bounded separately by
`brix_cache_dirty_max_age`, and a finished write-back copy by that same
horizon.

Age is measured from the **later of atime and mtime**. atime alone is not
trustworthy — `relatime` coarsens it and `noatime` freezes it entirely, which
would make every file look ancient and purge a hot cache. Taking the later of
the two degrades safely: on a `noatime` mount the age is effectively measured
from the fill instead of the last read, so the purge can only ever be too slow,
never too eager.

Off by default, deliberately: unlike the dirty horizon (which bounds a leak)
this one **discards otherwise-serviceable cache**, so it is only ever an
explicit operator choice. It runs on the same per-worker maintenance timer as
the stale-dirty reaper — that timer is now armed by *either* horizon.
Observability: `brix_cache_dirty_reaped_total{reason="cold"}` on `/metrics`.

```nginx
brix_cache_store        posix:/var/cache/brix;
brix_cache_cold_max_age 7d;
```

### `brix_cache_max_bytes <size>`

**Default:** `0` (off)

Cap the cache's **own total bytes** (XrdPfc `pfc.diskusage files` parity). This is
a second, independent reaper arm alongside the ppm filesystem-occupancy watermark
(`brix_cache_high_watermark`): when the sum of what this cache holds exceeds the
cap, the watermark reaper evicts oldest-first until it is back within it.

It exists because occupancy and footprint are not the same thing on a **shared
filesystem**. `statvfs` reports the whole mount's fullness — everyone's data — so
the ppm watermark either never fires (a huge mount the cache never fills) or
thrashes (a noisy neighbour fills the disk and the cache reaps itself to nothing).
A byte cap bounds the cache by what it actually owns, regardless of the neighbours.

The two arms compose: with both set, each tick reaps down to the FS low-water
mark *and* down to the byte cap. The byte arm uses the same LRU candidate set and
the same eviction (cold-tier demote, manager-unregister, sidecar cleanup) as the
occupancy arm — only the stop condition differs. The reaper timer is armed by
*either* arm, so a byte cap works even with no FS watermark configured.

Notes: eviction is **down to** the cap (there is no separate low mark; the reaper
cadence, `brix_cache_reap_interval`, rate-limits re-eviction). The owned-bytes sum
includes each object's small `.cinfo`/`.meta` sidecars, so it slightly over-counts
and evicts marginally sooner than a data-only measure.

```nginx
brix_cache_store     posix:/var/cache/brix;   # shares the mount with other data
brix_cache_max_bytes 200g;                    # keep our footprint under 200 GiB
```

### `brix_write_through on|off`

**Default:** `off`

Enables write-through behavior for native XRootD writes. When this is `on`, write-mode `kXR_open` requests are evaluated by the WT decision policy and eligible handles are mirrored to an origin server.

In this mode:
1.  **Open**: The module opens the local file and caches the WT allow/deny decision on the handle.
2.  **Write**: `kXR_write`, `kXR_pgwrite`, `kXR_writev`, and handle-based `kXR_truncate` update the local file and mark the handle dirty.
3.  **Sync**: `kXR_sync` mirrors the full local file to the WT origin, then sends origin truncate and sync. Origin failures are returned to the client.
4.  **Close**: Dirty handles are flushed on close. `sync` mode blocks during close; `async` mode posts the flush to the configured nginx thread pool. Close-time origin failures are logged but do not fail the close response.

> **Note:** Write-through mode uses whole-file replacement at sync/close, not per-write dual dispatch. It is a good fit for ingest-style workflows and less suitable for very large random-write workloads.

```nginx
thread_pool brix_cache_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;                # namespace used for ACL matching
        brix_cache on;
        brix_cache_export /var/cache/brix;
        brix_cache_origin origin.example.org:1094;
        brix_cache_eviction_threshold 0.9;
        brix_thread_pool brix_cache_io;

        brix_write_through on;
        brix_wt_mode sync;                  # sync | async
        brix_wt_origin origin.example.org:1094;
        brix_wt_allow_prefix /data/ingest/;
        brix_wt_deny_prefix /data/private/;
    }
}
```

### `brix_wt_mode sync|async`

**Default:** `sync`

Controls close-time WT flush behavior. `sync` mirrors dirty data before
`kXR_close` completes. `async` posts the mirror operation to the configured
thread pool and releases the handle immediately. Explicit `kXR_sync` requests
always flush synchronously.

### `brix_wt_origin <host:port>`

Sets the WT origin data server. If omitted, write-through uses
`brix_cache_origin` when that origin is configured.

### `brix_wt_allow_prefix <path>` / `brix_wt_deny_prefix <path>`

Repeatable WT policy filters. Deny prefixes take precedence over allow
prefixes. If one or more allow prefixes are configured, paths that match none
of them are treated as local-only writes.

---

### `brix_cache_export <path>`

Local directory used to store cached files. Client paths map directly under this directory, so a request for `/store/a.root` becomes `/var/cache/brix/store/a.root` when `brix_cache_export /var/cache/brix;` is configured. The directory must exist and be readable, writable, and searchable by nginx at startup.

```nginx
brix_cache_export /var/cache/brix;
```

---

### `brix_cache_origin host:port`

Origin data server used for cache misses. The value may be plain `host:port`, `root://host:port`, or `roots://host:port`. `roots://` enables direct TLS for the outbound origin connection.

```nginx
brix_cache_origin root://origin.example.org:1094;
brix_cache_origin roots://origin.example.org:1095;
```

When outbound TLS is enabled, nginx verifies the origin certificate using `brix_trusted_ca` if configured, otherwise OpenSSL's default trust paths.

---

### `brix_cache_origin_tls on|off`

**Default:** `off` unless `brix_cache_origin` uses `roots://`

Enables TLS from the first byte on the outbound cache-origin connection. This is useful when you prefer a separate `roots://` origin listener instead of cleartext `root://`.

```nginx
brix_cache_origin origin.example.org:1095;
brix_cache_origin_tls on;
```

---

### `brix_cache_lock_timeout <time>`

**Default:** `300s`

How long a worker waits for another worker's in-progress fill of the same file. Cache fills use per-file `O_EXCL` lock files under the cache directory, so concurrent opens of the same missing path collapse to one origin transfer.

```nginx
brix_cache_lock_timeout 120s;
```

---

### `brix_cache_eviction_threshold <ratio|percent>`

**Default:** `0.9`

High-water filesystem occupancy threshold for cache eviction. When a cache fill sees `brix_cache_export` above this ratio, one worker takes a cache-wide eviction lock and unlinks the oldest regular cached files until occupancy drops back to the threshold or no candidates remain.

The value may be written as a ratio (`0.85`) or a percent (`85` or `85%`). Temporary part files, fill lock files, the eviction lock, files on a different filesystem, and the file currently being filled are skipped.

```nginx
brix_cache_eviction_threshold 0.85;
```

---

### `brix_cache_store_endpoint on|off`

**Default:** `off` — valid on the HTTP planes (`http|server|location`) and, since the root:// plane gained it, on `stream server`.

Declares this server the **trusted remote cache-STORE surface** for a cache node whose `brix_cache_store` points at it. Internal reserved names — `<key>.cinfo`, `<key>.meta`, stage markers — are answered as absent on every ordinary export (a client must not be able to read or create one). A cache node running `brix_cache_meta sidecar` against a remote store writes exactly such a name beside each object, so without this switch the sidecar `kXR_open` is refused `kXR_NotFound` (3011), every cinfo store fails, and the tier silently refills on every read.

```nginx
stream {
    server {                       # the store node
        listen 1096;
        brix_root on;
        brix_export /srv/cachestore;
        brix_allow_write on;
        brix_cache_store_endpoint on;
    }
}
```

The switch lifts the reserved-name guard for `kXR_open`/`kXR_stat`/`kXR_statx` **only**. Directory listings still skip internal names (a cache addresses its sidecars by exact name, so nothing needs them enumerated), and export confinement is untouched. Leave it `off` on every client-facing export.

---

### `brix_cms_manager host:port [host:port ...]`

Registers this data server with one or more XRootD CMS managers and starts a
heartbeat connection to EVERY one of them concurrently (stock `all.manager`
parity: a node joins the whole redundant manager set, not just the first).
Manager addresses are resolved during config parsing.

Accepts multiple endpoints on one directive and/or repeated directives — the
entries accumulate, capped at 15 (stock `XrdCmsFinder MaxMan`).  A duplicate
endpoint (same resolved address) is rejected at parse time: stock managers
blacklist a second login from the same node identity, so a duplicate would
break the node's cluster membership rather than add redundancy.

Registry-miss lookups (`kXR_locate`, manager-mode open/stat/query paths)
rotate round-robin over the logged-in links (stock `ClientMan` rotation) and
fail over automatically when a manager drops; CNS namespace events fan out to
every live link so each redundant manager keeps a complete inventory.

```nginx
brix_cms_manager cms-a.example.org:1213 cms-b.example.org:1213;
brix_cms_paths /store;
brix_cms_interval 30s;
```

### `brix_cms_paths <string>`

**Default:** `brix_export`

Path string advertised in the CMS login packet. Use this when the exported CMS
namespace differs from the local filesystem root.

### `brix_cms_interval <time>`

**Default:** `30s`

How often each worker sends CMS load/availability heartbeats after registration.

### `brix_cms_vnid <string>`

**Default:** unset

Virtual network id advertised in the CMS login envCGI string (`vnid=`), matching
stock `cmsd` semantics. The manager records it per registered server and shows it
in the dashboard cluster rows. *(Phase-89 W9.)*

---

### CMS manager tuning (phase-89 CMS parity — all default to pre-phase behaviour)

These flags extend manager-mode selection and mutation handling. Every default
preserves the previous behaviour, so leaving them unset is a provable no-op.

#### `brix_cms_load_weight <0–100>`

**Default:** `0`

Blends the real machine-load vector from node heartbeats (`/proc`-sourced
cpu/net/mem/pagefault meter) into selection scoring. Read selection scores
`((100-w)·util + w·load)/100`; write selection scales `free_mb` down by
`w·load/10000`. `0` keeps the byte-identical space/util-only scoring.

#### `brix_cms_locate_window <time>`

**Default:** `0` (off)

Dynamic location: on a locate miss in the SHM location cache, park the client,
fan `kYR_state` probes out to logged-in node connections whose exports cover the
path, and redirect to the first `kYR_have` answer (which is then cached with a
30 s TTL). On window expiry the client gets `kXR_wait` and selection falls back
to the static registry chain. `0` = static prefix selection only.

#### `brix_cms_state_fanout <n>`

**Default:** `8`

Cap on how many node connections one dynamic-locate window probes.

#### `brix_cms_affinity on|off`

**Default:** `off`

Sticky selection: among the fresh (non-stale, non-blacklisted) candidate set, a
path hash — not the load metric — picks the server, so repeat opens of the same
path land on the same node. A drained or blacklisted host is never sticky.

#### `brix_cms_locate_multi on|off`

**Default:** `off`

`kXR_locate` answers `kXR_ok` with the full live `S<r|w>host:port` server set
(lateral redirect) instead of a single `kXR_redirect`. An empty set falls
through to the single-server path unchanged.

#### `brix_cms_fanout on|off` / `brix_cms_fanout_window <time>`

**Defaults:** `off` / `500ms`

Multi-replica mutation fan-out: with `brix_cms_fanout on`, a client
`kXR_rm`/`kXR_rmdir` whose path has ≥2 registered holders (all connected to this
worker) is forwarded to *every* holder instead of redirecting to one. The node
executor is silent on success, so aggregation is a deadline window: no
`kYR_error` inside `brix_cms_fanout_window` ⇒ `kXR_ok`; any node error ⇒
`kXR_error` with that node's text. Single-holder paths keep the redirect path.
**Gotcha:** the window is a msec slot — write `600ms`; a bare `600` parses as
600 *seconds*.

---

### CMS parity wave (2026-08-09 — stock `cms.*` selection/topology parity)

Every directive below defaults to the previous behaviour; leaving them unset is
a no-op. Covered by `tests/test_cms_parity_wave.py`.

#### `brix_cms_delay_servers <n>` / `brix_cms_delay_hold <secs>`

**Defaults:** `0` (off) / `5`

SUPCount floor (stock `cms.delay servers`). While fewer than `n` **data
servers** (roles `S`/proxy-server `PS`) are registered, the manager answers
every `kXR_locate`/`kXR_open`/`kXR_stat` with `kXR_wait <delay_hold>` instead of
redirecting — a fresh manager with 1 of 20 nodes up must not funnel the whole
grid onto that one node. Managers, supervisors and peers do not count toward the
floor.

#### `brix_cms_sched cpu N io N runq N mem N pag N space N fuzz N maxload N`

**Default:** all `0` (legacy `brix_cms_load_weight` scoring)

Component-weighted selection (stock `cms.sched`). Any non-zero weight switches
read scoring to the weighted mean of the five heartbeat `theLoad` bytes (cpu,
net/io, xeq/runq, mem, pag) plus the disk-utilisation `space` component; write
scoring keeps `free_mb` as the base, discounted by machine load. `fuzz N` (0–100)
treats two read candidates whose blended metric differs by ≤N% as equal and
rotates round-robin between them; `maxload N` demotes a node whose blended
machine load exceeds N to a last-resort tier below stale-but-live nodes
(graceful degradation, never a hard refusal — the SUPCount floor covers the
not-ready case). Each value is 0–100; unknown keys fail `nginx -t`.

#### `brix_cms_stage_select on|off`

**Default:** `off`

Stage-aware selection (stock two-phase select). A read of a file no node holds
(loc-cache miss, or a `brix_cms_emptylife` negative entry) is routed to the
roomiest **stage-capable** node (one that advertised the `kYR_status` stage bit)
instead of the least-utilised node — the recall lands on the node with the most
free space. Requires `brix_cms_locate_window` (or the negative cache) to know a
path has no live holder.

#### `brix_cms_fxhold <time>` / `brix_cms_emptylife <time>`

**Defaults:** unset (30 s legacy TTL) / `0` (off)

`brix_cms_fxhold` sets the positive location-cache TTL (stock `cms.fxhold`
defaults to 8 h; BriX keeps the legacy 30 s unless set). `brix_cms_emptylife`
enables a **negative** location cache: a `kYR_state` fan-out that expires with no
`kYR_have` records "no node holds this path" for the given TTL, so a client's
retry answers `kXR_NotFound` immediately instead of re-parking through another
full window. Both are msec slots — write `8h`, `30s`.

#### `brix_cms_dfs on|off`

**Default:** `off`

Shared-filesystem mode (stock `cms.dfs`). Every node sees every file, so the
per-file `kYR_state` fan-out is pure overhead — with `on`, locate skips the
probe entirely and selects by load among all registered nodes exporting the
path.

#### `brix_cms_server_max_direct <n>` *(CMS-server block)*

**Default:** `0` (off)

ManTree-style login offload. Once `n` direct data servers (`S`) are registered,
a **new** server login is answered `kYR_try` naming the least-utilised
registered supervisor (`R`) and closed; the node re-dials the supervisor,
forming the tree. Supervisors, managers, peers and reconnecting known members
are never offloaded. The node honours an unsolicited login `kYR_try`
(re-targeting its heartbeat link, reverting to the configured manager after
repeated failures or a redirect chain >4 deep). Full stock ManTree tree
*negotiation* (superport self-instantiation, ClustID dedup) is a documented
divergence.

#### `brix_cms_perf_pgm <cmd>` / `brix_cms_perf_interval <time>`

**Defaults:** unset (off) / `30s`

External machine-load feed (stock `cms.perf pgm`). A long-lived child process is
spawned once per CMS-client worker; each stdout line `cpu net xeq mem pag` (five
0–100 integers) overrides the `/proc` meter's figures in the `kYR_load`
heartbeat while fresher than `2×interval`. A dead feed is respawned with backoff;
a stale or missing feed silently falls back to `/proc` — the heartbeat is never
blocked.

#### `brix_cms_altds <port> [monitor]` / `brix_cms_altds_interval <time>`

**Defaults:** off / `10s`

Alternate (foreign) data server (stock `cms.altds`). The CMS login advertises
`<port>` as this node's data port, so clients selected here are redirected to a
co-located foreign data server (e.g. a stock `xrootd` on the same host — the
manager records the connection's peer address, so only the port is
advertisable). With `monitor`, a periodic non-blocking loopback probe of the
port drives `kYR_status` suspend/resume on every manager link when the foreign DS
dies or returns.

#### `brix_cms_min_free <MB>`

**Default:** `100`

The **mSpace** policy floor (in MB) this data node advertises in its CMS
`kYR_login` payload (stock `cms.space [min ...]`). It is the free-space level
below which the manager should stop selecting this node for **writes** — a
static policy figure, not a live measurement (the live free space rides the
`fSpace` field / periodic `kYR_load` heartbeat). Was a hardcoded 100 MB; the
default is unchanged, so existing meshes see no difference. Absolute megabytes
only — the stock percentage form (`min 2%`) is not accepted.

#### `brix_cms_whitelist_file <path>` *(CMS-server block)*

**Default:** unset

Inverse of `brix_cms_blacklist_file`: **only** hosts matching an entry may
register — a login from any other host is refused at admission and closed. Same
line grammar (host, `host:port`, IPv4 CIDR, `*` patterns), same mtime-poll +
re-assert cadence. Mutually exclusive with `brix_cms_blacklist_file`.

The blacklist file additionally accepts (2026-08-09) `*` host **patterns**
(XrdOucNList rules — at most one `*`) and a per-entry `redirect <host:port>`
action that answers a matching node's login with `kYR_try` naming the alternate
manager (instead of only draining it).

#### `brix_cms_role peer|proxy` (added to `auto|server|manager|supervisor`)

`peer` logs in with the `kYR_peer` Mode bit (no `kYR_server`): the manager
registers it as an overflow cluster consulted only as a last resort before
`kXR_NotFound`, never in normal selection. `proxy` logs in `kYR_proxy|kYR_server`
— a proxy data server selectable like any other.

---

### `brix_manager_mode on|off`

**Default:** `off`

Cannot be combined with [`brix_read_only`](#brix_read_only-onoff) or
`brix_read_only_public`: a manager redirects `mkdir`/`rm`/`rmdir`/`mv`/`chmod`/
`truncate` to a data node before the local read-only gate runs, so the endpoint
would not be read-only. `nginx -t` refuses the pair at `[emerg]`.

Enables dynamic server registry queries on this XRootD listener. When on, `kXR_locate` and `kXR_open` requests are answered with `kXR_redirect` to whichever registered data server best matches the requested path (lowest utilisation for reads, most free space for writes). The server also advertises the `kXR_isManager` capability bit in `kXR_protocol` responses.

Requires a companion `brix_cms_server on;` listener (typically on port 1213) to receive data server registrations. The registry is a 128-slot shared-memory table populated by the CMS server when data servers connect and send login frames.

See [cluster-mode.md](../05-operations/cluster-management.md) for the full two-tier and three-tier cluster configuration.

```nginx
stream {
    server {
        listen 1213;
        brix_cms_server on;
    }
    server {
        listen 1094;
        brix_root on;
        brix_export /dev/null;      # redirector has no local storage
        brix_manager_mode on;
    }
}
```

---

### `brix_cms_server on|off`

**Default:** `off`

Enables a CMS management-protocol server on this stream listener. When on, the listener accepts incoming TCP connections from data servers, parses CMS login and heartbeat frames, and maintains the shared server registry used by `brix_manager_mode`.

This directive is used on a dedicated management port (default 1213), not on the XRootD data port.

| CMS frame | Action |
|---|---|
| `kYR_login` | Register server: host, port, path list, free space, utilisation (+ `vnid=` from envCGI) |
| `kYR_avail` / `kYR_load` / `kYR_space` | Update load metrics (incl. the phase-89 machine-load vector) |
| `kYR_usage` / `kYR_stats` | Answer aggregate free-space (`kYR_load` 13-byte form) / size form |
| `kYR_status` | Reset / suspend / resume / stage-state transitions |
| `kYR_have` | Cache a node's dynamic location assertion (export-confined, drained/blacklisted refused) |
| `kYR_pong` | Update last-seen timestamp |
| Disconnect | Unregister server from registry |

```nginx
stream {
    server {
        listen 1213;
        brix_cms_server on;
    }
}
```

#### `brix_cms_blacklist_file <path>` (CMS-server block)

**Default:** unset

Operator-driven blacklist file for the CMS-server block: one `host`,
`host:port`, or IPv4 `a.b.c.d/n` CIDR per line (bare/bracketed IPv6 host text
matches exactly; malformed lines are warned and skipped, never fatal; 128
entries / 64 KB caps). The file is mtime-polled from the per-connection ping
tick and re-asserted after every registration, so **the file wins over an admin
`undrain`** — a file-listed host stays excluded until the file changes, while
removing a line lifts the ban within ≤3 ping intervals. *(Phase-89 W6′; see the
admin cluster API for runtime drain/undrain.)*

---

## CSI block-checksum integrity directives

At-rest integrity on the unified per-file metadata record ("xmeta"): one
CRC32C per block (default 1MiB), stored in the file's own `user.xrd.cinfo`
xattr (or a stock-readable `<file>.cinfo` sidecar when the xattr doesn't
fit). Reads verify the blocks they fully span; writes fold fresh CRCs and
merge them into the record at close. **On by default** — set `brix_csi off`
to opt out, or keep it on and set `brix_csi_trust_fs on` where the
filesystem already checksums end-to-end. All directives are stream
server-block scoped.

| Directive | Default | Meaning |
|---|---|---|
| `brix_csi on\|off` | `on` | Enable block-checksum integrity for this server |
| `brix_csi_block <size>` | `1m` | CRC granule for NEW records (existing records keep their own) |
| `brix_csi_require on\|off` | `off` | Refuse read-opens of files with no verifiable record |
| `brix_csi_trust_fs on\|off` | `off` | Trust the backing filesystem: skip read-verify |
| `brix_csi_scrub_interval <time>` | `0` (off) | Paced at-rest scrub cadence: re-verify every recorded block CRC under the export root every `<time>` |

### `brix_csi_trust_fs on|off`

**Default:** `off`

Declares the backing filesystem self-checksumming (ZFS, CephFS, RADOS, Btrfs)
and skips CSI verification on the read path: pure read handles don't load the
record at all, and reads through a read-write handle skip the block check.
The write side is untouched — writes keep folding block CRCs into the record
at close, and pgwrite wire-CRC validation stays on — so records remain fresh
for scrubbing and for switching back to `off` later.

Only enable this on storage that provides its own end-to-end data checksums;
on a plain filesystem it silently disables at-rest corruption detection for
reads. While trusting, `brix_csi_require` is not enforced on read opens.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /zpool/data;      # ZFS: checksummed end-to-end already
        brix_csi on;                # keep recording block CRCs on write
        brix_csi_trust_fs on;       # but don't re-verify reads
    }
}
```

Semantics worth knowing: a read verifies only the blocks it FULLY covers
(partial-edge blocks are skipped on the hot path); a CRC slot of zero means
"not computed" and never fails a read; a crash between writing and close
leaves stale CRCs, so reads of a torn upload fail with `kXR_ChkSumErr` until
the file is rewritten (fail-closed).

### `brix_csi_scrub_interval <time>`

**Default:** `0` (off)

Arms a paced background **at-rest scrub**. Because a read only verifies the
blocks it fully covers, a corrupt block in cold data is never noticed until an
unlucky client happens to read across it. When set, a per-server maintenance
timer walks the export root once every `<time>` and re-verifies **every**
recorded block CRC of every tagged file against its bytes on disk — surfacing
silent storage rot proactively rather than on the read path.

The interval is the pacing: one full sweep per interval, never a self-rearming
hot poll (it is a `cancelable` timer, so it never delays a graceful shutdown).
A block whose CRC slot is unset ("not computed") or whose recorded range runs
past the file on disk is skipped (fail-open on coverage gaps); the scrub only
reports a genuine CRC difference. Each corrupt block increments the
`brix_csi_scrub_mismatch_total` metric and emits an `error.log` diagnostic
naming the file, block index, and recorded-vs-on-disk CRC. The scrub is
read-only — it never repairs or quarantines; restore the affected file from a
good replica.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;
        brix_csi on;
        brix_csi_scrub_interval 6h;   # sweep the whole export every 6 hours
    }
}
```

Leave it at `0` on filesystems that already scrub themselves (ZFS/CephFS/RADOS
with periodic `scrub`), pairing with `brix_csi_trust_fs on` — the storage layer
does the at-rest verification there.

---

## Proxy mode directives

These directives configure transparent XRootD proxy mode, in which a stream
listener forwards `root://` client requests to one or more upstream XRootD data
servers or redirectors. All proxy directives are `server`-context (stream
`server {}` block). Defaults below match `src/protocols/root/stream/module.c`.

### `brix_proxy on|off`

**Default:** `off`

Enables transparent XRootD proxy mode for this stream server. Requires at least
one `brix_proxy_upstream`.

### `brix_proxy_upstream host[:port] [auth]`

Upstream XRootD data server or redirector. May appear multiple times for
round-robin load balancing. The optional second argument overrides
`brix_proxy_auth` for this upstream only.

### `brix_proxy_upstream_tls on|off`

**Default:** `off`

Wraps the outbound upstream connection in TLS from the first byte.

### `brix_proxy_upstream_tls_ca <path>`

PEM CA bundle used to verify the upstream TLS certificate (enables peer
verification).

### `brix_proxy_upstream_tls_name <host>`

SNI hostname presented on the upstream TLS connection. Defaults to the
`brix_proxy_upstream` host.

### `brix_proxy_auth <mode>`

**Default:** `anonymous`

Auth bridging mode for upstream connections (for example `anonymous`, `forward`,
or `sss`). `forward` replays the client bearer token; `sss` builds an SSS
credential from the configured key.

### `brix_proxy_login_user <string>`

Overrides the username placed in the upstream `kXR_login` frame.

### `brix_proxy_audit_log <path>|off`

**Default:** `off`

Writes one JSON line per closed or abandoned upstream file handle.

### `brix_proxy_reconnect_attempts <n>`

**Default:** `0`

Reconnect budget per client session when an idle upstream connection drops with
no open handles.

### `brix_proxy_connect_timeout <ms>`

**Default:** `10000`

Milliseconds allowed for the TCP connect to the upstream. `0` disables the
limit.

### `brix_proxy_read_timeout <ms>`

**Default:** `60000`

Milliseconds allowed between upstream response bytes. `0` disables the limit.

### `brix_proxy_keepalive_interval <ms>`

Idle keepalive interval for upstream connections.

### `brix_proxy_path_rewrite <strip> <add>`

Strips a leading prefix from open/path requests, then prepends `add` (for
example `brix_proxy_path_rewrite /brix /data`).

---

## CVMFS site-cache directives

These directives configure the `cvmfs://` protocol handler
(`ngx_http_brix_cvmfs_module`), which turns an nginx location into a
Squid-replacement CVMFS forward-proxy or reverse-proxy site cache. The cache is
read-only by construction — `brix_allow_write`, `brix_stage`, and
`brix_cache_slice_size` are rejected with a config error under a cvmfs location.

Unified storage directives (`brix_cache_store`, `brix_cache_verify`,
`brix_cache_evict_at`, `brix_cache_evict_to`, `brix_storage_backend`,
`brix_thread_pool`, …) apply to cvmfs locations exactly as they do to WebDAV and
S3. The tables below cover the cvmfs-specific knobs only.

### Core enable and manifest/negative cache

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs on\|off` | flag | `off` | Activate the cvmfs handler for this location (one protocol per location) |
| `brix_cvmfs_manifest_ttl <sec>` | seconds | `61` | How long `.cvmfspublished` manifests are held before revalidation |
| `brix_cvmfs_negative_ttl <sec>` | seconds | `10` | How long a known-missing object answer is cached |
| `brix_cvmfs_quarantine_dir <path>` | path | unset | Directory for CAS-verify failures; each quarantined file is evidence of a corrupt transfer |
| `brix_cvmfs_trace on\|off` | flag | `off` | Promote upstream-request lines to INFO in the error log (process-wide) |

### Upstream allow-list and fill policy

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_upstream_allow <host> …` | 1+ hosts | required | Stratum-1 hostname(s) this cache is allowed to fetch from; multi-host and multi-directive both work |
| `brix_cvmfs_upstream_max <n>` | integer | `8` | Maximum concurrent fill connections to any single upstream endpoint |
| `brix_cvmfs_client_hold <sec>` | seconds | `25` | Maximum time a waiting client is held while the cache retries origins before returning `504 Retry-After` |
| `brix_cvmfs_fill_max_life <sec>` | seconds | `300` | Maximum lifetime of a single fill; fill is abandoned and a fresh one started after this |

### Origin selection

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_origin_select static\|geo\|rtt` | enum | `rtt` | Strategy for ordering origins: `rtt` probes connect latency every `rtt_interval` and prefers the fastest; `geo` ranks by great-circle distance from `brix_cvmfs_here`; `static` uses declaration order |
| `brix_cvmfs_rtt_interval <sec>` | seconds | `60` | How often RTT probes run (only when `origin_select rtt`) |
| `brix_cvmfs_here <lat>:<lon>` | lat:lon | required for `geo` | Geographic coordinates of this cache node (e.g. `55.95:-3.19`) |
| `brix_cvmfs_origin_coords <host[:port]> <lat>:<lon>` | host lat:lon | required for `geo` | Coordinates of one Stratum-1; repeat for each origin |

`brix_cvmfs_origin_select geo` without `brix_cvmfs_here` is a config error. A `brix_cvmfs_origin_coords` entry not matched to a configured origin is also a config error. `geo` (and `rtt`) require origins registered via `brix_storage_backend` (an http/https URL or pipe-separated list); `brix_cvmfs_upstream_allow` alone does not register endpoints for geo ranking.

### Upstream stall detection

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_origin_connect_timeout <sec>` | seconds | `2` | TCP connect timeout per upstream attempt |
| `brix_cvmfs_origin_stall_timeout <sec>` | seconds | `4` | Seconds at the low-speed threshold before the connection is declared stalled |
| `brix_cvmfs_origin_stall_bytes <n>` | bytes | `1` | Low-speed threshold in bytes/second used with `origin_stall_timeout` |
| `brix_cvmfs_origin_attempt_timeout <sec>` | seconds | `0` (off) | Hard per-attempt time ceiling; `0` disables |
| `brix_cvmfs_origin_reuse_conn on\|off` | flag | `on` | Reuse HTTP keep-alive connections to origins |
| `brix_cvmfs_fill_retry_policy failover\|force-primary` | enum | `failover` | After a stall: `failover` tries the next endpoint; `force-primary` retries the ranked-first endpoint |
| `brix_cvmfs_shared_cache on\|off` | flag | `off` | Allow multiple cache processes to share the same cache directory |
| `brix_cvmfs_unified_origin on\|off` | flag | `off` | Serve every proxy request (including repository endpoints) from a single configured `brix_storage_backend` http(s) origin set |

### Server-side geo answering

These directives configure nginx's response to CVMFS geo-API requests
(`/cvmfs/<fqrn>/api/v1.0/geo/…`), so that clients rank Stratum-1s by distance
from this cache rather than making their own geo queries.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_geo_answer off\|rtt` | enum | `off` | `rtt` answers geo requests using RTT-derived rankings; `off` passes them upstream |
| `brix_cvmfs_geo_cache_ttl <sec>` | seconds | `60` | How long geo-answer results are cached |
| `brix_cvmfs_geo_max_servers <n>` | integer | `16` | Maximum servers returned in one geo-answer response |

### Secure cvmfs (scvmfs, EXPERIMENTAL)

`brix_scvmfs on` layers TLS and bearer-token authorization on top of a cvmfs
location. Requires `brix_cvmfs on` in the same location and a TLS listener
(`listen … ssl` with certificates). Plain HTTP is refused.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_scvmfs on\|off` | flag | `off` | Enable secure cvmfs on this location |
| `brix_scvmfs_authz none\|bearer` | enum | `none` | `bearer` gates clients on a WLCG/SciTokens read scope |
| `brix_scvmfs_token_issuers <path>` | path | required for `bearer` | SciTokens configuration file listing trusted issuers |

### Cache storage knobs (unified — apply to cvmfs)

These are the unified storage directives most commonly tuned for a cvmfs site cache.
See the unified grammar section at the top of this page for the complete list.

| Directive | Default | Purpose |
|---|---|---|
| `brix_cache_store posix:<path>` | required | Local cache directory (XFS recommended; the cache engine owns the volume) |
| `brix_cache_verify off\|cvmfs-cas` | **`cvmfs-cas`** for cvmfs (other protocols: `off`) | Verify every fill against its SHA-1 content address; quarantines corrupt objects |
| `brix_cache_evict_at <pct>` | `90` | Percent-full that triggers eviction. On the `root://` stream read cache this pair seeds the proactive watermark LRU reaper (percent → ppm; an explicit `brix_cache_high_watermark`/`brix_cache_low_watermark` pair takes precedence). On the cvmfs/HTTP plane occupancy eviction is not wired to it yet — cache growth there is bounded by `brix_cache_max_object` and DELETE/overwrite eviction. |
| `brix_cache_evict_to <pct>` | `80` | Percent-full target the reaper evicts down to (hysteresis partner of `brix_cache_evict_at`; must be lower). Same plane caveat as above. |
| `brix_storage_backend <url>` | unset | Reverse-proxy origin(s) — pipe-separated `http://` URL list for failover; use instead of `brix_cvmfs_upstream_allow` in reverse mode |
| `brix_thread_pool <name>` | `default` | nginx thread pool for fill I/O |

### Repo serving, composition and manifest trust

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_stratum0_root <path>` | path | unset | Serve a published Stratum-0 repo tree from `<path>` (explicit alias for `brix_export` — the merge refuses cache-fill upstream grammar in the same block, and the gate answers `/.cvmfs_master_replica` so a real Stratum-1 `cvmfs_server add-replica` recognizes it as a replication source) |
| `brix_cvmfs_virtual_repo <name> <member>…` | 2+ args | unset | Compose a virtual repo `<name>` from one or more member repos |
| `brix_cvmfs_repo_authz <repo> <scitokens.cfg>` | 2 args | unset | Token-gate one repo — clients need a WLCG/SciTokens read scope per the config (phase-85 F3) |
| `brix_cvmfs_verify_manifest <pubkey>` | path | unset | Master public-key file used to verify `.cvmfspublished` manifest signatures |

### Integrity scrubbing, QoS and provenance

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_scrub on\|off` | flag | `off` | Background CAS integrity scrubber — re-verifies cached objects against their content address (phase-87 G17) |
| `brix_cvmfs_scrub_interval <sec>` | seconds | `60` | Scrub cycle period |
| `brix_cvmfs_scrub_rate <n>` | integer | `20` | Scrub throttle — objects checked per cycle tick |
| `brix_cvmfs_attest <arg>` | takes 1 | unset | Runtime provenance attestation of served content (phase-87 G15) |
| `brix_cvmfs_qos <vo> <a> <b>` | 3 args | unset | Per-VO / per-job QoS fill throttling (phase-85 F9) |

### Content-transfer optimizations (phase-87, opt-in)

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_bundle on\|off` | flag | `off` | Chunk-bundle batch fetch — coalesce many small CAS fetches into one origin request (G2) |
| `brix_cvmfs_delta on\|off` | flag | `off` | Cross-revision delta transfer (G10) |
| `brix_cvmfs_dict on\|off` | flag | `off` | Trained shared-dictionary coding (G3) |
| `brix_cvmfs_learn on\|off` | flag | `off` | Workload-learned predictive prewarm (G11) |
| `brix_cvmfs_swarm on\|off` | flag | `off` | P2P swarm cold-start — peer caches seed each other (G12) |
| `brix_cvmfs_swarm_interval <sec>` | seconds | `3` | Swarm peer-refresh interval |

### Additional origin / TTL knobs

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_offline_ttl <sec>` | seconds | `0` (off) | Keep serving stale cached content for this long when every origin is unreachable |
| `brix_cvmfs_origin_http_version <ver>` | enum | auto | Force the HTTP version for origin fills (requires a libcurl that supports it) |

## Network / TCP tuning directives

Per-connection socket options applied once at accept on the `root://` stream
plane. All are **best-effort and non-fatal** — a kernel that rejects the option
(missing feature, value above a sysctl cap) leaves its default and the connection
proceeds. All default to the kernel default, so a stock deployment is unchanged.

### `brix_socket_sndbuf <size>`

**Default:** `0` (kernel autotuning) · **Context:** `stream {}`, `server {}`

Sets `SO_SNDBUF` (send-buffer bytes) on each accepted connection. On a high
bandwidth-delay-product link (long-RTT WAN transfers) the kernel's send
autotuning can lag the true BDP, capping a single download stream below line
rate; pinning the send buffer to the deployment BDP (`bandwidth × RTT`) lets the
server keep the pipe full. Setting it disables send autotuning for that socket,
so leave it `0` unless you have **measured** the BDP. The kernel doubles the
requested value for bookkeeping and clamps it to `net.core.wmem_max`. Phase-33
P3-B3. Download (server→client) is the dominant `root://` read direction, so this
is the primary throughput knob of the pair.

### `brix_socket_rcvbuf <size>`

**Default:** `0` (kernel autotuning) · **Context:** `stream {}`, `server {}`

Sets `SO_RCVBUF` (receive-buffer bytes) on each accepted connection — the
symmetric knob for the upload/PUT direction. Same BDP guidance and
`net.core.rmem_max` clamp as `brix_socket_sndbuf`.

**Example** — a 10 Gbps path with a 30 ms RTT (BDP ≈ 37.5 MiB):

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_storage_backend posix:/data;
        brix_socket_sndbuf 40m;   # requires: sysctl -w net.core.wmem_max=41943040
        brix_socket_rcvbuf 40m;   # requires: sysctl -w net.core.rmem_max=41943040
    }
}
```

## Backend credential delegation directives

Control how the gateway re-presents a client's proven identity to a downstream
backend/origin (the phase-70 "full credential delegation" work). All default to
**off / disabled**, so a stock deployment forwards nothing.

### `brix_backend_krb5_forwardable on|off`

**Default:** `off` · **Context:** `http {}`, `server {}`, `location {}` and
`stream {}`, `server {}`

Arms the Kerberos (krb5) origin leg. When a client authenticates over `root://`
with a **forwardable** TGT (`GSS_C_DELEG_FLAG`), turning this on lets the gateway
capture the delegated ticket and re-delegate it — via a fresh GSSAPI context — to
a Kerberised origin backend, so the origin sees the *client's* identity rather
than the gateway's. Left `off`, no forwarded credential is ever captured and the
gateway falls back to SELECT (its own service identity).

The origin service principal is **derived** as `host/<backend-fqdn>@<REALM>`,
taking the realm from the gateway's own configured principal — there is no
separate directive for the origin principal, and a backend host string is
rejected if it tries to smuggle a realm (`@`) or principal component (`/`).

Available on **both** request planes: the HTTP plane and the `root://` stream
plane (krb5 auth runs on the stream plane). The value is validated at `nginx -t`
— any token other than `on`/`off` is a hard load error, never a silent no-op.

> **Status (2026-07-28):** the cryptographic core (capture + forward + principal
> derivation) is landed and LIVE-verified against a real MIT KDC; the inbound
> two-round wire state machine and the outbound multi-leg drive are the remaining
> runtime pieces, blocked on live krb5 peers. See
> `docs/refactor/phase-70-full-credential-delegation.md` §5.7 / §5.7.1.

### S3 STS (`brix_backend_s3_sts_endpoint` / `brix_backend_s3_sts_flavor`)

The sibling S3 delegation directives (SigV4 `AssumeRole` against an STS endpoint;
`aws` or `minio` dialect) are documented in
`docs/refactor/phase-70-full-credential-delegation.md` §5.5. `…_endpoint` is
load-validated at `nginx -t` (must be a well-formed `http(s)://` URL).

## Phase-105 — unified cross-protocol directives (wave 2)

All registered once on the common module; set at `http{}`/`server{}`/location
scope and inherited by every brix HTTP protocol (WebDAV, S3, cvmfs) unless a
narrower scope is stated. Hard-renamed old spellings are listed in
`migration-unified-grammar.md`.

| Directive | Args | What it does |
|---|---|---|
| `brix_kv_zone` | `zone=name:size key=N val=N` (http main) | declare a shared-memory KV zone (token cache, rate-limit state) |
| `brix_token_cache` | `zone=<name>` | cross-worker verified-JWT cache; amortizes bearer validation on webdav AND s3. Only positive verdicts are stored; entries re-check `exp` and are TTL-capped at 5 min |
| `brix_rate_limit` | `zone= rate=<N>r/s burst=<N> [key=dn\|ip]` | per-client-IP token-bucket admission, enforced BEFORE the auth burden on webdav, s3 and cvmfs (`key=dn` is stream-plane semantics; HTTP keys by IP) |
| `brix_rate_limit_zone` / `brix_rate_limit_rule` / `brix_bandwidth_limit` / `brix_concurrency_limit` | see phase-25 docs | traffic-shaping rules; rules now inherit into nested locations like every other preamble rule array |
| `brix_max_delay` | `<time>` | cap on the client wait/Retry-After a response may advertise (xrootd maxdelay analog). HTTP default 0=off; stream default 60 |
| `brix_verify_depth` | `<n>` | accepted client proxy-chain depth cap in the auth path (VOMS proxies + delegation re-verify on HTTP; GSI login on stream). HTTP default 10; stream 0=unlimited |
| `brix_trusted_ca` / `brix_trusted_ca_dir` | `<file>` / `<dir>` | auth-layer verify-source CA material for GSI/VOMS cert auth. **Consumed by webdav today** — inert on protocols without cert auth (s3 SigV4/bearer) |
| `brix_client_ca_store` | `<dir>` (srv/loc) | hashed CA dir loaded into the SERVER SSL_CTX client-verify store at postconfiguration (server-wide by construction) |
| `brix_delegation_endpoint` | `on\|off` | opt-in GSI proxy-upload delegation well-known endpoint. **Served by the webdav dispatch** — enabling it elsewhere has no endpoint to serve |
| `brix_tcp_congestion` | `<alg>` | sender-side TCP congestion algorithm (e.g. `bbr`) applied by the shared file-serve path to EVERY HTTP download (webdav GET, S3 GetObject, cvmfs) |
| `brix_mirror_url` + `_methods`/`_sample`/`_strip_auth`/`_writes`/`_log_diverge`/`_timeout`/`_token` | see phase-24 docs | traffic-mirror settings; the mirror handlers are global, so one `http{}`-level target mirrors every brix HTTP protocol |
| `brix_token_introspect_url` / `_loc` / `_ttl` / `_fail_open` | str / str / `<time>` / flag | OIDC introspection (revocation): `_loc` names the internal location that proxy_passes to the IdP; consulted for any brix request carrying a Bearer token. `_ttl` accepts time units (default 30s); `_fail_open` default on |
| `brix_webdav_query_token` | `on\|off` (webdav) | accept `?authz=`/`?access_token=` query-string tokens (default on) — webdav auth surface, renamed from `brix_http_query_token` |
| `brix_webdav_secretkey` | `<key>` (webdav) | redirect-CGI HMAC key (pairs with `brix_webdav_redirect_*`) — renamed from `brix_http_secretkey` |

Stream-plane spellings unified in the same wave: `brix_authdb_engine`
(`native|xrdacc`, was `brix_authdb_format`), `brix_acc_audit` /
`brix_acc_refresh` (were `brix_authdb_audit`/`_refresh`),
`brix_wt_stage_root`/`_backend`/`_block_size` (were `brix_cache_wt_stage_*`),
and the HTTP TPC outbound-token quartet now spelled
`brix_tpc_outbound_{token_endpoint,client_id,client_secret,scope}`.
