# XrdHttp + GSI credential delegation through BriX — all-client matrix

**2026-08-04.** Companion to the `root://` GSI delegation proof
(`gsi-delegation-capture-*`, brixbench `gsi_deleg_alice_bob.sh`). This one proves the
**HTTP/WebDAV** delegation mode: end user **alice** (X.509 proxy, mutual TLS on the
front leg) → BriX HTTPS gateway running as unix **bob** → official **XrdHttp+GSI**
origin, with the origin authenticating **every** delegated op as *alice*, never bob.

Reusable drivers + configs: `/root/dev/brixbench/gsi_xrdhttp_deleg/`.

## The two BriX "in front of XrdHttp" modes (same distinction as root://)

- **Staged storage-backend gateway** (`brix_storage_backend` + a fixed
  `brix_credential x509_proxy`): terminates the client, talks to the origin as **one
  fixed host identity** = bob. Origin sees bob. *Not* delegation.
- **Per-user reverse-proxy delegation** (`brix_delegation_endpoint` + the
  `$brix_delegated_cred` variable feeding `proxy_ssl_certificate`): each user first
  deposits their proxy; the back leg then re-derives and presents *that user's* proxy.
  Origin sees **alice**. This is the mode proved here.

## Rig

- **Origin** (`origin.cfg`): official `xrootd -R nobody`, `XrdHttp:21210` + root `:21211`,
  `sec.protocol gsi … -gridmap … -gmapopt:2`, `http.secxtractor libXrdHttpVOMS-5.so`
  (extracts the proxy DN), `http.gridmap` (DN→alice), `xrootd.chksum max 2 adler32`.
  XrdHttp bridges into the xroot layer, so it needs a real thread pool
  (`xrd.sched mint 8 maxt 64 avlt 16`) or it hangs. Log:
  `.../og/og/origin.log` (note the `-n og` doubles the subdir).
- **Front** (`gateway.conf`): the session's static-brix nginx 1.28.3
  (`/tmp/brix-nginx-session-*/nginx`; `proxy_ssl_certificate` takes a **variable** only
  on ≥1.21.4 — system nginx 1.20.1 can't and errors trying to `fopen("$brix_delegated_cred")`).
  `user bob;`, front-leg `ssl_verify_client on` + `brix_webdav_proxy_certs on` +
  `brix_client_certificate_folder`/`brix_ssl_client_capath` (hashed CA dir);
  delegation endpoint `/.well-known/brix-delegation`; back leg
  `proxy_pass https://127.0.0.1:21210` with `proxy_ssl_certificate $brix_delegated_cred`.
- **Delegation upload**: authenticate the PUT with the **EEC** (`usercert.pem`+`userkey.pem`),
  body = the proxy. Authenticating the upload with the *proxy* fails with
  `brix_delegation: DN mismatch` — the front-leg identity then carries the extra proxy
  CN (`…/CN=12345/CN=12346`) and no longer equals the uploaded proxy's EEC DN
  (`…/CN=12345`). Stored at `<cred_dir>/x5h-<sha256(EEC_DN)[:32]>.pem` (bob-owned 0600).
- **Proxy minting on OpenSSL ≥3.5 (2026-08-05).** Do **not** mint alice's proxy with
  `xrdgsiproxy init` for this rig: the proxy it produces on OpenSSL 3.5.x carries an
  extra `Extended Key Usage: TLS Web Client Authentication`, `Key Usage`, and a
  `Path Length Constraint: 0`, and OpenSSL 3.5.5's proxy-path validator then **rejects
  the chain** (`verify … -allow_proxy_certs` → *error 20 at depth 0, unable to get local
  issuer certificate*). This is client/tooling-side, **not** a BriX regression — the
  *stock* origin rejects the same proxy direct (BriX out of path), and OpenSSL rejects
  it locally. Mint instead with `gsi_xrdhttp_deleg/mint_alice_proxy.py` (a thin variant
  of `tests/lib/fwd_mint_proxy.py`): it signs an RFC-3820 proxy **on top of the existing
  alice EEC** (`usercert.pem`/`userkey.pem`) with a minimal `id-pe-proxyCertInfo`
  (`id-ppl-inheritAll`, no pathlen, no EKU) — the exact encoding OpenSSL 3.5 accepts.
  The leaf DN `…/CN=Test User/CN=12345/CN=<serial>` still maps to alice via the origin
  gridmap (`…/CN=Test User/CN=12345`). `run_deleg_matrix.sh` and the drivers read this
  proxy from `/tmp/xrd-test/pki/user/proxy_std.pem`; re-mint it (valid 24 h) before a run.

## Result — origin-log verified

Origin login tally across the whole run: **45 `login as alice`, 0 `login as bob`**, and
`nobody` only from the two intentional controls below. The gateway's own unix id (bob)
**never** appears as the origin login.

| client | transport | ops | delegated as alice? |
|---|---|---|---|
| **curl** | WebDAV | MKCOL·PUT·GET·HEAD·PROPFIND(0/1)·range·**checksum(Want-Digest)**·MOVE·DELETE — 14/14 | ✅ every op |
| **PyXRootD** (`xrd.http.dav.HTTPFileSystem`) | davs | mkdir·write·read·exists·stat·getsize·listdir·statx·rm·rmdir — 11/11 | ✅ (needs Python ≥3.10 for `slots=`) |
| **go-hep** (`xrootd/xrdhttp`) | https | MkdirAll·Create·ReadAll·Stat·ReadAt·Statx·Rename·RemoveFile·RemoveDir — 9/9 | ✅ (`WithClientCertificate`+`WithRootCAs`) |
| **XrdRust** (`xrd --cert/--key/--ca-file`) | davs | put·cat·ls·size·check·rm — 6/6 | ✅ — **rebuild with `cargo build --features full`** (default build has no TLS transport) |  <!-- client-flags-allow: `xrd` here is XrdRust, a third-party client that happens to share a name with ours -->
| **XRootD.jl** (`Storage/web.jl`) | davs | mkcol·write·read·stat·range·listdir·move·rm·rmdir — 9/9 | ✅ **now delegates through the front** — Finding 1 fixed (see re-run below) |
| **BriX bundled client** (`client/bin/xrdcp`,`xrdfs` davs) | davs | `xrdcp` put/get + `xrdfs` stat/ls — its whole davs surface | ✅ presents X.509 proxy — **fixed**, Finding 2. Mutating verbs (mkdir/mv/rm) are **root://-only by design** (`xrdfs` prints *"not supported over WebDAV … use a root:// endpoint"*, identically direct-to-origin), not a delegation gap. |

### Re-run 2026-08-05 — Finding 1 resolved on the delegation path, fresh-proxy mint

Re-ran the full matrix through the front (`:21212`) after (a) the Finding-1 operator fix
(`ssl_session_tickets off; ssl_session_cache off;` on the gateway — see Finding 1) and
(b) minting a fresh OpenSSL-3.5-valid alice proxy (see *Proxy minting* above). All five
HTTP-capable clients pass and **`login as bob` stayed 0**:

| client | ops | delegated as alice |
|---|---|---|
| curl | 16/16 (full WebDAV surface incl. subdir MKCOL/MOVE/DELETE) | ✅ |
| PyXRootD (pure-py `xrd`, python3.11 + `PYTHONPATH`) | 11/11 | ✅ |
| go-hep (run inside its module `/root/dev/hep`) | 9/9 | ✅ |
| XrdRust (`/root/dev/XrdRust/.../xrd`) | 6/6 | ✅ |
| **XRootD.jl** | **9/9 — now PASSES through the front** (was fail-closed-to-nobody) | ✅ |
| BriX bundled `xrdcp`/`xrdfs` | put/get/stat/ls | ✅ |

Controls: **negative** — a front request with no client proxy is refused at the TLS layer
(`ssl_verify_client on` → **HTTP 400**), so a delegated identity cannot be spoofed;
**direct-to-origin baseline** (`direct_baseline.sh` → `:21210`, BriX out of path) — every
client authenticates straight to stock XrdHttp+GSI as alice, `nobody +0  bob +0`. Runner:
`gsi_xrdhttp_deleg/run_deleg_matrix.sh`.

**Negative control**: remove the stored `x5h-…pem` → the same alice-proxy ops still get
200/201 at the origin but log `login as nobody` (origin's anonymous fallback), delta of
alice logins = **0**; restore → `login as alice` again. So the alice identity comes
specifically from BriX presenting the delegated proxy, not from the client's own connection.

## Direct-to-origin baseline (control) — every client vs *stock* XrdHttp+GSI

The matrix above is the *delegation* path (client → BriX-as-bob → origin). The complementary
control takes BriX **out** of the path: each client talks straight to the stock XRootD
XrdHttp+GSI origin (`:21210`), presenting alice's own proxy, and the origin's
`http.secxtractor` + `http.gridmap` map the leaf DN → alice directly (no delegation, no back-leg
re-presentation). Driver: `brixbench/gsi_xrdhttp_deleg/direct_baseline.sh` (the three shared
drivers honour `BRIX_DELEG_URL` so the same files drive both paths).

| client | direct → stock origin `:21210` | origin login |
|---|---|---|
| curl (WebDAV) | ✅ PROPFIND 207, GET 200 | alice |
| PyXRootD (`HTTPFileSystem`) | ✅ 11/11 ops | alice |
| go-hep (`xrootd/xrdhttp`) | ✅ 9/9 ops | alice |
| XrdRust (`--features full`) | ✅ ls + size | alice |
| **XRootD.jl** (`Storage/web.jl`) | ✅ **9/9 ops** | alice |
| BriX bundled (`xrdfs` davs) | ✅ stat rc 0 | alice |

Login delta over a full run: **`alice +N  nobody +0  bob +0`**. Two things this pins down:

- **XRootD.jl passes 9/9 directly**, so **Finding 1 is a BriX delegation-path bug, not a
  client↔stock-XrdHttp incompatibility**: straight to the origin there is no delegation step,
  so the origin reads the DN off the leaf the client itself presents and never needs BriX to
  recover the EEC from a resumed TLS session. Finding 1 is real, but its blast radius is the
  reverse-proxy delegation mode only.
- The **bundled BriX client authenticates as alice against *stock* XrdHttp**, re-confirming
  Finding 2's client-cert presentation is not BriX-front-specific.

## Finding 1 — `$brix_delegated_cred` fails closed on a RESUMED TLS session (FIXED)

XRootD.jl's `web.jl` client (Julia HTTP.jl over OpenSSL.jl, pinned to **TLS 1.2** because
its TLS 1.3 lane never answers a CertificateRequest) presents alice's proxy on the front
leg and the front **accepts** it: `code=200 leafDN="CN=12346,…" verify=SUCCESS`. But the
back leg logs `delegated_cred=""` and the origin sees `login as nobody` — a silent
de-privilege.

**Root cause — TLS session resumption, not the chain accessor.** The first request over a
fresh connection delegates fine; the *silent* failures are on **resumed** sessions. A
resumed TLS handshake (session ticket / session-ID cache) re-sends **no** Certificate
message, so both `SSL_get_peer_cert_chain()` *and* `SSL_get0_verified_chain()` come back
empty — only the cached leaf survives. `SSL_get_verify_result()` still reports `X509_V_OK`
(the identity is remembered), so the request passes `ssl_verify_client on`, but there is no
chain left to recover the EEC from → empty variable → fail-closed to anonymous. The tell is
`$ssl_session_reused`: curl logged `reused=.` (full handshakes, delegated fine) while the
Julia client logged `reused=r` on every failing op. curl/PyXRootD/go-hep/XrdRust reuse
less aggressively over these short runs, which is why only the OpenSSL.jl framing surfaced
it — it is **not** a Julia bug (a calibrated `chain_probe.py` — an OpenSSL server with
`VERIFY_ALLOW_PROXY_CERTS` and only the CA trusted, so the handshake succeeds *iff* the
client sent the chaining EEC — accepts the Julia handshake; a leaf-only control is rejected).

BriX's behaviour was already **safe** (never mis-delegates — worst case anonymous, never the
wrong user); the defect was the *silent* de-privilege. **Fix (applied):**

1. **Operator fix — disable resumption on the gateway server block** (the real cure, forces
   a full handshake with a fresh chain on every request):
   ```
   ssl_session_tickets off;
   ssl_session_cache   off;
   ```
   Now baked into `tests/configs/nginx_arc_httpg_proxy.conf` with an explanatory comment.
   With this set, the Julia client delegates as alice on every op (`+9`, all `reused=.`).
2. **Server fix — never de-privilege in silence** (`delegated_cred_find_eec()` /
   `brix_http_delegated_cred_variable()` in `src/protocols/webdav/module_init.c`):
   - the EEC scan is deduped to the shared `delegation_find_eec()` (the same non-proxy scan
     the upload endpoint uses) over the peer chain, then — defense in depth — over
     `SSL_get0_verified_chain()` (the chain OpenSSL rebuilt during verification), gated on
     the `X509_V_OK` already checked upstream so it cannot widen trust;
   - when no EEC can be recovered **and** `SSL_session_reused()` is true, a `WARN` names the
     exact one-line operator fix instead of failing closed silently.
   Unit test: `tests/c/deleg_find_eec_test.c` (runner `deleg_find_eec` in
   `tests/cmdscripts/c_auth_units.py`) — links the real `delegation.o` and covers success
   (EEC found among proxies), error (NULL/empty chain → NULL), and security-negative
   (all-proxy chain → NULL: a proxy is never returned in the EEC's place).

   *Why the verified-chain fallback is not sufficient alone, and resumption must still be
   disabled:* on a resumed session that rebuilt chain is **also** empty, so only step 1
   restores delegation. Step 2 makes a full-handshake edge case robust and, crucially,
   converts the resumed-session failure from silent to logged.

## Finding 2 — the bundled BriX client can now do HTTPS mutual TLS (FIXED)

Previously `client/bin/xrdcp`/`xrdfs` spoke `davs://` but their web-TLS layer
(`brix_tls_client()` in `client/lib/net/tls.c`) did **server verification only** — its
signature carried no client-cert/key, so it presented no X.509 proxy over HTTPS.

**Fix (applied):**
- `brix_tls_client()` gained a `client_cert` parameter; when set it loads the proxy PEM as
  the client cert chain **and** key (`SSL_CTX_use_certificate_chain_file` +
  `SSL_CTX_use_PrivateKey_file` + `SSL_CTX_check_private_key`, fail-closed on any error). A
  GSI proxy PEM holds proxy cert + key + EEC chain in one file, so one path feeds both.
- The parameter is threaded through the whole HTTP-client surface alongside `ca_dir`
  (`httpx_connect`, `brix_http_req`/`download`/`upload`(`_resumable`), `brix_web_stat`/
  `readdir`, `brix_webfile_open`, `brix_webdav_list`/`mkcol`, `brix_kaconn`/`brix_webmeta`).
  S3 paths pass NULL (SigV4, not a client cert — INV-6).
- New resolver `brix_web_proxy_pem()` (`conn.c`) picks the proxy the same way the `root://`
  GSI path does: `$X509_USER_PROXY` → `/tmp/x509up_u<euid>`, returning non-NULL only when the
  file is readable (so plain-https endpoints and no-proxy runs are unaffected — TLS sends a
  client cert only when the server requests one). `xrdcp --proxy` is exported into
  `$X509_USER_PROXY` so the davs leg honours it identically to `root://`; `xrdfs`/`xrootdfs`
  read it from the environment.

**Tests:** `client/tests/c/web_proxy_pem_unit.c` (resolver: success / error-fail-closed /
security-neg env-precedence + NULL-buffer). Live-verified against the mutual-TLS front from
Finding 1 (`ssl_verify_client on`): `xrdfs davs://…:21212 stat /` presenting alice's full
proxy → **HTTP 207, rc 0, real stat** with a clean client-cert verify (no server error line);
with no readable proxy the client presents **no** cert and nginx refuses with 400 (*"client
sent no required SSL certificate"*) — exactly matching curl.

**Adjacent, still open (pre-existing, not this fix):** `xrdcp`'s copy path passes `ca_dir =
NULL` to the davs transport, so *server*-cert verification falls back to the system bundle
instead of `$X509_CERT_DIR`/grid CAs — an https origin with a private/grid CA fails
`unable to get local issuer certificate` (`xrdfs` resolves it and works). That is the
server-verification side, independent of the client-cert presentation fixed here.
