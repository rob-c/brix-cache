# gsiftp:// GridFTP — GSI-secured data channel (deep dive)

> **Scope.** Everything learned bringing the GridFTP gateway's **data channel**
> up to full GSI security (DCAU + `PROT P`), proven with the real
> `globus-url-copy` client. Companion to the plan in
> [../refactor/phase-82-gridftp-gateway.md](../refactor/phase-82-gridftp-gateway.md).
> Code: `src/protocols/gridftp/ftp_handler.c`, `src/auth/gssapi/gsi_mech.{c,h}`.
> Tests: `tests/test_gridftp_gsiftp.py` (7/7 green, incl. `-dcpriv` GET+PUT).
>
> The last section compares this design head-to-head with the `root://`
> (XRootD) protocol plane, because the two make **opposite** structural choices
> for the same job (authenticated, encrypted bulk transfer over the VFS).

---

## 1. What GridFTP actually is

`gsiftp://` is **FTP (RFC 959) + RFC 2228 security + a second TCP connection
for the payload**. Unlike a modern single-socket protocol, GridFTP splits
control from data onto physically separate connections:

```
                        globus-url-copy  (client)
                          │            │
        control channel   │            │   data channel(s)
        (commands/replies)│            │   (file bytes only)
                          ▼            ▼
   ┌───────────────────────────┐  ┌───────────────────────────┐
   │ TCP :2811-ish             │  │ TCP :ephemeral (PASV)      │
   │ USER / STOR / RETR / LIST │  │ raw file bytes, no verbs   │
   │ AUTH GSSAPI / ADAT / PROT │  │ opened per transfer        │
   └───────────────────────────┘  └───────────────────────────┘
              gateway (brix_gridftp STREAM module, ftp_handler.c)
```

Two independent security decisions ride on top:

| Layer            | Command      | What it protects                         | This gateway |
|------------------|--------------|------------------------------------------|--------------|
| Control channel  | `AUTH GSSAPI`+`ADAT` | commands, replies, credential delegation | ✅ (was already done) |
| Data channel     | `DCAU` + `PROT` | the actual file bytes                     | ✅ **this work** |

Before this work the control channel was fully GSI-secured but the **data leg
was cleartext** (`globus-url-copy -nodcau`). Now `-dcpriv` (DCAU A + PROT P)
gives an authenticated, encrypted data channel end to end.

---

## 2. The control channel (context — already working)

The RFC 2228 security handshake is a **TLS 1.2 handshake tunnelled inside
base64 `ADAT` tokens** on the FTP control channel, followed by GSI credential
delegation folded into the same tunnel. Driven by
`brix_gssapi_srv_*` (`src/auth/gssapi/gsi_mech.c`).

```
 client                                              gateway (ftp_handler.c)
   │  AUTH GSSAPI                                        │
   │ ─────────────────────────────────────────────────► │  334 (proceed)
   │                                                     │
   │  ADAT <base64(TLS ClientHello…)>                    │   ┐
   │ ═══════════════════════════════════════════════════│   │ TLS 1.2 handshake,
   │ ◄══ 335 ADAT=<base64(ServerHello, Cert, …)> ════════│   │ each flight carried
   │ ═══ ADAT=<base64(Cert, Finished)> ═════════════════►│   │ as a base64 ADAT arg
   │ ◄══ 335 ADAT=<base64(Finished)> ════════════════════│   ┘  (pinned to TLS 1.2 —
   │                                                     │      1.3 flight shape
   │  ── GSI delegation sub-exchange (app-data) ──       │      breaks 335/235)
   │  'D' ►  ◄ proxy-cert REQUEST  ►  signed proxy       │   → brix_gsi_assemble_proxy
   │ ◄══ 235 ADAT=<final token> ═════════════════════════│      = delegated credential
   │                                                     │
   │  every later command now GSS-wrapped:               │
   │  ENC <base64> ─►  ◄─ 633 <base64>                    │   sec_active = 1
```

Two artefacts survive the handshake and are the **inputs to data-channel
security**:

* `fc->ctrl_dn`   — the verified end-entity subject DN (the user's identity).
* `fc->deleg_proxy` — the **delegated credential** PEM the client handed us,
  shaped `<proxy cert><issuer chain><private key>` by `brix_gsi_assemble_proxy`.

Captured in `ftp_gss_finalize()`.

---

## 3. The data channel — DCAU + PROT decoded empirically

Everything below was determined by packet/behaviour observation against the
real globus client, not from a spec read. Three facts, each of which became a
fix.

### 3.1 Fact #1 — `PROT P` is straight TLS on the data socket

The GridFTP data channel for `PROT P` is **not** globus-token-framed. The
client opens the TLS session with a **raw ClientHello** (`16 03 01 …`) directly
on the data socket. The server just runs ordinary OpenSSL:

```
  PASV data socket (already TCP-accepted)
        │
        ▼
   ftp_data_secure(fc, dfd):
        SSL_new(tls_ctx)
        ftp_load_deleg_cred(ssl)          ← present the USER's cred (§3.2)
        SSL_set_fd(ssl, dfd)
        SSL_set_accept_state(ssl)         ← server = TLS acceptor
        SSL_set_max_proto_version(TLS1_2) ← match control-channel pin
        SSL_set_options(IGNORE_UNEXPECTED_EOF)  ← (§3.3)
        SSL_accept(ssl)                   ← raw ClientHello, no framing
        … verify peer, bind identity …
   then SSL_read / SSL_write for the bytes.
```

`DCAU N` / `PROT C` keep the legacy cleartext path (a bare `read`/`write` on
`dc->fd`); the gateway still advertises and honours both.

### 3.2 Fact #2 — the server presents the *delegated user credential*, not the host cert

DCAU authenticates the data channel as **the user on both ends**. globus checks
the data peer's name against the control-channel identity. If the server offers
its **host cert**, globus rejects it:

```
  error: the name of the remote entity
         (/DC=test/DC=xrootd/CN=localhost)                 ← host cert  ✗
     and the expected name
         (/DC=test/DC=xrootd/CN=Test User/CN=12345)        ← the user
     do not match
```

So `ftp_load_deleg_cred()` loads `fc->deleg_proxy` (the credential the client
delegated over the control channel) onto the data-channel `SSL`: leaf proxy via
`SSL_use_certificate`, issuer chain via `SSL_add1_chain_cert`, private key via
`SSL_use_PrivateKey`. The server literally acts *as the user* on the data leg.

After the handshake the gateway does the mirror check on the client's
data-channel cert — verify against the CA store **and** require the DN to equal
`fc->ctrl_dn`, so a CA-valid third party cannot hijack the transfer:

```
   SSL_accept done
        │
        ├─ leaf  = SSL_get_peer_certificate(ssl)
        ├─ chain = SSL_get_peer_cert_chain(ssl)
        ├─ brix_gsi_verify_chain(ca_store, leaf, chain) ── must be OK
        └─ res.dn_buf == fc->ctrl_dn ?  ── else 425, drop.
```

### 3.3 Fact #3 — GridFTP stream mode signals EOF by *closing*, without close_notify

There is **no length framing** on the raw data channel. End-of-data = the
sender closes the connection. globus closes it **without** a TLS `close_notify`.
OpenSSL 3.x reports that abrupt close as `SSL_R_UNEXPECTED_EOF_WHILE_READING`
(an `SSL_ERROR_SSL`), which killed a STOR *after every byte had arrived*:

```
  brix DBG stor read=16384 sslerr=0     ┐ all 24000 bytes
  brix DBG stor read= 7616 sslerr=0     ┘ received fine
  brix DBG stor read=   -1 sslerr=1     ← SSL_ERROR_SSL on the close → 550 ✗
```

Fix: `SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF)` on the data SSL, so
the abrupt close reads back as a clean EOF (`SSL_ERROR_ZERO_RETURN` → our
`ftp_dc_read` returns `0`). This matches GridFTP stream-mode semantics exactly
(close *is* the EOF marker; there is nothing else to truncate).

---

## 4. The certificate-chain gotcha (the subtle one)

This is the bug that ate the most time and is worth its own section.

When the server presents the delegated credential, globus must be able to build
a path from our leaf up to a trusted CA. The delegated PEM's identity ladder:

```
   CN=Test User            (EEC — end-entity cert, the human)
      └─ CN=12345           (proxy)
            └─ CN=12346      (proxy  ← the client's CONTROL-channel leaf)
                  └─ CN=1812454284   (the delegated proxy we present as leaf)
```

To verify our leaf `CN=1812454284`, globus needs its **direct issuer**
`CN=12346`, then `CN=12345`, then the CA.

**The trap:** on the *server* side, OpenSSL's `SSL_get_peer_cert_chain()`
**excludes the peer's own leaf** (you must fetch the leaf separately via
`SSL_get_peer_certificate()`). So when we captured the client's presented chain
during control-channel delegation, `CN=12346` — which was the client's *leaf* —
was silently missing. The assembled `deleg_proxy` chain had a hole:

```
  BROKEN chain we presented                FIXED chain
  ─────────────────────────                ───────────
  leaf : CN=1812454284                      leaf : CN=1812454284
  chain: CN=12345          ✗ gap            chain: CN=12346   ◄── re-added
  chain: CN=Test XRootD CA   (CN=12346         chain: CN=12345
                              missing)         chain: CN=Test XRootD CA

  globus: "certificate verify failed"      globus: verifies, transfer proceeds
```

**The fix** threads the missing leaf out of the GSSAPI layer and back into the
data channel:

```
  control-channel handshake              data-channel handshake
  ───────────────────────                ───────────────────────
  gsi_mech.c:                            ftp_handler.c:
    SSL_get_peer_certificate(g->ssl)       ftp_load_deleg_cred():
      = client leaf CN=12346                 SSL_use_certificate(leaf CN=1812454284)
        │                                     SSL_clear_chain_certs()
        │  brix_gssapi_srv_peer_cert_pem()    ┌─ SSL_add1_chain_cert(ctrl_leaf_pem)  ← FIRST
        ▼                                     │      = CN=12346  (the recovered issuer)
    ftp_gss_finalize():                       ├─ SSL_add1_chain_cert(CN=12345)
      fc->ctrl_leaf_pem = <PEM> ──────────────┘  SSL_add1_chain_cert(CA)
```

New public function (declared in `gsi_mech.h`):

```c
/* the client's control leaf — the delegated proxy's direct issuer, and NOT
 * part of the server-side SSL_get_peer_cert_chain(). */
ngx_int_t brix_gssapi_srv_peer_cert_pem(brix_gssapi_srv_t *g, ngx_str_t *out);
```

---

## 5. End-to-end sequence: `globus-url-copy -dcpriv` PUT

Putting §2–§4 together for a STOR (upload). GET is the mirror image with the
data arrows reversed and the EOF signalled by *our* `SSL_shutdown`.

```
 client (globus)                                    gateway (ftp_handler.c)
 ───────────────                                     ──────────────────────
  AUTH GSSAPI / ADAT …  ══════ TLS-in-tokens ══════►  ftp_gss_finalize():
                                                        fc->ctrl_dn
  (delegates credential 'D' …)                          fc->deleg_proxy
                                                        fc->ctrl_leaf_pem   ← §4
  ◄──── 235 auth complete ─────────────────────────
  PBSZ 1048576         ─────────────────────────────►  200
  DCAU A               ─────────────────────────────►  200 DCAU A
  PROT P               ─────────────────────────────►  200 Protection = Private
  PASV                 ─────────────────────────────►  227 (h,p,p) listen socket
       └── TCP connect data socket ────────────────►  ftp_data_accept() → dfd
  STOR secure-up.bin   ─────────────────────────────►  150 Opening BINARY
                                                        ftp_data_secure(fc, dfd):
  raw TLS ClientHello  ══════════════════════════════►   SSL_accept (present
  ◄════ ServerHello + delegated-user cert chain ═════     delegated USER cred)
  ══════ client proxy cert ══════════════════════════►   verify vs CA + DN==ctrl_dn
                                                        ── handshake OK ──
  ══════ SSL_write(file bytes) ══════════════════════►   ftp_dc_read → brix_vfs_pwrite
  ══════ … ═══════════════════════════════════════════►  …
  close (no close_notify)  ── FIN ───────────────────►   IGNORE_UNEXPECTED_EOF
                                                          → read()==0 → done  ← §3.3
  ◄──── 226 Transfer complete ─────────────────────
```

---

## 6. TLS roles on the data channel

A recurring source of confusion; here is the settled truth for this gateway
(PASV mode, which is what globus uses by default):

| Aspect                     | Value                                    |
|----------------------------|------------------------------------------|
| Who TCP-connects the data socket | **client** (server is in PASV listen) |
| Who is TLS **acceptor**    | **server** (`SSL_set_accept_state`) — both GET and PUT |
| Who is TLS **initiator**   | **client** (raw ClientHello) — both GET and PUT |
| Server's presented identity | the **delegated user proxy**, not the host cert |
| Client's presented identity | the user's control-channel proxy         |
| Mutual auth                | yes — `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` + post-handshake DN pin |
| TLS version                | pinned **1.2** (matches the control-channel GSI pin) |
| EOF marker                 | connection close (GET: our `SSL_shutdown`; PUT: client FIN, `IGNORE_UNEXPECTED_EOF`) |

The role is fixed by *who connects the TCP*, not by data direction — so STOR and
RETR use the identical `SSL_set_accept_state` path. (The earlier hypothesis that
DCAU reverses TLS roles by data direction turned out to be **wrong**; the STOR
failure was the EOF gotcha, not a role mismatch.)

---

## 7. Code map

| Concern | File · function |
|---|---|
| Control-channel GSI handshake + delegation | `auth/gssapi/gsi_mech.c` · `brix_gssapi_srv_step` |
| Expose client control leaf (the fix in §4) | `auth/gssapi/gsi_mech.c` · `brix_gssapi_srv_peer_cert_pem` |
| Capture DN / deleg cred / control leaf | `gridftp/ftp_handler.c` · `ftp_gss_finalize` |
| Load delegated cred onto data SSL | `gridftp/ftp_handler.c` · `ftp_load_deleg_cred` |
| Bring up + verify data-channel TLS | `gridftp/ftp_handler.c` · `ftp_data_secure` |
| Data-channel read/write/close abstraction | `gridftp/ftp_handler.c` · `ftp_dc_read` / `ftp_dc_write` / `ftp_dc_close` |
| PROT / DCAU / PBSZ verb handling | `gridftp/ftp_handler.c` · `ftp_dispatch` |
| Transfer drivers (VFS both ends) | `gridftp/ftp_handler.c` · `ftp_retr_file` / `ftp_stor_file` / `ftp_list_dir` |

`ftp_dc_t { int fd; SSL *ssl; }` is the small seam that lets every transfer
driver be written once and run over either cleartext (`ssl==NULL`) or TLS.

---

## 8. Comparison with the `root://` (XRootD) protocol

The two planes solve the same problem — authenticated, encrypted bulk transfer
funnelled through the same `brix_vfs_*` storage seam — with **opposite**
structural choices. This is the most instructive part of the whole exercise.

### 8.1 Connection topology

```
   gsiftp:// (GridFTP)                     root:// (XRootD)
   ───────────────────                     ────────────────
   TWO sockets, asymmetric roles           ONE socket, everything multiplexed

   ┌── control (verbs) ──┐                 ┌──────────────────────────────┐
   │ AUTH/PROT/STOR/RETR │                 │ single TCP/TLS connection    │
   └─────────────────────┘                 │ kXR_login → kXR_auth →        │
   ┌── data (bytes) ─────┐                 │ kXR_open/read/write/pgread…  │
   │ new socket / xfer   │                 │ requests AND payload interleaved│
   └─────────────────────┘                 └──────────────────────────────┘
   handler: ftp_handler.c                  handler: connection/handler.c
   (blocking, synchronous dialogue)        (async recv/send state machine)
```

### 8.2 Where TLS lives

```
  gsiftp control:  TLS *inside* base64 ADAT tokens (TLS-in-application-data),
                   pinned 1.2, driven by a mem-BIO OpenSSL in gsi_mech.c.
  gsiftp data:     a SECOND, independent raw TLS session on the data socket
                   (this document). Two separate TLS contexts per transfer.

  root (roots://): ONE in-band TLS upgrade on the single socket
                   (connection/tls.c), negotiated via kXR_protocol tls flags.
                   Same session carries auth and payload. One TLS handshake.
```

GridFTP can run **two full TLS handshakes per transfer** (control tunnel + data
socket); root runs **one** for the whole session.

### 8.3 Identity & credential model

| | gsiftp (this work) | root:// |
|---|---|---|
| Auth mechanism | RFC 2228 GSSAPI/GSI over ADAT | `kXR_auth` sec plugins: `gsi`, `sss`, `ztn`/tokens |
| Credential delegation | **built in** — client delegates a proxy the server re-uses | none in-band; TPC uses separate token/credential flows |
| Data-channel identity | server **impersonates the user** (presents the delegated proxy) | data rides the same authenticated session — no second identity |
| Peer-identity pin | data DN must equal control DN (`ctrl_dn`) | single session identity; nothing to cross-check |
| Where enforced | `ftp_data_secure` (post-handshake) | auth gate at dispatch boundary |

The GridFTP "server presents the user's own credential on the data channel" is a
genuinely unusual model — the server is briefly *acting as the user* to a third
party. root has no analogue because there is no second channel and no delegation.

### 8.4 Framing & EOF

```
  gsiftp data:  NO framing. Raw bytes. EOF = connection close.
                → needs IGNORE_UNEXPECTED_EOF, close-as-EOF semantics (§3.3).

  root:         fully framed. 24-byte request header + dlen payload; responses
                framed; pgread/pgwrite use kXR_status(4007) with per-page
                CRC32c (INVARIANT 1). Length is always known; a short read is
                an error, not an EOF.
```

This is the crux: GridFTP's lack of data-channel framing is *why* the EOF gotcha
exists at all. root cannot have that bug — every transfer is length-delimited
and integrity-checked page by page.

### 8.5 Integrity

| | gsiftp | root:// |
|---|---|---|
| In-flight confidentiality | TLS (PROT P) | TLS (roots://) |
| In-flight integrity of payload | TLS record MAC only | TLS **plus** kXR pgread/pgwrite CRC32c per 4 KiB page |
| Length/truncation protection | **none at app layer** (stream mode) | explicit dlen per frame |

### 8.6 Concurrency model

* **gsiftp** — the `ftp_handler.c` dialogue is **blocking/synchronous**: accept
  data socket, handshake, pump, close, reply, all inline. Simple to reason
  about; one transfer at a time per control connection (MODE E parallel streams
  are a future phase).
* **root** — an **async recv/send state machine** (`connection/recv.c`,
  `write_helpers.c` out_ring FIFO) driven by nginx events; many requests in
  flight on one socket.

### 8.7 Shared foundation

Despite the divergence, both planes bottom out on the **same** invariants:

* All storage through `brix_vfs_*` (INVARIANT 11/12) — `ftp_retr_file` /
  `ftp_stor_file` use `brix_vfs_open`/`pread_full`/`pwrite_full` exactly like the
  root read/write handlers. No raw file I/O in either protocol tree.
* Path resolved through the VFS seam before any open (INVARIANT 4).
* Same CA store / `brix_gsi_verify_chain` for GSI verification.

### 8.8 One-line summary

> **root** multiplexes authenticated, framed, CRC-checked payload over a single
> in-band-TLS connection. **gsiftp** splits verbs and bytes across two sockets,
> delegates the user's credential so the server can *become* the user on a
> second raw-TLS data socket whose only EOF signal is the connection closing.
> Same VFS underneath; opposite plumbing on top.

---

## 9. Test coverage

`tests/test_gridftp_gsiftp.py` (phase-81 `LifecycleHarness`, real
`globus-url-copy`), **7/7**:

```
  test_list_directory          LIST over wrapped control channel
  test_get_roundtrip           RETR, cleartext data (-nodcau)
  test_put_roundtrip           STOR, cleartext data (-nodcau)
  test_get_roundtrip_dcpriv    RETR, GSI-encrypted data (-dcpriv)   ← this work
  test_put_roundtrip_dcpriv    STOR, GSI-encrypted data (-dcpriv)   ← this work
  test_get_missing_object_fails  error path
  test_untrusted_ca_rejected     security-negative (handshake refused)
```

Run (note the Python-3.9 pytest gotcha — use a 3.10+ interpreter):

```
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python3 -m pytest tests/test_gridftp_gsiftp.py -p no:xdist -q
```

---

## 10. Gotcha cheat-sheet

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | data DN ≠ user name | server offered host cert | present `deleg_proxy` on data SSL |
| 2 | "certificate verify failed" on data channel | `SSL_get_peer_cert_chain()` drops the peer leaf → delegated chain missing its direct issuer `CN=12346` | `brix_gssapi_srv_peer_cert_pem` → `ctrl_leaf_pem` → prepend as first chain cert |
| 3 | STOR 550 after *all* bytes arrive | globus closes data socket without `close_notify`; OpenSSL 3.x → `SSL_R_UNEXPECTED_EOF_WHILE_READING` | `SSL_OP_IGNORE_UNEXPECTED_EOF` on data SSL |
| 4 | pytest "mass regression" at collection | `pytest` entrypoint is Python 3.9; newer test files use 3.10+ syntax | run under `python3` 3.10+ |
