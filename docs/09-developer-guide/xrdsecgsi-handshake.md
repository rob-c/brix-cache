# Implementing the real XrdSecgsi handshake (client & server)

> **Status (2026-06-21):** the **native client** speaks real XrdSecgsi and
> authenticates to stock servers — `./client/xrdfs root://eoslhcb.cern.ch ls
> /eos/lhcb` lists the directory, identical to `/usr/bin/xrdfs`. This documents
> the protocol, every wire-format detail, and **every gotcha that cost an
> iteration**, so the remaining work (the v≥10400 signed-DH path and the
> *server* side) is mechanical. Reference source: `/tmp/xrootd-src/src`
> (`XrdSecgsi/`, `XrdCrypto/`, `XrdSut/`).

This is the single most intricate wire protocol in the XRootD stack. Read it
before touching `src/auth/gsi/` or `client/lib/sec/sec_gsi.c`.

---

## 1. Why this was needed

Our GSI was a *mutually-compatible-but-non-standard* implementation: the native
client only ever talked to our own server and vice-versa, so neither spoke real
XrdSecgsi. Symptom: `./client/xrdfs root://eoslhcb.cern.ch ls /eos/lhcb` failed
with *"unauthorized identity used"* while stock `xrdfs` worked with the same
proxy.

**Diagnosis** (forcing one protocol at a time):
- `--auth gsi` → `Secgsi: ErrParseBuffer: main buffer missing: kXGC_certreq` —
  the server rejected our **first** message.
- `--auth unix` → the exact user-visible error. So in the default
  gsi→token→krb5→sss→unix chain, **GSI failed and the client silently fell back
  to `unix`**, presenting the local UNIX identity → EOS rejected it.

The fix is a from-scratch port of XrdCryptossl + XrdSecgsi, because even our
server was non-standard (it emitted `kXRS_puk` as a bare DH key, not the full
`XrdCryptosslCipher::Public()` serialization). All new primitives live in the
**shared** `src/auth/gsi/gsi_core.c`, which compiles into both `libxrdproto.a` (the
client) and the nginx module (the server) — one source of truth.

---

## 2. The protocol at a glance

XrdSecgsi is a 2-round (for the cert exchange) challenge-response over an
`XrdSutBuffer` framing, establishing a Diffie-Hellman session cipher and proving
the client owns its proxy by signing a server-issued random tag.

```
  CLIENT (proxy)                                         SERVER (host cert)
       │                                                       │
       │  R1  kXGC_certreq                                     │
       │  cryptomod·version·issuer_hash·clnt_opts              │
       │  main{ rtag_C }  ── keep rtag_C for §6 ──────────────▶│
       │                                          R2 builds DH params + key
       │  R2  kXGS_cert                                        │
       │  cipher_alg·md_alg·server x509·server DH public       │
       │◀── main{ rtag_S, sign(rtag_C) } ── main is CLEAR ─────│
       │                                                       │
   derive session cipher = DH(server pub, my priv)             │
   AES key = first keylen bytes of the shared secret           │
   prove possession: sign(rtag_S) with PROXY private key       │
       │                                                       │
       │  R2' kXGC_cert                                        │
       │  cryptomod·MY DH public·cipher_alg                    │
       │  ENC main{ proxy chain, sign(rtag_S), rtag_C2 } ─────▶│
       │                              derive same key, decrypt main,
       │                              verify sign(rtag_S) vs proxy chain,
       │                              verify chain → trusted CA, map DN
       │◀────────────────── kXR_ok  AUTHENTICATED ─────────────│
       ▼                                                       ▼
   rtag = random tag (anti-replay)   ·   sign() = RSA over RAW bytes, no digest
```

Two protocol variants, gated by version (`XrdSecProtocolgsi.hh`):
`XrdSecgsiVersDHsigned = 10400`, current `XrdSecgsiVERSION = 10600`.

| | **v < 10400 (unsigned, IMPLEMENTED)** | **v ≥ 10400 (signed-DH, PENDING)** |
|---|---|---|
| Server DH public bucket | `kXRS_puk` (plain `Public()` blob) | `kXRS_cipher` (the `Public()` blob **RSA-signed** with the server cert key — client `DecryptPublic`s it) |
| Client DH public bucket | `kXRS_puk` (plain) | `kXRS_cipher` (RSA-signed with the **proxy** key, `EncryptPrivate`) |
| `HasPad` (DH derive `dh_pad`) | **0** | **1** |
| `useIV` (per-message IV) | **0** (zero IV, not prepended) | **1** (fresh IV prepended) |

**The version is the master switch.** The server adapts to the *client's*
advertised `kXRS_version`. Our hand-rolled client controls both sides of the
decode, so advertising `v:10300` makes a modern server use the far simpler
unsigned path — which is how the implemented client works against EOS today.

---

## 3. The XrdSutBuffer wire framing

Every message (and the nested `main`) is an `XrdSutBuffer`
(`XrdSut/XrdSutBuffer.cc::Serialized`):

```
"gsi\0"                      protocol name, NUL-terminated  (4 bytes)
<step:int32 BE>             e.g. kXGC_certreq=1000, kXGC_cert=1001, kXGS_cert=2001
repeat: <type:int32 BE><size:int32 BE><data[size]>          one per bucket
```

**Gotcha #7 — length-delimited, NO terminator.** `Serialized` writes *no*
`kXRS_none` at the end; the buffer length bounds it. Our `xrootd_gbuf_end`
appends a 4-byte `kXRS_none` (type only, no size field) — fine for a *top-level*
buffer the peer scans by type, but inside an **encrypted main** it is mis-read as
a malformed bucket and the deserialize drops the real buckets → *"client
certificate missing"*. **Build the inner main without `gbuf_end`.**

Bucket type codes (`src/protocol/gsi.h`): `kXRS_cryptomod=3000`, `main=3001`,
`puk=3004`, `cipher=3005`, `rtag=3006`, `signed_rtag=3007`, `version=3014`,
`clnt_opts=3019`, `x509=3022`, `issuer_hash=3023`, `cipher_alg=3025`,
`md_alg=3026`. Steps: `kXGC_certreq=1000`, `kXGC_cert=1001`, `kXGS_cert=2001`.

---

## 4. Round 1 — the certreq (`xrootd_gsi_build_certreq`)

The first client message. **Gotcha #1:** a bare `"gsi\0"+kXGC_certreq` is
rejected (*"main buffer missing: kXGC_certreq"*) — the certreq opcode and the
client random tag must be **inside a nested `kXRS_main`**:

```
OUTER (step kXGC_certreq):
  kXRS_cryptomod  = "ssl"
  kXRS_version    = <int32 BE>          echo the server's advertised v: (or 10300)
  kXRS_issuer_hash= "<hash>.0|<hash>.0" echo the server's ca: list
  kXRS_clnt_opts  = 0x00000080          int32 BE
  kXRS_main       = NESTED buffer:
        "gsi\0" + kXGC_certreq
        + kXRS_rtag(8 random bytes)      ← retained for §6 mutual-auth
        + kXRS_none
```

`v:`, `c:`, `ca:` come from the gsi protocol `parms`
(`v:10600,c:ssl,ca:5168735f.0|4339b4bc.0`) the auth driver passes —
`xrootd_gsi_parse_parms` extracts them.

---

## 5. The session cipher — `XrdCryptosslCipher`, byte-exact

The hardest part. All in `gsi_core.c`; unit-tested by `tests/c/gsi_cipher_test.c`.

**Fixed DH parameters.** Both ends use ONE hard-coded 3072-bit safe-prime group
(`XrdCryptosslCipher.cc::dh_param_enc`), embedded verbatim as
`xrootd_gsi_dh_params_pem`. **Gotcha #2:** our old code used `ffdhe2048` and
derived against *our* params, not the peer's → *"no/garbled server DH key"*. The
peer sends its params in the PEM; we key off **those**.

**Wire form = `Public()` (NOT `AsBucket()`).** `XrdSecProtocolgsi.cc:1605` builds
the `kXRS_puk`/`kXRS_cipher` bucket from `sessionKey->Public()`:

```
<PEM "DH PARAMETERS" block, incl. "-----END DH PARAMETERS-----\n">
"---BPUB---"  <DH public key as BN_bn2hex, UPPERCASE>  "---EPUB---"
```

(`AsBucket()` — 7 host-endian int32 lengths + type+IV+buffer+p+g+pub+pri hex — is
the *local/stored* form, e.g. a session file; never the wire form.)

**Session key.** `EVP_PKEY_derive` the shared secret, then **the AES-128 key is
its first 16 bytes** (`XrdCryptosslCipher.cc` L580-620: it `SetBuffer(ldef=16,
ktmp)`). **Gotcha #4:** the derive's `dh_pad` must equal the peer's `HasPad` —
**0 for v<10400**, 1 otherwise — or the leading secret bytes differ and the key
is wrong (*"error decrypting main buffer"*). `xrootd_gsi_cipher_session_key`
takes a `padded` flag.

**Symmetric encryption.** `aes-128-cbc`, standard **PKCS#7** padding (XrdCrypto
`EncDec` does *not* `set_padding(0)`). **Gotcha #5:** tell the server which
cipher you used — include `kXRS_cipher_alg = "aes-128-cbc"` in round-2, else it
defaults to `bf-cbc`. **Gotcha #6 — the IV (the subtlest):** `useIV` is true only
for v≥10400. For the unsigned path **the IV is 16 zero bytes and is NOT
prepended**. If you prepend a random IV anyway, CBC means only the *last*
plaintext block depends on… the previous ciphertext block, so its PKCS padding
still validates and decrypt "succeeds" — but the *first* block (holding
`"gsi\0"`+step+the start of the x509 bucket) is garbage, so the server parses a
bufferful of nonsense → *"client certificate missing"*. `*_encrypt/_decrypt` take
a `use_iv` flag: 1 = random IV prepended, 0 = zero IV, nothing prepended.

---

## 6. Round 2 — proof of possession (`gsi_more`, unsigned path)

The server's `kXGS_cert` carries `kXRS_puk` (its DH public), `kXRS_x509` (its
cert), `kXRS_cipher_alg`, and a `kXRS_main`. **Gotcha #8 — the server main is in
CLEAR**, because at this step the server has no session key yet (it needs our
public, which we send in the response). So parse it directly for the server's
`kXRS_rtag` — do **not** decrypt it.

Proof of possession = **sign the server's rtag with the proxy private key**
(`XrdCryptosslRSA::EncryptPrivate` = `EVP_PKEY_sign` with `RSA_PKCS1_PADDING`
over the **raw** rtag bytes, no message digest — `xrootd_gsi_rsa_sign_raw`). The
proxy file (`$X509_USER_PROXY` or `/tmp/x509up_u<uid>`) holds the cert chain
**and** the RSA private key (`PEM_read_bio_PrivateKey`).

Build the response `kXGC_cert`:
```
INNER main (NO kXRS_none terminator — §3 #7):
  kXRS_x509        = the proxy cert chain (concatenated PEM, certs only)
  kXRS_signed_rtag = the server's rtag, RSA-signed with the proxy key
  kXRS_rtag        = a fresh 8-byte tag
  → encrypt with the session key, use_iv=0
OUTER (step kXGC_cert):
  kXRS_cryptomod = "ssl"
  kXRS_puk       = OUR Public() blob
  kXRS_cipher_alg= "aes-128-cbc"
  kXRS_main      = the encrypted inner
```
The server derives the same session key from our `kXRS_puk`, decrypts the main,
verifies the signed rtag against the proxy chain (which it verifies to a trusted
CA), maps the DN → `kXR_ok`. Done.

> `signing_active` (kXR_sigver request signing) is left off — `ls`/dirlist work
> without it. A read (`xrdcp`) from a redirector like EOS then redirects to a
> data server (a fresh handshake) — out of scope for the auth fix.

---

## 7. Shared architecture & the primitives

Everything is in `src/auth/gsi/gsi_core.{c,h}` → compiled into **both** the client
(`shared/xrdproto/libxrdproto.a`) and the server (the nginx module, via the root
`config`). New primitives:

- `xrootd_gsi_parse_parms` / `xrootd_gsi_rand` / `xrootd_gsi_build_certreq` (R1)
- `xrootd_gsi_cipher_keygen` / `_public` / `_parse_peer` / `_session_key(padded)`
  / `_encrypt(use_iv)` / `_decrypt(use_iv)` (the cipher)
- `xrootd_gsi_rsa_sign_raw` (EncryptPrivate / proof of possession)

Client glue is `client/lib/sec/sec_gsi.c` (`gsi_first`, `gsi_more`).

---

## 8. How to debug it (the iteration loop)

Crypto fails opaquely ("AuthFailed"), so a **local stock-xrootd GSI server** is
essential — far faster than hitting EOS, and the error message *advances* one
gotcha at a time. `tests/test_native_gsi_interop.py` self-provisions exactly this
(throwaway CA + host cert + proxy + `sec.protbind * only gsi`); the standing
manual rig lives at `/tmp/gsi_interop` (port 21094). The loop:

```
make -C shared/xrdproto && make -C client xrdfs
X509_CERT_DIR=/tmp/gsi_interop/certs X509_USER_PROXY=/tmp/gsi_interop/user/proxy.pem \
  ./client/xrdfs --auth gsi root://$(hostname -f):21094 ls /gsidata
```

Watch the server's `AuthFailed` text — it names exactly which check failed
(`main buffer missing` → R1; `no/garbled server DH key` → cipher parse;
`error decrypting main buffer` → key/pad/IV; `client certificate missing` →
IV/terminator/main framing; `certificate chain verification failed` →
PKI/proxy). Stock `xrdfs` with the same env is the reference success. **Kill the
manual :21094 server before running the pytest** (its fixture self-provisions on
21094).

Two regression tests pin this forever: `tests/test_gsi_cipher.py` (the cipher
math, no live peer) and `tests/test_native_gsi_interop.py` (the keystone: native
client auths to a real XrdSecgsi server).

---

## 9. The signed-DH path (v ≥ 10400) — DONE, both directions

Both the unsigned (default, universally compatible) and the RSA-signed-DH paths
now interoperate with the official tools in **all four directions**:
`./client/xrdfs` ↔ stock `xrootd`, *and* stock `xrdfs`/`xrdcp` ↔ our nginx
server, for both version paths. Regression tests:
`tests/test_native_gsi_interop.py` (`test_stock_client_signed_dh`,
`test_native_client_signed_dh`).

### 9a. The wire difference (signed vs unsigned)

```text
  UNSIGNED  (v < 10400, default)        SIGNED-DH  (v ≥ 10400)
  ─────────────────────────────         ───────────────────────────
  DH public bucket:                      DH public bucket:
    kXRS_puk = Public() blob               kXRS_cipher = RSA-sign(Public())
    (sent in the clear)                    sender signs w/ its cert key;
                                           receiver DecryptPublic()s w/
                                           the sender cert public key
  dh_pad = 0  (HasPad)                    dh_pad = 1
  IV     = 16 zero bytes,                 IV     = fresh 16 bytes,
           NOT prepended                           prepended to AES-CBC main
  AES key = first keylen bytes of the DH secret  ── same for both ──
  bucket TYPE (puk vs cipher) is what signals the variant to the peer
```

The sender RSA-signs its `Public()` blob with its cert private key
(`XrdCryptosslRSA::EncryptPrivate`, chunked by `key_size − 11`) into
`kXRS_cipher`; the receiver `DecryptPublic`s it with the sender's cert public
key (`verify_recover`, chunked by `key_size`). The session then uses `HasPad=1`
(dh_pad=1) and `useIV=1` (a fresh 16-byte IV prepended to the AES-CBC main).
The unsigned (`< 10400`) path sends the bare `Public()` as `kXRS_puk`,
`dh_pad=0`, zero IV (nothing prepended). The bucket *type* signals the variant;
the AES key is the first *keylen* bytes of the DH secret either way.

### 9b. The server side (`src/auth/gsi/`)
- **Round 1** (`cert_response.c`): when the handshake is signed
  (`ctx->gsi_signed_dh`, see 9c), RSA-sign the same `Public()` blob with the host
  key and emit it as `kXRS_cipher` instead of `kXRS_puk`. The client recovers it
  with the host cert it also receives in `kXRS_x509`. The pooled `ffdhe2048` key
  is reused (no parameter sensitivity — see the cipher gotcha below).
- **Round 2** (`parse_x509.c` → `xrootd_gsi_parse_x509_signed`): recover the
  client's `Public()` from its signed `kXRS_cipher` using the proxy public key it
  sends in `kXRS_puk` (`DecryptPublic`), derive the **padded** DH secret
  (`set_dh_pad(1)`), AES-128 key = first 16 bytes, decrypt the **IV-prepended**
  main, then extract the proxy chain exactly as the unsigned path does.
- The version the server advertises in `login.c`'s `&P=gsi,v:…` block drives the
  client's signed-vs-unsigned decision (10000 = unsigned, 10600 = signed-capable).

### 9c. Configurability — `xrootd_gsi_signed_dh off|auto|require`
A stream `server{}` directive (`src/stream/module.c`,
`src/core/types/config.h` `gsi_signed_dh`):
- `off` (default) — always emit unsigned `kXRS_puk`; advertise `v:10000`.
  Interoperates with every official client.
- `auto` — advertise `v:10600`; sign for clients whose certreq `kXRS_version`
  is ≥ 10400, fall back to unsigned otherwise.
- `require` — advertise `v:10600`; signed only.

### 9d. The gotchas that cost the most (read before touching this)
1. **Cipher negotiation, NOT the DH params, is the subtle killer.** The client
   picks the **first** cipher in the *server's* advertised `kXRS_cipher_alg`
   list that it can instantiate. Our server originally advertised
   `aes-256-cbc:aes-128-cbc:bf-cbc`, so stock `xrdfs` chose **aes-256-cbc**
   (32-byte key) while our signed decrypt keyed a 16-byte **aes-128** session →
   every pad/IV combination failed the CBC padding check with a *correct* DH
   secret. Fix: advertise `aes-128-cbc` **first** (also stock's `DefCipher`
   order), so every peer keys a 16-byte aes-128 session. Symptom to recognise:
   the recovered peer public is valid and the secret derives, yet the main
   decrypt fails for *all* pad/IV combinations — that is a cipher/key-length
   mismatch, not a DH mismatch.
2. **The server must advertise `v:10600`** (`login.c`) or the stock client never
   switches to the signed path — it stays unsigned, looks for `kXRS_puk`, and
   reports `server public part for session cipher missing`.
3. **RSA round-trips are a matched pair.** `our-client ↔ our-server` passing
   proves *nothing* about stock compatibility (our encrypt/decrypt invert each
   other regardless of format). Only `stock ↔ ours` in *both* directions does.
4. **`DecryptPublic` succeeding means the recovery was exact** (PKCS#1 verify
   checks padding); if it returns > 0 the recovered public is correct — look
   elsewhere (the cipher) for a secret mismatch.

## 10. Test coverage

- `tests/test_gsi_cipher.py` — C unit vectors for the shared cipher/RSA
  primitives (`gsi_core.c`): DH agreement through the wire round-trip, AES
  encrypt/decrypt, certreq, `EncryptPrivate`/`DecryptPublic` recover.
- `tests/test_native_gsi_interop.py` — the keystone interop (our client ↔ stock
  server; stock client ↔ our server, unsigned and signed).
- `tests/test_gsi_bridge.py` — cross-server GSI transfers (our nginx ↔ a stock
  `xrootd`).  Self-healing: an autouse fixture starts a reference `xrootd` on
  `REF_PORT` (11099) when the harness has not, so the suite never hangs or
  skips on missing infrastructure.
- `tests/test_gsi_handshake.py` — **comprehensive, self-contained** (76 cases,
  **zero skips** — every prerequisite is a hard `assert`).  Drives every
  observable handshake stage with both the official tools (stock `xrdfs`/`xrdcp`,
  `curl`) and our native client (`client/bin/xrd{fs,cp}`, built on demand by an
  autouse fixture):
  - `root://` ls/stat/read/write **plus 5 MiB large I/O and
    mkdir/rmdir/mv/query-checksum** across all `xrootd_gsi_signed_dh` policies
    (`off`/`auto`/`require`) — read and write together prove the session cipher
    in both directions over many AES-CBC blocks.
  - **GSI followed by an in-protocol TLS upgrade** (`roots://`, `xrootd_tls on`)
    read + write.
  - **concurrent handshakes** (12 in parallel, per policy) — the ephemeral-DH
    keypool must answer every certreq without head-of-line blocking.
  - protocol-version advertisement (`off` → `v:10000`, signed → `v:10600`,
    observed via the stock client's `XrdSecDEBUG` token dump).
  - DN/identity extraction from the verified proxy chain (the server log
    escapes the space, so the DN reads `…CN=Test\x20User…`).
  - negatives — a proxy from an untrusted CA, an expired credential, no
    credential, and a client that distrusts the server host cert: all refused.
  - native client ↔ a real stock `xrootd` GSI server (ls + read + write).
  - **auth enforcement** — unauthenticated read *and* write are refused.
  - **cross-server** transfer (our nginx ↔ a stock `xrootd`, GSI both ends).
  - extra authenticated ops — truncate, cat.
  - **wire-level** — drive the handshake by hand over a raw socket and inspect
    the bytes: the `&P=gsi,v:…,c:ssl,ca:…` login advertisement (version per
    policy), and the kXGS_cert bucket structure (server cert + `aes-128-cbc`-first
    cipher list + `kXRS_puk` unsigned vs `kXRS_cipher` signed), including the
    per-client version gate (a v10300 certreq downgrades `auto` to unsigned).
  - **kXR_sigver enforcement** — at `security_level intense` GSI auth completes
    (pre-key) then the first protected op is refused (3010) for lacking a
    signature, proving enforcement is wired to `signing_key = SHA-256(DH secret)`.
  - **RSA-4096** host + proxy keys through the signed-DH handshake (the RSA
    sign/recover chunking at a larger modulus), stock *and* native client.
  - **VOMS** — a fake VOMS proxy (`voms-proxy-fake` + an LSC vomsdir) carrying a
    VO is admitted to a `require_vo`-gated path while the plain (no-VO) proxy is
    refused, proving the server extracts the VOMS attribute (stock + native).
  - **`xrootd_auth both`** — the GSI client selects gsi from a `&P=ztn…&P=gsi…`
    advertisement (stock + native), and the wire advertisement carries both.
  - more query opcodes (config / locate / stat-q), a spread of file sizes
    (0/1/16/17/9973/65537 bytes) over the session cipher, a deeper wire check
    (kXGS_cert offers a sha256 digest; login carries an 8-hex CA hash), and
    concurrent HTTPS proxy-cert requests.
  - `https://` WebDAV with the **same** x509 proxy over TLS client-cert auth
    (`xrootd_webdav_proxy_certs`): PROPFIND/GET/PUT/HEAD/DELETE/MKCOL/COPY/MOVE/
    OPTIONS/range/Depth-1/4 MiB with a proxy, and the rejections (no cert /
    untrusted / expired — any non-2xx).

All 220 GSI tests across the seven files above pass with **zero skips**.

**S3 is deliberately excluded.** S3 — ours (`src/protocols/s3/`) and the official
`XrdS3` — authenticates with AWS SigV4 only; GSI does not apply. A guard test
(`test_s3_uses_sigv4_not_gsi`) pins that invariant; SigV4 coverage is in
`tests/test_s3_*.py`.
