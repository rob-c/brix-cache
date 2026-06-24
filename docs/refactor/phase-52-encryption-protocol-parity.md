# Phase 52 — XRootD security/encryption-protocol parity (server + native client)

**Status:** (2026-06-23). **WS-A DONE + stock-verified** (table-driven GSI cipher
negotiation; 113 GSI handshake tests green **including native↔stock both
directions**, cipher unit test passes).  **WS-C (host) DONE** (server + native
client + login advertisement; build-clean, config parses).  **WS-B (pwd) DONE,
our-client↔our-server** (2-round DH-bootstrapped XrdSecpwd password flow, PBKDF2
credential verify; 5 end-to-end tests green — download, upload, wrong-password,
unknown-user, no-credential).  Remaining: full stock-XrdSecpwd byte-interop
(pre-shared srvpuk + 3-RT mutual rtag) — documented in
[phase-52-pwd-wire-spec.md](phase-52-pwd-wire-spec.md).

### WS-B — `pwd` (XrdSecpwd) implemented (server + native client)

- `XROOTD_AUTH_PWD=8` / `XROOTD_AUTHN_PWD=0x80` / `XROOTD_METRIC_AUTH_PWD=8`.
- Server `src/pwd/auth.c` (2-round handshake) + `src/pwd/pwdfile.c` (PBKDF2 verify).
  Round 1 exchanges DH publics (reusing the shared `gsi_core` cipher) + the asserted
  user; round 2 decrypts `kXRS_main` and checks the credential
  (PBKDF2-HMAC-SHA1, 10000 iters, 24 B — the exact stock KDF) against
  `xrootd_pwd_file`.  Opt-in (`xrootd_auth pwd`), empty pwd-file = deny all, and
  the password never touches disk in cleartext.  Advertised as `&P=pwd,v:10100,c:ssl`.
- Client `client/lib/sec/sec_pwd.c` sources the password non-interactively from
  `XRDC_PWD` (or the stock `XrdSecCREDS` hex blob), user from `XRDC_PWD_USER`/`USER`.
- **TLS-gated by intent:** the credential is recoverable by the server and only
  DH-session-encrypted on the wire — `pwd` is for trusted/closed networks under TLS.
  Tried LAST in the client preference order; selected only when advertised.

### WS-A.1 — XrdSecgsi `useIV` interop rule (interop bug found + fixed)

A non-standard `#<ivlen>` cipher-name suffix was introduced this session to signal
IV-prepend; it **broke native→stock GSI** (stock's `EVP_get_cipherbyname(
"aes-128-cbc#16")` fails → "client certificate missing: kXGC_cert"). Root cause
from the XrdSecgsi source: `useIV = (RemVers >= XrdSecgsiVersDHsigned/10400)` — IV
usage is decided **purely from the negotiated peer version, independently on both
sides**; the wire cipher name is **bare** and the IV length is the cipher's own
`MaxIVLength()` (16 for aes-cbc). **Fix:** client emits the bare cipher name
(`sec_gsi.c`); the server signed-DH path (`parse_x509.c`) strips the IV
unconditionally (`use_iv = 1` — that path only runs for ≥10400); removed the
`gsi_client_iv_len`/`#N` helper. The unsigned (<10400) path keys the raw secret with
a zero IV. Result: byte-for-byte interop restored both directions.

### WS-C — `host` auth implemented (server + native client)

- `XROOTD_AUTH_HOST=7` / `XROOTD_AUTHN_HOST=0x40` / `XROOTD_METRIC_AUTH_HOST=7`.
- `src/host/auth.c`: reverse-resolves the peer (`xrootd_acc_resolve_peer`) and
  matches `xrootd_host_allow` (exact host or `.suffix` patterns); **fail-closed**
  (empty/unset allowlist denies). Dispatched from `src/gsi/auth.c` on credtype
  `host`; advertised in `src/session/protocol.c`; registered in `config`.
- Client: `client/lib/sec/sec_host.c` (sends `"host\0"`+FQDN, tried **last**),
  wired into both module lists in `client/lib/auth.c` and `client/Makefile`.
- Off-by-default (requires `xrootd_auth host` + a non-empty `xrootd_host_allow`);
  hostname/DNS is spoofable → intended for closed networks behind TLS only.

### WS-A — implemented (decision: full table-driven rewrite)

- Shared `src/gsi/gsi_core.{c,h}`: cipher descriptor + allowlist
  (`aes-128-cbc`/`aes-256-cbc`/`bf-cbc`/`des-ede3-cbc`), runtime-resolved via
  `EVP_get_cipherbyname` (bf/3des need the OpenSSL-3 legacy provider, loaded
  best-effort); `xrootd_gsi_cipher_lookup`/`_pick`; `session_key` now derives
  `key_len` bytes; `encrypt`/`decrypt` take the descriptor (native IV length).
  `aes-128-cbc` stays first → the proven default + stock interop is byte-identical.
- Server signed-DH path (`src/gsi/parse_x509.c`) honours the client's
  `kXRS_cipher_alg` choice (the unsigned path already did); no-bucket default
  changed aes-256→aes-128 (`parse_crypto_helpers.c`).
- Client (`client/lib/sec/sec_gsi.c`) picks the first supported cipher from the
  server's advertised list and echoes it; TPC outbound keys aes-128.
- Server advertises a configurable + *filtered* list
  (`xrootd_gsi_ciphers`, default aes-128 first) — only ciphers it can key.
- Tests: `tests/c/gsi_cipher_test.c` round-trips all resolvable ciphers (passes).
- **Remaining for WS-A:** an end-to-end test where our client negotiates a
  non-default cipher (server `xrootd_gsi_ciphers "aes-256-cbc:..."`); stock
  xrdcp/xrootd interop per-cipher (needs a stock harness pinned to each cipher).

(original plan follows)

---

**Drafted:** 2026-06-23
**Scope:** the XrdSec **security protocols** and the GSI **session-cipher/digest
negotiation**, on both the server (`src/`) and the native client (`client/`).
**Hard requirement:** byte-for-byte interop with official XRootD `xrootd`/`xrdcp`
in BOTH directions (our client ↔ stock server, stock client ↔ our server).

---

## 1. Context & motivation

XRootD authenticates with a **negotiated security protocol**: after `kXR_login`
the server advertises a `&P=<proto>,args` list and the peer picks one it supports
(`XrdSec/XrdSecPManager.cc`). The official protocol set is:

| Proto | What it authenticates | Session crypto | Notes |
|---|---|---|---|
| `gsi` | X.509 proxy cert + VOMS | **negotiated cipher** (AES/BF/3DES) + digest | modern, primary |
| `ztn` | WLCG/SciToken bearer JWT | requires TLS | modern |
| `krb5` | Kerberos 5 ticket | Kerberos-internal | common |
| `sss` | pre-shared key table | Blowfish32 (implicit) | intra-grid |
| `unix` | self-asserted UID/GID | none | weak/loopback |
| `pwd` | username + password | DH+RSA session key | **legacy/deprecated** |
| `host` | hostname only | none | **weak**, implicit fallback |

Within `gsi`, XrdCrypto's `ssl` factory negotiates a **symmetric session cipher**
from a configurable list (default `aes-128-cbc:bf-cbc:des-ede3-cbc`,
`XrdSecgsi/XrdSecProtocolgsi.cc`) carried in the `kXRS_cipher_alg` handshake
bucket, plus a **digest** (`sha256:md5`). TLS (`roots://`) is a *separate*
transport (`XrdTls/`), orthogonal to XrdSec.

### 1.1 Already implemented here (server + client — do NOT redo)

| Capability | Server | Client |
|---|---|---|
| `gsi` (x509 + VOMS, DH, RSA signed-DH, OCSP) | `src/gsi/`, `src/crypto/` | `client/lib/sec/sec_gsi.c` |
| `ztn` (token/JWT/macaroon) | `src/gsi/auth.c`→`src/token/` | `client/lib/sec/sec_token.c` |
| `sss` (Blowfish-CFB64 + replay check) | `src/sss/` | `client/lib/sec/sec_sss.c` |
| `unix` (loopback-gated) | `src/unix/auth.c` | `client/lib/sec/sec_unix.c` |
| `krb5` (AP_REQ, compile-gated) | `src/krb5/auth.c` | `client/lib/sec/sec_krb5.c` |
| TLS transport (`roots://`, `kXR_*TLS`) | `src/connection/tls.c` | `client/lib/tls.c` |
| Protocol-list advertise + negotiate | `src/session/protocol.c:151-176` | `client/lib/auth.c:22-44` |

### 1.2 Gaps to "support all"

1. **GSI session-cipher/digest negotiation is hardcoded.** `src/gsi/gsi_core.c`
   uses `EVP_aes_128_cbc()` (lines ~537/573) regardless of the negotiated
   `kXRS_cipher_alg`, and the advertised string (`parse_crypto_helpers.c`) is a
   fixed token. It interoperates today *only because* `aes-128-cbc` is the default
   first cipher — a stock peer configured to require `aes-256-cbc`, `bf-cbc`, or
   `des-ede3-cbc`, or a non-default digest, would fail. This is the **highest-value
   interop gap.**
2. **`pwd` (XrdSecpwd) — MISSING** on both server and client (no `"pwd"` credtype).
   Legacy/deprecated (transmits passwords; weak trust model).
3. **`host` — MISSING** on both sides (hostname-only; spoofable; XRootD treats it
   as an implicit weak fallback).

---

## 2. Recommendation & prioritisation

- **WS-A (GSI cipher/digest negotiation) is the only gap with real modern-interop
  value** — implement it first. It hardens parity with any stock GSI deployment.
- **WS-B (`pwd`) and WS-C (`host`) are legacy/weak.** Implement for completeness if
  "support all" is a hard goal, but **off by default, opt-in, with loud security
  caveats** (pwd ≈ plaintext-password trust; host ≈ hostname spoofing). Many
  modern sites disable both. Recommend gating them behind explicit directives and
  documenting that WLCG/grid deployments should not enable them.
- No wire-format invention anywhere — every byte matches the XrdSec/XrdCrypto spec
  in `/tmp/xrootd-src/src/XrdSec*`, `/tmp/xrootd-src/src/XrdCrypto`.

---

## 3. Workstreams

### WS-A — Full GSI session-cipher + digest negotiation (server + client)

The session key is derived as the first *keylen* bytes of the (padded) DH shared
secret; the cipher + digest are chosen from a negotiated list. Make this
table-driven instead of hardcoded AES-128.

- **A1. Cipher descriptor table** (`src/gsi/` shared, used by server + client):
  map each XrdCrypto cipher name → `{ EVP_CIPHER*, key_len, iv_len, block }` for
  `aes-128-cbc` (16B), `aes-256-cbc` (32B), `bf-cbc` (16B, variable-key Blowfish),
  `des-ede3-cbc` (24B). Replace the hardcoded `EVP_aes_128_cbc()` in
  `gsi_core.c`'s encrypt/decrypt with a `(EVP_CIPHER*, keylen)` parameter; derive
  the session key length from the descriptor (must match XrdCrypto's key-from-DH
  derivation incl. the `dh_pad` padding + signed-DH IV handling already present).
- **A2. Digest descriptor**: select the MD (`sha256` / `md5`) used for the
  signing-key derivation + RSA-signed-DH hash from the negotiated value (the
  `kXR_sigver` HMAC path in `parse_crypto_helpers.c` must use the chosen MD).
- **A3. Server side**: a configurable advertised cipher/digest list
  (`xrootd_gsi_ciphers "aes-256-cbc:aes-128-cbc:bf-cbc:des-ede3-cbc"`,
  `xrootd_gsi_digests "sha256:md5"`, defaults matching stock), emit it in the
  `kXGS_init` `kXRS_cipher_alg` bucket, and use the cipher the client selected in
  its `kXGC_cert` response. Keep the phase-48 "advertise the to-be-used cipher
  first" gotcha (memory `gsi_signed_dh_server`).
- **A4. Client side** (`client/lib/sec/sec_gsi.c`): parse the server's advertised
  cipher/digest list (already partially read into debug), pick the first mutually
  supported entry, and encrypt the `kXGC_cert` payload with it.
- **A5. Reuse**: the descriptor table + key-derivation live in the shared
  `src/gsi/gsi_core.*` (dual-built into server and client — the established seam),
  so server and client stay byte-identical.

### WS-B — `pwd` (XrdSecpwd) password protocol (server + client, opt-in)

Mirror the stock handshake (`/tmp/xrootd-src/src/XrdSecpwd/`): DH+RSA session-key
setup, then password verification; optional server-public-key (`srvpuk`) mutual
check and random-tag signing.

- **B1. Server**: new `src/pwd/` auth handler routed from `xrootd_gsi_auth.c`'s
  credtype dispatcher on `"pwd"`; password store backed by a hashed password file
  (NOT `/etc/shadow`; a dedicated `xrootd_pwd_file`), `xrootd_auth pwd` mode,
  `XROOTD_AUTH_PWD` enum value, advertise `"pwd "` in `src/session/protocol.c`.
  Reuse the GSI DH/cipher table from WS-A for the session key.
- **B2. Client**: `client/lib/sec/sec_pwd.c` — credential sourcing (`.xrd/pwd`
  file or prompt), DH exchange, password send under the negotiated cipher; add to
  the `client/lib/auth.c` preference list (LAST — below all stronger protocols).
- **B3. Security gates**: refuse `pwd` unless the connection is TLS (or an explicit
  `xrootd_pwd_allow_cleartext on`); loud startup warning; document the weak model.

### WS-C — `host`-based auth (server + client, opt-in)

- **C1. Server**: accept the implicit `host` protocol — authenticate by the peer's
  reverse-resolved hostname against an allowlist (`xrootd_auth host` +
  `xrootd_host_allow <pattern>...`), `XROOTD_AUTH_HOST` enum, advertise `"host"`.
  Reuse the XrdAcc reverse-DNS path (`src/acc/resolve.c`, now breaker-bounded) for
  the lookup. Fail-closed when DNS is unavailable.
- **C2. Client**: trivial — present the `host` credential (hostname) when the
  server advertises it and no stronger protocol matched.
- **C3. Security gate**: off by default; warn that hostname auth is spoofable
  without DNSSEC/TLS-pinned peers.

### WS-D — Tests + docs (interop is the whole point)

- **D1. Cipher matrix interop** (WS-A): drive a stock `xrootd` server configured
  for each of `aes-256-cbc` / `bf-cbc` / `des-ede3-cbc` and each digest, and prove
  our client authenticates; and a stock `xrdcp` client (forced to each cipher via
  `XrdSecGSICIPHER`/`XrdSecGSIMD`) against our server. Reuse the gated
  real-XrdCl/stock-tooling pattern (memory `native_client_gsi_interop`,
  `pyxrootd_isolation_worker`). Plus our-client ↔ our-server for each cipher.
- **D2. `pwd`/`host`**: success + wrong-password/denied-host negative + the
  security-gate (cleartext refused without TLS) tests.
- **D3. Negotiation edge cases**: no mutually-supported cipher → clean auth
  failure (not a crash); server advertises N, client offers M, intersection picked.
- **D4. Docs**: `docs/04-protocols/` security-protocol matrix; update
  `CLAUDE.md` ROUTING/auth notes; `contrib/xrootd.conf.example` for the new
  directives with security caveats.

---

## 4. Files to create / modify (representative)

- GSI cipher/digest (WS-A): `src/gsi/gsi_core.{c,h}` (cipher descriptor + key
  derivation), `src/gsi/parse_crypto_helpers.c` (advertise/parse list),
  `src/gsi/cert_response.c` (server pick), `client/lib/sec/sec_gsi.c` (client
  pick); directives in `src/config/server_conf.c` + `src/stream/module.c`.
- `pwd` (WS-B): new `src/pwd/`, `client/lib/sec/sec_pwd.c`, dispatcher in
  `src/gsi/auth.c`, advertise in `src/session/protocol.c`, enum in
  `src/types/tunables.h`, `client/lib/auth.c` order; register new `.c` in `config`
  + `client/Makefile`, run `./configure`.
- `host` (WS-C): `src/host/` (or fold into `src/unix/`), `client/lib/sec/sec_host.c`,
  same dispatch/advertise/enum wiring.
- Tests (WS-D): `tests/test_gsi_cipher_matrix.py` (extend existing
  `tests/test_gsi_cipher.py`), `tests/test_pwd_auth.py`, `tests/test_host_auth.py`.

## 5. Verification

```bash
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
# (client) cd client && make

# GSI cipher matrix — our client vs stock server forced to each cipher, and
# stock xrdcp (XrdSecGSICIPHER=aes-256-cbc, =bf-cbc, =des-ede3-cbc) vs our server:
PYTHONPATH=tests pytest tests/test_gsi_cipher_matrix.py -v
# pwd / host (opt-in):
PYTHONPATH=tests pytest tests/test_pwd_auth.py tests/test_host_auth.py -v
# Full auth interop regression must stay green:
PYTHONPATH=tests pytest tests/ -k "gsi or sss or krb5 or token or unix or auth" -q
```

Manual: `XrdSecGSICIPHER=aes-256-cbc XrdSecPROTOCOL=gsi xrdcp root://<our-server>//f /tmp/x`
(stock xrdcp) must succeed; `./client/bin/xrdcp root://<stock-xrootd>//f /tmp/x`
with the stock server requiring aes-256-cbc must succeed.

---

## 6. Decisions for the operator (raise before building WS-B/WS-C)

- Is full GSI cipher negotiation (WS-A) sufficient, or are `pwd`/`host` genuinely
  required? They are legacy/weak and most modern (WLCG) sites disable them.
- If `pwd`/`host` are wanted, confirm the off-by-default + TLS-gated posture.
