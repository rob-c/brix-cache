# `client/lib/sec/` — native client authentication modules

## Overview

The client-side XRootD `kXR_auth` protocol modules — one per credential type. Each
builds the credential and drives its handshake against the nginx-xrootd server
dialect, with **no libXrdSec dependency** (pure C). The shared DH / session-cipher /
bucket math used by the crypto-bearing modules (GSI, pwd) lives in the common
`gsi_core` (compiled into both this client and the server module), so these files
are mostly orchestration plus their protocol-specific framing.

`client/lib/auth.c` selects which module to offer based on what the server
advertises, trying strongest-first; the weak host/unix/pwd schemes are preferred
**last** and are intended for trusted/closed networks (under TLS).

## Files

| File | Protocol | Rounds | Notes |
|---|---|---|---|
| `sec.h` | — | — | The module interface shared by all schemes. |
| `sec_gsi.c` | `gsi` (X.509 proxy) | 2 | The dominant WLCG auth: DH key exchange + AES-256-CBC-wrapped proxy PEM. Math in `gsi_core`. |
| `sec_token.c` | `ztn` (WLCG bearer/JWT) | 1 | Discovers a JWT (`$BEARER_TOKEN`, `$BEARER_TOKEN_FILE`, runtime-dir, `/tmp/bt_u<uid>`); no crypto (TLS provides confidentiality). |
| `sec_sss.c` | `sss` (shared secret) | 1 | Pre-shared symmetric key from a keytab; assembles the exact BF32 credential the server decoder expects. |
| `sec_krb5.c` | `krb5` (Kerberos 5) | 1 | AP-REQ from the default credential cache (a `kinit` TGT), libXrdSec-free. |
| `sec_pwd.c` | `pwd` (password) | 2 | DH-session-encrypted password (`$XRDC_PWD` / stock creds blob). Trusted networks under TLS only. |
| `sec_host.c` | `host` | 1 | Asserts no identity; the server reverse-resolves the peer. Weakest scheme. |
| `sec_unix.c` | `unix` | 1 | Sends the local username; the server trusts it only for loopback peers. |

## Invariants

- **No libXrdSec.** Every credential is built from first principles here +
  `gsi_core` + libxrdproto primitives (e.g. `xrootd_sha256`).
- **Strongest-first selection** with the spoofable/cleartext-adjacent schemes
  (`host`, `unix`, `pwd`) preferred last — see `client/lib/auth.c`.
- **Wire-exact framing.** Each payload matches the server decoder byte-for-byte
  (the `XProtocol.hh kXR_auth` credtype tag + the scheme's body); the per-file
  header docblocks cite the exact server-side counterpart.

## See also

- `../README.md` — the `libxrdc` library overview.
- Server side: [`src/auth/gsi/`](../../../src/auth/gsi/), [`src/auth/token/`](../../../src/auth/token/),
  [`src/auth/sss/`](../../../src/auth/sss/), [`src/auth/krb5/`](../../../src/auth/krb5/).
