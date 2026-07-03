# pwd — password (`XrdSecpwd`) authentication for the `root://` stream protocol

## Overview

This subsystem implements the XRootD **`pwd`** security protocol (the wire
equivalent of upstream `XrdSecpwd`) for `root://`/`roots://` clients. A client
authenticates with a username + password, exchanged as a 2-round,
Diffie-Hellman-bootstrapped handshake so the credential is never sent in the
clear on the wire. It is one of several pluggable stream credential types
(`gsi`, `token`, `sss`, `unix`, `krb5`, `pwd`, `host`), all dispatched from the
single `kXR_auth` handler in `../gsi/auth.c`.

`pwd` is XRootD's legacy password scheme. It is **opt-in and fail-closed**: it
must be explicitly selected (`brix_auth pwd`), requires `brix_pwd_file`
(empty = deny all), and **should run only under TLS** — the credential is only
DH-session-encrypted on the wire, and the server recovers the plaintext to verify
it. The password database stores only a salt + a PBKDF2 hash, never cleartext.
Isolating the scheme here keeps the password surface in one auditable place.

In the request lifecycle this sits at the **stream login/auth stage**. After the
handshake and `kXR_login`, the client sends a `kXR_auth` request whose credential
type is `pwd`; the dispatcher in `../gsi/auth.c` calls `brix_handle_pwd_auth()`
here, which drives the two rounds. The key agreement and `kXRS_main` encryption
reuse the shared GSI DH + session-cipher primitives in `../gsi/gsi_core.c`. Only
the `root://` stream path uses it.

## The two-round exchange

```
round 1  client → kXRS_puk(client DH pub) + kXRS_user
         server → kXR_authmore: kXRS_puk(server DH pub) + credsreq
round 2  client → kXRS_main = DH-session-encrypted { kXRS_creds }
         server → kXR_ok iff PBKDF2(password, salt) == stored hash
```

## Files

| File | Responsibility |
|---|---|
| `auth.c` | `brix_handle_pwd_auth(ctx, c, conf)` — drives the two-round exchange. Static helpers: `pwd_status_word` (bucket status packing), `pwd_send_credsreq` (round-1 `kXR_authmore` reply with the server DH pub + creds request), `pwd_round1` (parse client pub + user, agree the session key), `pwd_round2` (decrypt `kXRS_main`, extract the credential, verify, set identity/session/metrics). |
| `pwdfile.c` | `brix_pwd_file_lookup()` + `brix_pwd_verify()` — load a user's salt + stored hash from `brix_pwd_file` (`user:salthex:hashhex`) and verify a presented plaintext via `PKCS5_PBKDF2_HMAC_SHA1` (10000 iters, 24 B) + a constant-time compare. KDF is byte-identical to stock `XrdSecpwd`. No allocation; fixed buffers; pure libc + OpenSSL. Static helpers: `pwd_from_hex`, `pwd_parse_line`. |
| `pwd.h` | Shared declarations for the two files (the `pwdfile` lookup/verify prototypes). |

The public entry point `brix_handle_pwd_auth` is declared in
`../ngx_brix_module.h`; `brix_pwd_file` and the `auth` selector live on
`ngx_stream_brix_srv_conf_t`. Wire details: `docs/refactor/phase-52-pwd-wire-spec.md`.
