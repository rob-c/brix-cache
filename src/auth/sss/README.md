# sss — Simple Shared Secret authentication (Blowfish-CFB64 + CRC32)

## Overview

SSS (Simple Shared Secret) is XRootD's native symmetric authentication scheme. A
shared secret key is distributed to clients and servers out-of-band (a keytab
file, typically owner-only `0600`); the client encrypts a self-describing
identity credential with Blowfish-CFB64 under that key, and the server decrypts
it, checks integrity and freshness, and extracts the user/group identity. SSS is
the workhorse for production grid sites that cannot deploy x509 certificate
infrastructure, and for trusted server-to-server links. It is selected by
`brix_auth sss` (`BRIX_AUTH_SSS`, value 4) plus an `brix_sss_keytab`
directive.

This subsystem sits on the **stream** (`root://`) authentication path. After the
client `kXR_login`, it sends a `kXR_auth` request whose credential `protocol`
field is `"sss"`; the opcode dispatcher in [`../handshake/`](../handshake/) routes
through [`../gsi/auth.c`](../gsi/auth.c) (`brix_handle_auth`), which dispatches
on credential type to `brix_handle_sss_auth()` in `auth_request.c`. On success
the handler populates `ctx->dn` / `ctx->vo_list` / `ctx->primary_vo`, sets the
unified `ctx->identity` (`BRIX_AUTHN_SSS`), registers the session in
[`../session/`](../session/registry.h), and tracks per-VO / unique-user metrics.

The same credential machinery is reused in two other places. In **proxy mode**,
when an upstream XRootD server demands SSS, [`../proxy/`](../proxy/) calls
`brix_sss_build_proxy_credential()` (`auth_proxy_credential.c`) to mint a
credential *as a client*. In **CMS cluster mode**, the `kYR_xauth` handshake in
[`../cms/`](../cms/) verifies a peer's self-contained SSS blob with the
transport-independent `brix_sss_verify_blob()` (`auth_crypto_helpers.c`), and
loads its keytab through the shared `brix_sss_load_keytab()` (`config.c`).

SSS is purely an auth/identity establishment layer: it issues no I/O, touches no
filesystem path, and returns control to the normal opcode dispatcher once the
session identity is set. Kernel path confinement ([`../path/beneath.c`](../path/))
and ACL enforcement of that identity happen later in [`../path/`](../path/)
(`authdb`, `auth_gate`, VO rules) — never inside this subsystem.

## Files

| File | Responsibility |
|---|---|
| `auth_request.c` | `brix_handle_sss_auth()` — the `kXR_auth` `"sss"` handler. Parses the outer packet, looks up the key by id, decrypts the cleartext, verifies CRC32 + timestamp, parses the identity TLV, applies key policy (`anyuser`/`anygroup`/`usrgroup`/...), sets `ctx->dn`/`vo_list`/`primary_vo`/`identity`, registers the session, emits metrics, and replies `kXR_ok` (or `kXR_authmore` for the interactive SNDLID form). |
| `auth_crypto_helpers.c` | Shared crypto + wire primitives: big-endian read/write (`brix_sss_read_be32`/`be64`, `write_be32`), software `brix_sss_crc32` (poly `0xedb88320`), `brix_sss_bf32_crypt` (Blowfish-CFB64 via OpenSSL EVP, zero IV, no padding, OpenSSL-3 legacy-provider load), key lookup (`brix_sss_find_key`/`find_key_arr`), and the transport-independent verifier `brix_sss_verify_blob` used by CMS. |
| `auth_identity_challenge.c` | Identity TLV parsing and the challenge/failure responses: `brix_sss_parse_identity` (bounds-checked TAG-LEN-VALUE stream → name/grps/host/ip), `brix_sss_copy_packed_string` (overflow-safe field extraction), `brix_sss_auth_failed` (sends `kXR_NotAuthorized`), and `brix_sss_send_authmore` (encrypts a fresh `nobody` LGID challenge for the local-id round-trip). |
| `auth_proxy_credential.c` | `brix_sss_build_proxy_credential()` — builds an outbound `kXR_auth` `"sss"` credential when *this* server acts as an SSS client to an upstream (proxy mode): random nonce + gen-time + NAME TLV → CRC32 → BF32 encrypt → outer header with 8-byte BE key-id. |
| `config.c` | Startup keytab loader/validator: `brix_sss_load_keytab()` (shared by stream + CMS) opens the keytab `O_NOFOLLOW`/`O_CLOEXEC`, checks permissions via the shared `sss_keytab_mode_ok()`, parses each `N:/k:/u:/g:/n:/e:` line via the shared `sss_keytab_parse_line()` into a neutral entry, copies it into `brix_sss_key_t`, sets policy `opts`, and skips expired entries; `brix_configure_sss_auth()` wires it into the per-server config when `auth == BRIX_AUTH_SSS`. |
| `sss_keytab_kernel.c` | Shared, ngx-free keytab text grammar (`sss_keytab_parse_line` line tokeniser/validator + `sss_keytab_mode_ok` permission check). Linked into both the module and the native client (`client/lib/sss_keytab.c`) via libxrdproto, so a client-minted keytab is parsed by the server under identical rules. Hex decode reuses the shared `compat/hex.c` codec. |
| `sss_internal.h` | Cross-file contract: wire-length constants (`BRIX_SSS_HDR_LEN` 16, `BRIX_SSS_DATA_HDR_LEN` 40), `BRIX_SSS_BASE_TIME` epoch, enc/option/TLV-type codes, the `brix_sss_identity_t` decoded-identity struct, and all shared prototypes. |
| `README.md` | This document. |

> Note: this subsystem was reorganized — the historical `auth.c` / `key_parse.c`
> files no longer exist; their logic now lives in `auth_request.c` and `config.c`
> respectively.

## Key types & data structures

- **`brix_sss_key_t`** (defined in [`../types/config.h`](../types/config.h)) —
  one parsed keytab entry: `id` (`int64_t` wire key-id), `exp` (expiry `time_t`,
  0 = never), `opts` (policy bitmask), `key[BRIX_SSS_KEY_MAX]` + `key_len` (raw
  secret, max 128 bytes), and the `name[BRIX_SSS_NAME_MAX]` /
  `user[BRIX_SSS_USER_MAX]` / `group[BRIX_SSS_GROUP_MAX]` strings. Lives in
  `conf->sss_keys` (an `ngx_array_t`).
- **`brix_sss_identity_t`** (`sss_internal.h`) — the identity decoded from a
  credential's TLV body: `name[256]`, `grps[512]` (comma-separated), `host[256]`,
  `ip[128]`, and `id_count` (count of non-random fields; the parser fails if it
  is zero).
- **Wire layout** — outer packet: 4-byte magic `"sss\0"`, 1-byte version, spare,
  `kn_size` (named-key length, must be 8-aligned or 0), enc type
  (`BRIX_SSS_ENC_BF32` = `'0'` at offset 7), 8-byte BE key-id at offset 8,
  optional NUL-terminated key name, then the BF32 ciphertext. Decrypted cleartext:
  32-byte random nonce + 4-byte BE `gen_time` (offset 32) + reserved + 1 option
  byte (`USEDATA`/`SNDLID`) at offset 39, then the identity TLV stream, with a
  4-byte CRC32 appended **before** encryption.
- **Key policy `opts`** ([`../types/tunables.h`](../types/tunables.h),
  `BRIX_SSS_OPT_*`): `ALLUSR` `0x01` / `ANYUSR` `0x02` (take username from the
  credential), `ANYGRP` `0x04` (take groups from the credential), `USRGRP` `0x08`
  (derive group from user → no group set), `NOIPCK` `0x10` (keytab `name` ends in
  `+`). These are set from sentinel keytab values (`anybody`, `allusers`,
  `anygroup`, `usrgroup`). **Distinct from** the *on-the-wire* option byte values
  `BRIX_SSS_OPT_USEDATA` `0x00` / `SNDLID` `0x01` declared in `sss_internal.h`.
- **TLV field types** (`sss_internal.h`): `NAME` `0x01`, `GRPS` `0x04`, `RAND`
  `0x07`, `LGID` `0x10`, `HOST` `0x20`.

## Control & data flow

**Inbound (stream `kXR_auth`):**

1. [`../handshake/`](../handshake/) dispatcher → [`../gsi/auth.c`](../gsi/auth.c)
   `brix_handle_auth` matches credential type `"sss"`, checks
   `conf->auth == BRIX_AUTH_SSS` (`gsi/auth.c:126`), and calls
   `brix_handle_sss_auth(ctx, c, conf)` (`gsi/auth.c:130`).
2. `auth_request.c` validates the outer header, `brix_sss_find_key()` selects
   the key by id, `brix_sss_bf32_crypt(0, ...)` decrypts, CRC32 + `gen_time`
   freshness are checked, and `brix_sss_parse_identity()` extracts the TLV.
3. If the credential's option byte is `SNDLID`, control diverts to
   `brix_sss_send_authmore()` (a `kXR_authmore` challenge) and the client
   re-submits a `USEDATA` credential.
4. On success the handler sets `ctx->dn`/`vo_list`/`primary_vo`, updates
   `ctx->identity` via `brix_identity_set_dn`/`set_vos_csv`
   ([`../types/identity.h`](../types/identity.h)), records metrics through
   [`../metrics/`](../metrics/) (`brix_track_vo_activity`,
   `brix_track_unique_user`), calls `brix_session_register()`
   ([`../session/`](../session/registry.h)), and returns `kXR_ok` via
   `BRIX_RETURN_OK`.

**Outbound (proxy mode):** [`../proxy/`](../proxy/) (`events_bootstrap.c`) calls
`brix_sss_build_proxy_credential()` to encrypt a credential with the local
keytab key (selected via `conf->sss_keyname`, or the first key when empty), then
sends it as a `kXR_auth` to the upstream.

**CMS peer auth:** [`../cms/`](../cms/) (`server_auth.c:72`) calls
`brix_sss_verify_blob(ctx->conf->sss_keys, CMS_SSS_LIFETIME, ...)` to validate a
peer's self-contained credential out of the `kYR_xauth` frame; the keytab itself
is loaded at config time by `brix_sss_load_keytab()` from
[`../cms/`](../cms/) `server_module.c`.

**Startup:** [`../config/postconfiguration.c`](../config/postconfiguration.c)
calls `brix_configure_sss_auth()` alongside the GSI/token loaders; any failure
aborts nginx start (fail-closed).

## Invariants, security & gotchas

- **CRC32, not HMAC — and integer compare, not `memcmp`.** Integrity is a CRC32
  appended to the cleartext *before* encryption. After decrypt it is read as a
  BE `uint32_t` and compared with `got_crc != want_crc` (`auth_request.c:101`,
  `auth_crypto_helpers.c:260`). This is safe: the CRC is not secret — secrecy is
  the Blowfish key — and a mismatch is the **wrong-key / tampering** signal, so
  timing-attack concerns about the compare do not apply.
- **Replay window is mandatory.** `gen_time` (offset 32, in seconds since the
  `BRIX_SSS_BASE_TIME` 2008 epoch that dodges the 2038 32-bit overflow) is
  rejected once `gen_time + lifetime <= now` (`auth_request.c:112`). The stream
  path uses `conf->sss_lifetime`; CMS uses `CMS_SSS_LIFETIME` (3600s).
- **Only self-contained (`USEDATA`) credentials authenticate inbound.** The
  interactive `SNDLID` form triggers a `kXR_authmore` re-challenge on the stream
  path; in `brix_sss_verify_blob()` it is explicitly **`NGX_DECLINED`**, never
  accepted (`auth_crypto_helpers.c:277`).
- **Keytab files must be private — checked at load.** `brix_sss_keytab_mode_ok`
  rejects world bits and (for non-`.grp` files) group bits; the keytab is opened
  `O_NOFOLLOW`+`O_CLOEXEC` and `fstat`'d on the fd to defeat symlink/TOCTOU
  swaps (`config.c:121`, `config.c:375`). Empty / no-usable-key keytabs are a hard
  `NGX_LOG_EMERG` startup error.
- **Fail-closed parsing everywhere.** The TLV parser (`auth_identity_challenge.c`)
  validates every length before advancing the cursor — a missed check would turn
  a malformed credential into an out-of-bounds read. `brix_sss_copy_packed_string`
  clamps to `dst_len-1`; the keytab line parser rejects odd-length hex, oversized
  fields, and non-positive ids. `brix_sss_bf32_crypt` rejects `key_len == 0`
  and `> INT_MAX` lengths. `brix_sss_verify_blob` bounds its decrypt scratch to
  an 8 KiB on-stack buffer (`clear[8192]`) and rejects oversized ciphertext.
- **Decrypted plaintext is wiped.** Every decrypt site `OPENSSL_cleanse()`s the
  scratch buffer so identity bytes do not linger in the pool / on the stack
  (`auth_request.c:145`, `auth_crypto_helpers.c` error + success paths).
- **`auth == BRIX_AUTH_SSS` is enforced twice.** The dispatcher rejects `"sss"`
  unless SSS is the configured mode (`gsi/auth.c:126`), and `config.c` only loads
  a keytab in that mode — SSS is not silently usable alongside other schemes.
- **nginx discipline:** stream-path allocation uses the connection pool
  (`ngx_palloc(c->pool, ...)`); responses are framed via
  `brix_build_resp_hdr` + `brix_queue_response` ([`../response/`](../response/)),
  never raw writes. Wire strings reaching logs go through
  `brix_sanitize_log_string`. The keytab loader runs at config time and is the
  *only* place blocking file I/O (`open`/`fgets`/`fstat`) is permitted — never on
  a live connection.

## Entry points / extending

- **Add a new keytab field:** add a `case` in `brix_sss_parse_key_line()`
  (`config.c`) switching on the field prefix char; extend `brix_sss_key_t`
  ([`../types/config.h`](../types/config.h)) if it needs new state; keep unknown
  fields ignored for keytab compatibility but fail-closed on malformed *required*
  fields (`N:` id, `k:` key).
- **Add a new identity TLV type:** add the constant to `sss_internal.h` and a
  `case` in `brix_sss_parse_identity()` (`auth_identity_challenge.c`); remember
  non-`RAND` fields must increment `id_count` to count as a valid identity.
- **Add a new key policy option:** define `BRIX_SSS_OPT_*` in
  [`../types/tunables.h`](../types/tunables.h), set it from a sentinel
  user/group/name value in `brix_sss_parse_key_line()`, and apply it where
  `key->opts` is consulted in `auth_request.c`.
- **Reuse SSS over a new transport:** call `brix_sss_verify_blob()` (verify) or
  `brix_sss_build_proxy_credential()` (mint) — they are transport-independent
  and allocate nothing; do not re-implement the decrypt/CRC/replay chain.

## See also

- [`../gsi/`](../gsi/) — credential-type dispatch (`brix_handle_auth`) and the
  x509/GSI auth path.
- [`../token/`](../token/) — WLCG/JWT bearer-token auth (distinct auth domain).
- [`../krb5/`](../krb5/), [`../unix/`](../unix/), [`../voms/`](../voms/) — sibling
  authentication schemes.
- [`../session/`](../session/) — session registry populated after auth.
- [`../cms/`](../cms/) — CMS `kYR_xauth` peer authentication (reuses SSS verify).
- [`../proxy/`](../proxy/) — outbound SSS as a client to upstream servers.
- [`../path/`](../path/) — kernel confinement + ACL/VO enforcement of the
  established identity.
- [`../config/`](../config/) — `postconfiguration.c` startup wiring.
- [`../README.md`](../README.md) — master subsystem index.
