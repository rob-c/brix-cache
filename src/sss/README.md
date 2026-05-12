# sss — Simple Shared Secret authentication

SSS is a symmetric authentication scheme native to XRootD. A shared key is
distributed to clients and servers out-of-band (usually via a keytab file);
the client encrypts a challenge with Blowfish-CFB and the server verifies it.
It is widely used at production grid sites that cannot deploy x509 certificates.

## Files

| File | Purpose |
|---|---|
| `auth.c` | `kXR_auth` handler — parses the encrypted challenge, decrypts with Blowfish-CFB, verifies the CRC32 integrity check, extracts the client identity (`name`, `grps`), and sets `ctx->dn` / `ctx->vo_list` on success. |
| `key_parse.c` | Parses the server-side SSS key file (`/etc/xrootd/s.sss.keytab` or configured path). Loads key ID, key bytes, optional expiry, and policy options (`anyuser`, `anygroup`, etc.). |
| `config.c` | `xrootd_sss_keytab` directive parser. Reads and validates the keytab file at nginx startup. |

## Protocol sketch

1. Client sends `kXR_login` — server responds with a session ID and
   `kXR_authmore` containing an encrypted login-ID challenge.
2. Client sends `kXR_auth` with credential type `"sss\0"` containing the
   Blowfish-encrypted identity block.
3. Server decrypts the block, verifies the appended CRC32, checks the
   generation timestamp, and accepts or rejects.

## Key gotcha — CRC, not HMAC

SSS uses a CRC32 appended to the plaintext **before** encryption. After
decryption the CRC is read as a big-endian `uint32_t` and compared with
`got_crc != want_crc` — a 32-bit integer compare, not a `memcmp`. This is
safe because the CRC is not a secret; the secrecy comes from the Blowfish key.
Timing attacks on CRC comparison do not apply.

## See also

- `docs/authentication.md` §SSS for the full configuration reference.
- `src/gsi/` for the x509/GSI auth path.
- `src/token/` for JWT/WLCG bearer token auth.
