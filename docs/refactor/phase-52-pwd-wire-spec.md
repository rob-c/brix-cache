# Phase 52 WS-B — XrdSecpwd (`pwd`) wire-handshake spec (normal password flow)

**Source of truth:** `/tmp/xrootd-src/src/XrdSecpwd/XrdSecProtocolpwd.{cc,hh}`,
`XrdSut/XrdSutBuffer.cc`, `XrdSut/XrdSutAux.hh`, `XrdSut/XrdSutPFEntry.hh`,
`XrdCrypto/XrdCryptosslAux.cc` (PBKDF2 KDFun), `XrdCrypto/XrdCryptosslCipher.cc` (DH).
Scope: the `kpCT_normal` non-interactive flow with `XrdSecCREDS` as credential source.
Out of scope: AFS, autoreg/srvpuk auto-registration, onetime, crypt(3), interactive
prompt, password-change.

## Crypto = identical to GSI
The pwd session cipher is `XrdCryptosslCipher` from the same `XrdCryptossl` factory as
XrdSecgsi. DH agreement is identical: `Public()` exports DH public, `Finalize(peerpub)`
runs `EVP_PKEY_derive`. **Reuse `src/auth/gsi/gsi_core.c` DH + cipher primitives verbatim.**
KDFun = **PBKDF2-HMAC-SHA1, 10000 iters, 24-byte output** (`XrdCryptosslAux.cc:78-110`).

## Bucket TLV (XrdSutBuffer.cc:438-514)
Serialized buffer = `proto"\0"` + `step:int32 BE` + N×(`type:int32 BE` + `len:int32 BE`
+ payload) + `kXRS_none(0):int32 BE` terminator. int32 buckets (version/timestamp/status)
carry exactly 4 BE bytes. `kXRS_inactive(1)` buckets are dropped.

### kXRS_* codes (XrdSutAux.hh, contiguous from 3000)
`none=0, inactive=1, cryptomod=3000, main=3001, puk=3004, cipher=3005, rtag=3006,
signed_rtag=3007, user=3008, creds=3010, message=3011, version=3014, status=3015,
timestamp=3021, afsinfo=3027`.

## pwdStatus_t (XrdSecProtocolpwd.hh:192-196) — marshalled as ONE htonl'd word
`struct { char ctype; char action; short options; }` (size 4). On the wire:
`wire = htonl(*(uint32_t*)&struct_in_host_memory)` — swap the whole 4-byte image, NOT
per-field. Decode: `host = ntohl(wire)`. `ctype kpCT_normal=0`. `options` must include
`kOptsClntTty=0x0080` or the server aborts continuations (Authenticate:1550-1556).
Entry status `kPFE_ok=1`.

## Two buffers per message
- **global**: `kXRS_cryptomod("ssl")`, `kXRS_puk` (DH public), `kXRS_main` (carrier).
- **main** (serialized then encrypted WHOLE into `kXRS_main` with the DH cipher):
  `kXRS_version(10100)`, `kXRS_user`, `kXRS_creds`, `kXRS_status`, `kXRS_timestamp`,
  `kXRS_rtag`→`kXRS_signed_rtag`, `kXRS_message`.

## Credential transform (THE CRUX)
Client sends the **raw password bytes** in `kXRS_creds` (NO client hashing); the whole
`kXRS_main` is DH-cipher-encrypted in `AddSerialized`. `XrdSecCREDS` is hex of
`"&pwd""\0"`+`<4-byte pfx>`+`<password bytes>`; wire creds = the trailing password bytes
(QueryCreds:2349-2405). Server: `DoubleHash` = PBKDF2-HMAC-SHA1(received_pw, stored_salt,
10000, 24B), compare to stored 24-byte hash (CheckCreds:2025-2104, SaveCreds salt=8 rand).

## Rtag mutual auth (reuse GSI signed-rtag)
Encrypting the peer's `kXRS_rtag` with the shared DH cipher and retyping it to
`kXRS_signed_rtag` IS the signature (AddSerialized:2938-2951); verify by decrypt+memcmp
(CheckRtag:3821-3872). Server requires it when `VeriClnt==2` (default); client when
`VeriSrv==1` (default) → default normal flow is **3 round-trips**. With `VeriSrv=0,
VeriClnt=0` the flow collapses to 1 RT (legitimate config).

## AddSerialized (2912-3019)
SetStep(next) on both buffers; encrypt any main `kXRS_rtag`→`signed_rtag`; if client add
`kXRS_timestamp`; add a fresh `kXRS_rtag` (cache for verify); serialize main; wrap into
global `kXRS_main`; **encrypt that bucket whole** with the DH cipher.

## DH bootstrap caveat (stock interop)
Stock clients require the server's DH public (`srvpuk`) **pre-shared** (pwdsrvpuk cache)
or fetched via autoreg before RT1. Our implementation exchanges puks in-band (server
sends its puk in the first auth response), which is simpler and works our-client↔our-
server but diverges from stock's pre-shared-srvpuk assumption. Full stock interop =
implement the pre-shared-srvpuk + autoreg puk distribution + 3-RT mutual rtag. Verified
against a stock `sec.protocol pwd` server with a pwd-admin DB is the remaining gap.

`XrdSecpwdVERSION = 10100`. Server parm: `&P=pwd,v:10100,id:<srvid>,c:ssl`.

## Operator: generating xrootd_pwd_file entries

Each line is `user:salthex:hashhex[:vo1,vo2]`, `hash = PBKDF2-HMAC-SHA1(password, salt,
10000, 24B)` (`#`/blank lines ignored). The optional 4th field is a comma-separated
VO/group list stamped onto the authenticated identity (same seam GSI/unix fill), so
group-aware backends (e.g. pblock catalog-internal ownership) enforce group access for
password users; the legacy 3-field form yields an empty VO set. Generate an entry with
a random 8-byte salt:

```python
import hashlib, os, sys
user, pw = sys.argv[1], sys.argv[2]
salt = os.urandom(8)
h = hashlib.pbkdf2_hmac("sha1", pw.encode(), salt, 10000, 24)
print(f"{user}:{salt.hex()}:{h.hex()}")
```

The native client supplies the password via `XRDC_PWD` (or the stock `XrdSecCREDS`
hex blob) and the username via `XRDC_PWD_USER`/`USER`; select with `xrdcp --auth pwd`.
`pwd` is opt-in (`xrootd_auth pwd` + a non-empty `xrootd_pwd_file`) and should run
only behind TLS.

The SAME db also serves HTTP/WebDAV exports: `brix_webdav_pwd_file <file>` enables
HTTP Basic auth (curl `-u user:pass`) verified with the identical PBKDF2 check, and
stamps the identity (dn = username, VOs from the 4th field) like the stream side —
one credential store across root://, http(s):// and dav(s)://. Exports with a
pwd file answer unauthenticated/failed requests with `401` +
`WWW-Authenticate: Basic realm="brix"` so browsers pop their native login
prompt (cert/token-only exports keep the flat 403 — no prompt that cannot
succeed). Both sides log a
config-time WARN that password auth is poor practice for production; prefer
GSI/x509 or bearer tokens, and serve password auth only over TLS.
