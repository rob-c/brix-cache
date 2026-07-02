# Phase 48 — Native client real XrdSecgsi interop (talk GSI to stock XRootD/EOS)

**Status:** PLAN + stop-gap + regression fixture landed 2026-06-21; the crypto
port (W1–W7) pending (multi-session). **Landed this session:** §1 stop-gap
(visible GSI failure, verified vs. EOS + local); §3 the local stock-xrootd GSI
test fixture + `tests/test_native_gsi_interop.py` (stock-client auth PASS proving
the fixture, native-client auth XFAIL = the keystone gap, stop-gap guard PASS).
The fixture also gives a **fast local iteration target** for the port (no remote
EOS needed) — confirmed: stock `xrdfs` lists `/gsidata` over GSI, ours reproduces
`ErrParseBuffer: main buffer missing: kXGC_certreq` exactly as against EOS.
**Problem:** `./client/xrdfs root://eoslhcb.cern.ch ls /eos/lhcb` fails
("user access restricted - unauthorized identity used"), while stock
`/usr/bin/xrdfs` works with the same proxy (`/tmp/x509up_u1000`).

---

## 0. Diagnosis (certain)

The native GSI module (`client/lib/sec/sec_gsi.c`) is a **minimal stub that only
interoperates with our own (equally non-standard) server**, not real XrdSecgsi:

- Forcing `--auth gsi` against EOS returns
  `Secgsi: ErrParseBuffer: main buffer missing: kXGC_certreq` — the server rejects
  our **first** message.
- Forcing `--auth unix` reproduces the exact user-visible error. So in the default
  gsi→token→krb5→sss→unix chain, **GSI fails and the client silently falls back to
  `unix`**, presenting the local UNIX identity → EOS rejects it.

**Confirmed wire-level gaps** (vs. a stock `xrdfs` debug trace,
`XrdSecDEBUG=3 XrdSecGSITRACE=3`):

| Aspect | Our client sends | Real XrdSecgsi requires |
|---|---|---|
| Round-1 outer | bare `"gsi\0"+kXGC_certreq` | `+ kXRS_cryptomod`("ssl"), `kXRS_version`(10600), `kXRS_issuer_hash`, `kXRS_clnt_opts`, `kXRS_main` |
| Round-1 main | (none) | nested `"gsi\0"+kXGC_certreq + kXRS_rtag`(8-byte client tag) `+ kXRS_none` |
| Round-2 pubkey | `kXRS_puk` (bare DH pubkey) | `kXRS_cipher` = full `XrdCryptosslCipher::AsBucket()` (DH p/g + pub + IV) |
| Round-2 proof | (none) | `kXRS_signed_rtag` = server's rtag signed with the **proxy private key** |
| Round-2 algos | (none) | `kXRS_cipher_alg`, `kXRS_md_alg`("sha256") |
| Cipher | `aes-256-cbc` | `aes-128-cbc:bf-cbc:des-ede3-cbc` (server picks `aes-128-cbc`) |
| Mutual auth | (ignored) | verify server's signature over our round-1 rtag |

**Our own server is ALSO non-standard** (`src/auth/gsi/cert_response.c` emits `kXRS_puk`,
not `kXRS_cipher`) — so this is a *from-scratch* port of XrdCryptossl/XrdSecgsi's
client side, not "match our server". (A separate follow-up should make the *server*
XrdCrypto-compatible too, or it cannot serve stock `xrdcp`.)

### Decoded round-1 buffer (the exact target)

Outer buffer, Step = `kXGC_certreq` (1000):
```
kXRS_cryptomod (3000): "ssl"
kXRS_version   (3014): 0x00002968  (= 10600)
kXRS_issuer_hash(3023): "5168735f.0|4339b4bc.0"   (echo of server's ca: list)
kXRS_clnt_opts (3019): 0x00000080
kXRS_main      (3001): <nested buffer, 28 bytes>:
        "gsi\0" + kXGC_certreq(1000)
        + kXRS_rtag(3006), len 8, <8 random bytes>
        + kXRS_none(0)
kXRS_none (0)
```
`v:`, `c:`, `ca:` all come from the gsi protocol `parms`
(`v:10600,c:ssl,ca:5168735f.0|4339b4bc.0`) the auth driver already receives but
`gsi_first` currently ignores.

### Authoritative source references (`/tmp/xrootd-src/src/`)

- `XrdSecgsi/XrdSecProtocolgsi.cc` — client state machine, `AddSerialized`,
  rtag/issuer-hash/clnt_opts handling, `getCredentials`/`ParseClientInput`.
- `XrdCrypto/XrdCryptosslCipher.cc` — `AsBucket()` (kXRS_cipher serialize, ~L988),
  `Public()` (L877), DH derive + IV `Encrypt()`/`Decrypt()` (L1112–1186).
- `XrdCrypto/XrdCryptosslgsiAux.cc` — proxy/rtag signing helpers.
- `XrdSut/XrdSutBuffer.cc` — buffer/bucket (de)serialization (nested main).

---

## 1. Stop-gap — DONE (this session)

`client/lib/auth.c`: when a credential-bearing protocol fails, print a stderr
warning before falling back, so the real cause is visible:
```
xrdc: warning: 'gsi' authentication failed (Secgsi: ErrParseBuffer: main buffer
missing: kXGC_certreq (AuthFailed)); falling back to the next offered protocol
```
Keeps stdout (data) clean. Built + verified against EOS.

---

## 2. The port — workstreams

Order chosen so each step is independently testable against the **local stock-xrootd
GSI server** (§3) for fast iteration; final check vs. EOS.

- **W1+W2+W3 — round-1 certreq — DONE + VERIFIED 2026-06-21.** All shared in
  `gsi_core` (so the server can reuse them too): `xrootd_gsi_parse_parms` (v:/c:/ca:),
  `xrootd_gsi_rand`, `xrootd_gsi_build_certreq` (outer + nested-main with the client
  rtag). Client `gsi_first` now echoes the server's crypto/version/ca and sends the
  standard certreq; the round-1 rtag is retained (file-static in `sec_gsi.c`) for W6.
  **Verified:** against the local stock server the error advanced from
  `main buffer missing: kXGC_certreq` → `no/garbled server DH key` — i.e. the server
  **accepts round-1** and we now fail only at round-2 because `gsi_more` still reads
  the legacy `kXRS_puk`. No regression (native_tools 15/15, no harness break).
- **W4 — XrdCryptosslCipher port (the big one, NEXT).** The wire `kXRS_cipher` is
  `XrdCryptosslCipher::Public()` (NOT `AsBucket()`):
  `<PEM "DH PARAMETERS" block incl. "-----END DH PARAMETERS-----\n"> + "---BPUB---"
  + <DH pub as BN_bn2hex uppercase> + "---EPUB---"`.  (Our existing
  `xrootd_gsi_dh_pub_encode` emits only the bare `---BPUB---hex---EPUB--` — 9-dash
  EPUB, no PEM params — which is the non-standard `kXRS_puk` our server uses.)  The
  DH **params are the server's** (parse p/g from the server cipher's PEM and keygen
  with them — NOT ffdhe2048).  `AsBucket()` (the full serialize incl. private key,
  7 host-endian int32 lengths: ltyp,livc,lbuf,lp,lg,lpub,lpri + type+IV+buffer+
  p+g+pub+pri hex) is the LOCAL/stored form, not the wire form.  Session AES key:
  read the DH-secret→key step in `XrdCryptosslCipher.cc` L480–570 (the keygen-from-
  peer path) — that, plus IV-prepend `Encrypt()`/`Decrypt()` (L1112–1186) and
  `aes-128-cbc`. Byte-match exactly; iterate vs. the local server (next error after
  this lands should be a round-2 main/x509/signed_rtag issue, not DH).
- **W5 — round-2 assembly.** kXRS_cryptomod + kXRS_cipher (W4) + kXRS_cipher_alg +
  kXRS_md_alg("sha256") + kXRS_x509(proxy chain) + kXRS_main(encrypted:
  signed_rtag + new client rtag).
- **W6 — proof-of-possession + mutual auth.** Load the proxy **private key** from
  the proxy file; sign the server's round-1 `kXRS_rtag` (RSA, sha256) →
  `kXRS_signed_rtag`. Verify the server's signature over *our* round-1 rtag
  (`secgsi_CheckRtag` equivalent) using the server cert's public key.
- **W7 — issuer hash.** Compute the X509 issuer hash(es) of our chain
  (`X509_NAME_hash`-compatible `%08x.0`) and/or echo the server `ca:` list; send the
  intersection so the server picks the right CA.

Each WS keeps the existing happy-path against our own server working (the server is
lenient and ignores the extra/standard buckets) — verify no harness regression.

---

## 3. Tests — make this checked forever (explicit, per the user's directive)

The root failure is that GSI was only ever tested **client↔our-own-server**, never
against a real XrdSecgsi peer. The regression suite must close that:

1. **Local stock-xrootd GSI server fixture** (`tests/gsi_interop/`): start a real
   `xrootd` (built under `/tmp/xrootd-src/build`, or the system one) configured for
   `XrdSecgsi` with a throwaway test CA + host cert, and a test user proxy minted
   from that CA. A pytest fixture brings it up/tears it down.
2. **`test_native_gsi_interop.py`:**
   - `./client/xrdfs --auth gsi root://<local> ls /` **succeeds** (the keystone
     assertion — fails today, passes when the port lands).
   - byte-exact `xrdcp` round-trip over GSI to the stock server.
   - negative: a proxy from an untrusted CA is rejected (no silent unix fallback to
     a wrong identity).
   - the stop-gap: a forced-`gsi` failure surfaces the GSI error on stderr (guards
     the §1 behaviour).
3. **Cross-check fixture (optional, opt-in `XRDGSI_EOS=1`):** the same `ls` against
   real EOS, skipped by default (needs a real grid proxy + network).
4. **Unit vectors for W4:** capture a known `kXRS_cipher` bucket + DH secret from a
   stock-client trace and assert our `AsBucket()`/derive/`Encrypt` reproduce it
   byte-for-byte (catches cipher-format drift without a live server).

> Until the port lands, the keystone assertion is an **xfail** documenting the gap —
> so the suite records it rather than hiding it.

---

## 4. Non-goals / follow-ups

- Making the *server* (`src/auth/gsi/`) XrdCrypto-compatible (so stock `xrdcp` can GSI to
  us) is a separate phase — related but out of scope here.
- VOMS AC parsing on the client (the proxy already carries it inside the cert; we
  just need to transmit the chain intact, which W5's `kXRS_x509` does).

## 5. Verification

- Per-WS: against the §3 local stock-xrootd server (fast), then `XrdSecDEBUG=3`
  trace diff vs. stock `xrdfs`.
- Final: `./client/xrdfs root://eoslhcb.cern.ch ls /eos/lhcb` lists the directory.
- Harness: existing GSI tests (11095/11096) + full client suite stay green.
