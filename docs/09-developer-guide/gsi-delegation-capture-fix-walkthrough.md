# GSI X.509 Proxy-Delegation Capture — Full Diagnostic Walkthrough & Fix

**Date:** 2026-07-01
**Status:** ✅ Resolved. Inbound F6 delegation capture works end-to-end; the target test is green.
**Scope:** `src/auth/gsi/delegation.c`, `src/auth/crypto/pki_build.c`, `tests/pki_helpers.py`,
`utils/voms_proxy_fake.py`, `tests/test_tpc_delegation.py`.
**Companion:** [`gsi-delegation-capture-investigation.md`](gsi-delegation-capture-investigation.md)
(the terse root-cause record; this file is the long-form narrative of *how* it was found).

> **TL;DR.** Our nginx XRootD server (as a TPC destination with `xrootd_tpc_delegate on`)
> could not capture a delegated X.509 proxy from a stock `xrdcp` client. Three independent
> problems stacked on top of each other and masked one another: (1) a **test-PKI confound**
> (certs lacked `keyUsage`), (2) a **real server bug** in proxy-chain verification
> (AKID/SKID mismatch), and (3) the **decisive wire bug** — we transmitted the proxy request
> as DER when the stock client requires PEM. A fourth non-bug — the *client* only arms
> delegation for a real `xrdcp --tpc delegate` operation, not the `XrdSecGSIDELEGPROXY` env
> var — had been mis-recorded as a fundamental limitation. Fixing all three, and driving the
> test correctly, turns a long-standing XFAIL into a green hard assertion.

---

## 1. What "delegation capture" is, and why it matters

In X.509 proxy **delegation** a client hands a short-lived, key-bearing proxy credential to a
server so the server can later act **as the user** to a third party. For us this is the
foundation of the monitoring/MITM tap proxy and of native third-party-copy (TPC): our nginx
destination must obtain the user's proxy so it can pull bytes from the source *as the user*,
not as the gateway host.

The GSI delegation sub-protocol (XrdSecgsi) runs as an extra handshake round after normal
authentication:

```
client  --kXGC_cert-->  server        (normal GSI auth: client presents its proxy chain)
server  --kXGS_pxyreq-> client        (server: "here is a proxy request; sign it for me")
client  --kXGC_sigpxy-> server        (client: "here is your signed delegated proxy")
```

Our implementation lives in `src/auth/gsi/delegation.c`:
`xrootd_gsi_begin_delegation()` builds and sends the `kXGS_pxyreq`;
`xrootd_gsi_handle_sigpxy()` consumes the `kXGC_sigpxy` and assembles the credential.

## 2. The symptom

With `xrootd_tpc_delegate on`, the handshake reached `kXGC_sigpxy` but our server logged:

```
xrootd: GSI delegation: sent kXGS_pxyreq (awaiting signed proxy)
xrootd: GSI kXGC_sigpxy: signed proxy (kXRS_x509) missing (client declined to delegate?)
```

and the client aborted with `Authentication with gsi failed: GSI proxy delegation failed`.

`tests/test_tpc_delegation.py::test_dest_captures_delegated_proxy` was marked `xfail` with the
explanation *"the stock client declines to return a signed proxy under its usedDNS/hostname
delegation policy in this synthetic-hostname WSL2 rig (needs a real grid host)."* **That
explanation was false**, and disproving it was the first breakthrough.

## 3. Methodology

The work followed the `systematic-debugging` discipline: **no fixes before root cause**, gather
evidence at every component boundary, and change one variable at a time. Concretely, the
evidence sources were:

* **Our server's `error_log`** at `info`/`warn` — the delegation state machine narrates itself.
* **The stock client's GSI trace** — `XrdSecDEBUG=3` + `xrdcp -d1`, which dumps every
  `XrdSutBuffer` (bucket types, encrypted/plaintext, step names).
* **A working reference** — the *same* stock client delegating to a *stock* `xrootd` source,
  captured the same way, to diff against.
* **The authoritative stock source** at `/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc`
  and `/tmp/xrootd-src/src/XrdCrypto/XrdCryptosslX509Req.cc` — read, not guessed.
* **Small standalone C probes** compiled against the system OpenSSL to confirm exact error
  codes, and **Python bucket parsers** to decode the decrypted GSI buffers byte-by-byte.

The single most valuable move was **building a working reference and diffing it**: it converted
"the client declines" from an opaque fact into "the client behaves differently against us vs
stock — therefore the defect is ours."

---

## 4. Diagnosis, in the order it actually unfolded

### 4.1 Problem 0 — the `keyUsage` confound (found first, blocking everything)

GSI proxy signing (`XrdCryptosslgsiAux.cc:X509SignProxyReq`) rejects a signing chain whose
end-entity certificate carries **no `keyUsage` extension**:

```c
if (nriext == 0 || !haskeyusage) { PRINT("wrong extensions in request..."); return -kErrPX_BadExtension; }
```

The test PKI minted EEC/host certs with bare `openssl x509 -req` — **no `keyUsage`**. Every
delegation attempt that reached the crypto step was therefore doomed *before any protocol
question could be evaluated*. Real IGTF/grid certs always carry `keyUsage`, so this was purely a
fixture defect, but it had to be removed first or it would mask everything else.

**Fix:** add `keyUsage` (and a realistic `extendedKeyUsage`) to every generated cert:

* `tests/pki_helpers.py` — user EEC gets `keyUsage=critical,digitalSignature,keyEncipherment`
  + EKU `clientAuth`; host cert gets keyUsage + EKU `serverAuth,clientAuth`.
* `utils/voms_proxy_fake.py` — the VOMS proxy gets a critical `KeyUsage(digitalSignature)`,
  matching `utils/make_proxy.py` (which already had it).
* `tests/test_tpc_delegation.py` — the inline PKI's `signed()` helper gains the same extfile.

Verified with `openssl verify -allow_proxy_certs` and a live regression run (GSI handshake 42
passed, VOMS ACL 31 passed). With the confound gone, the handshake advanced — and immediately
hit the next wall.

### 4.2 Problem 1 — client cert rejected: "unable to get local issuer certificate"

With keyUsage-bearing certs, the very first delegation attempt failed *earlier* than before, at
chain verification:

```
xrootd: GSI client cert rejected: unable to get local issuer certificate
```

This was surprising: the EEC verifies fine against the CA on its own. The discriminator turned
up by comparing two proxies:

* `utils/make_proxy.py` proxies (Python `cryptography`) → `openssl verify -allow_proxy_certs
  -untrusted EEC proxy` → **OK**.
* `xrdgsiproxy`-minted proxies (used by the delegation test) → **error 20** (unable to get
  local issuer).

Dumping the extensions side-by-side exposed it:

```
xrdgsiproxy proxy leaf:                 F6 EEC (its issuer):
  Subject Key Identifier: 7A:30:…:43      Subject Key Identifier: 7A:30:…:43
  Authority Key Identifier: 34:AE:…:28    Authority Key Identifier: 34:AE:…:28
```

`xrdgsiproxy` **copied the EEC's SKID *and* AKID verbatim into the proxy**. So the proxy's AKID
(`34:AE…28`, which is really the CA's key id) does **not** match the EEC's SKID (`7A:30…43`).
A tiny C probe confirmed the exact OpenSSL verdict:

```
X509_check_issued(eec, proxy) = 30 (authority and subject key identifier mismatch)
proxy EXFLAG_PROXY = 1
```

OpenSSL's default `check_issued` treats `X509_V_ERR_AKID_SKID_MISMATCH` (30) as "not the
issuer", drops the EEC as a candidate, and — finding no other issuer — reports error 20.

**Why it had been invisible:** a `keyUsage`-less EEC also has no SKID, so there was nothing to
mismatch; the strict check simply never engaged. Adding realistic certs *exposed* a latent
server bug. Crucially, the **stock `xrootd` source verified the same proxy fine** — its
`XrdCryptosslX509Chain` walker matches issuers by **subject name + signature** and ignores the
AKID hint. Our server uses OpenSSL's stricter `X509_verify_cert`. This is a genuine production
bug: real grid proxies (which have SKIDs) would be rejected by us but accepted everywhere else.

**Fix** (`src/auth/crypto/pki_build.c`): install a proxy-tolerant `check_issued` on stores built for
proxy verification. It defers to `X509_check_issued`, and *only for a subject OpenSSL has
recognised as a proxy* (`EXFLAG_PROXY`) whose sole objection is an AKID/SKID (or AKID
issuer-serial) mismatch, it accepts the name-matching issuer. The RSA signature is still
verified downstream by `X509_verify_cert`, so this relaxes issuer **selection**, never trust.
It is scoped to proxy stores (GSI passes `X509_V_FLAG_ALLOW_PROXY_CERTS`); plain WebDAV
client-cert stores pass `flags=0` and keep OpenSSL's strict default.

> **OpenSSL 3.0 API note.** There is no `X509_STORE_CTX_set_check_issued` in OpenSSL 3.0 —
> only the store-level `X509_STORE_set_check_issued`. The callback therefore lives where the
> store is built (`pki_build.c`), not in the per-request verify helper (`gsi_verify.c`); the
> ctx inherits the store's callback at `X509_STORE_CTX_init`.

With cert verification fixed, the handshake finally reached the delegation round proper — and
declined there.

### 4.3 Problem 2, part A — the client wasn't even *asking* to delegate

The server logged the client's advertised delegation options as `opts=0x80 (fwd=0 sign=0 dlg=0)`
and, after sending `kXGS_pxyreq`, `signed proxy (kXRS_x509) missing`. Decrypting the client's
`kXGC_sigpxy` (a Python walk over the session-cipher-decrypted `kXRS_main`) showed it contained
`kXRS_signed_rtag` + `kXRS_x509_req` (**our own CSR, echoed back**) + a `kXRS_message` bucket
reading:

```
Not allowed to sign proxy requests
```

That message is `ClientDoPxyreq`'s decline path when `hs->Options & kOptsSigReq` is clear. The
stock client's own trace explained why:

```
Secgsi Proxy delegation option: 0
```

The test was invoking `xrdcp` with `XrdSecGSIDELEGPROXY=1` and a plain PUT. **That env var did
not arm delegation** — `dlgpxy` stayed 0, so `kOptsSigReq` was never set and the decline was
correct client behaviour, independent of anything our server did.

Reading the stock source resolved the trigger question. `hs->Options = PxyReqOpts` is set on the
**client** from *its own* config (env/CLI), and those bits are **not advertised to the server**
(so our "sign=0" log was reading the wrong field — it never contains them). Re-running with a
real TPC-delegate operation flipped it:

```
$ xrdcp --tpc delegate only root://src//file root://our-nginx//dest
# client:  Secgsi Proxy delegation option: 1
# server:  GSI client delegation opts=0x85 (fwd=0 sign=1 dlg=1)
```

`--tpc delegate` sets `kOptsSigReq | kOptsDlgPxy`; the env var alone does not. **This overturns
the prior investigation's "infeasible / needs a real grid host" conclusion** — it was an
artifact of the wrong trigger (compounded by the keyUsage confound). The capture test must drive
delegation with `--tpc delegate`, not the env var.

### 4.4 Problem 2, part B — the decisive bug: DER vs PEM

With `kOptsSigReq` now genuinely set, the client entered the *sign* branch — and still declined,
but with a **different** message extracted from `kXRS_message`:

```
could not resolve proxy request
```

This is `ClientDoPxyreq`'s failure when `X509Req(bucket)` cannot parse our request. Reading the
stock parser settled it in one line (`XrdCryptosslX509Req.cc`):

```c
// Get certificate request from BIO
if (!PEM_read_bio_X509_REQ(bmem,&creq,0,0)) {
   DEBUG("unable to read certificate request to memory BIO");
   return;
}
```

The stock client parses the `kXRS_x509_req` bucket as **PEM**. But `xrootd_gsi_build_pxyreq`
emits **DER** (`i2d_X509_REQ`), and `delegation.c` put that DER straight on the wire:

```c
xrootd_gbuf_bucket(&b.inner, kXRS_x509_req, b.req_der, b.req_len);   /* DER — wrong */
```

A DER blob is not valid PEM, so `PEM_read_bio_X509_REQ` returns NULL and the client declines.
This was the true, decisive defect — the AKID/SKID and keyUsage fixes were prerequisites that
merely let the handshake *reach* this point.

**Why the DER output is correct to keep:** `xrootd_gsi_build_pxyreq`'s DER is consumed as DER by
`xrootd_gsi_sign_pxyreq` (our own outbound-signing path) and by `proxy_req_unittest.c`
(`d2i_X509_REQ`). Changing the core to PEM would break those. The encoding is a **wire-format**
concern, so the conversion belongs at the wire edge in `delegation.c`.

---

## 5. The implementation

### 5.1 `src/auth/gsi/delegation.c` — PEM-encode the proxy request

A small DER→PEM converter, applied to the request before it enters the `kXRS_x509_req` bucket:

```c
/*
 * Re-encode a DER X509_REQ as PEM.  The stock XrdSecgsi client parses the
 * kXRS_x509_req bucket with PEM_read_bio_X509_REQ (XrdCryptosslX509Req), so the
 * proxy request MUST travel as PEM on the wire; xrootd_gsi_build_pxyreq emits
 * DER (consumed as DER by xrootd_gsi_sign_pxyreq and its unit tests), so the
 * conversion happens here at the wire edge rather than in the crypto core.
 */
static u_char *
gsi_req_der_to_pem(const u_char *der, size_t der_len, size_t *pem_len)
{
    const unsigned char *p = der;
    X509_REQ            *req = d2i_X509_REQ(NULL, &p, (long) der_len);
    BIO                 *b;
    char                *d;
    long                 n;
    u_char              *out = NULL;

    if (req == NULL) return NULL;
    b = BIO_new(BIO_s_mem());
    if (b != NULL && PEM_write_bio_X509_REQ(b, req) == 1) {
        n = BIO_get_mem_data(b, &d);
        out = malloc((size_t) n + 1);
        if (out != NULL) { memcpy(out, d, (size_t) n); out[n] = '\0'; *pem_len = (size_t) n; }
    }
    BIO_free(b);
    X509_REQ_free(req);
    return out;
}
```

Wired into `xrootd_gsi_begin_delegation()` with matching lifecycle (new `req_pem`/`req_pem_len`
fields in the owned-scratch struct, converted right after `build_pxyreq`, freed in `bdg_fail`):

```c
/* The stock client parses kXRS_x509_req as PEM — re-encode the DER request. */
b.req_pem = gsi_req_der_to_pem(b.req_der, b.req_len, &b.req_pem_len);
if (b.req_pem == NULL) { … "cannot PEM-encode proxy request" … return bdg_fail(&b); }
…
xrootd_gbuf_bucket(&b.inner, kXRS_x509_req, b.req_pem, b.req_pem_len);   /* PEM — correct */
```

The receive side already matched stock: the client returns the signed proxy as PEM
(`kXRS_x509`), and `xrootd_gsi_handle_sigpxy` → `xrootd_gsi_assemble_proxy` reads it with
`PEM_read_bio_X509`.

### 5.2 `src/auth/crypto/pki_build.c` — proxy-tolerant issuer selection

```c
static int
pki_proxy_check_issued(X509_STORE_CTX *ctx, X509 *subject, X509 *issuer)
{
    int rv = X509_check_issued(issuer, subject);
    if (rv == X509_V_OK) return 1;
    /* Real xrdgsiproxy/voms-proxy-init proxies copy the EEC's AKID (points at
     * the CA, not the EEC); accept the name-matching issuer for PROXY subjects.
     * The RSA signature is still verified by X509_verify_cert afterwards. */
    if ((X509_get_extension_flags(subject) & EXFLAG_PROXY)
        && (rv == X509_V_ERR_AKID_SKID_MISMATCH
            || rv == X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH))
        return 1;
    return 0;
}
…
/* installed only when proxy certs are allowed (GSI stores, not WebDAV client-cert) */
if (extra_flags & X509_V_FLAG_ALLOW_PROXY_CERTS)
    X509_STORE_set_check_issued(store, pki_proxy_check_issued);
```

### 5.3 Test PKI — `keyUsage` everywhere

`tests/pki_helpers.py`, `utils/voms_proxy_fake.py`, and the inline PKI in
`tests/test_tpc_delegation.py` now emit `keyUsage` (and realistic `extendedKeyUsage`) on every
generated certificate, mirroring an IGTF-issued grid identity.

### 5.4 The test — drive delegation correctly, assert the capture

`test_dest_captures_delegated_proxy` dropped its `xfail` and now runs a real
`xrdcp --tpc delegate only` (source = stock `xrootd`, dest = our nginx), asserting both the
capture log line and that the captured identity is the delegating **user**:

```python
r = _run([XRDCP, "-f", "--tpc", "delegate", "only",
          f"root://{gate['fqdn']}:{SRC_PORT}//data/hello.txt",
          f"root://{gate['fqdn']}:{DST_PORT}//cap.txt"], env=gate["env"])
assert "captured delegated proxy" in log
assert f'dn="{USER_DN}' in log
```

---

## 6. Verification

```
GSI delegation: captured delegated proxy (5447 bytes) dn="/O=F6Test/CN=F6 User/CN=888442596"
```

| Suite | Result |
|---|---|
| `test_tpc_delegation.py` | **3 passed, 1 xfailed** (xfail = the separate outbound-pull phase) |
| `proxy_req_unittest.c` (DER crypto core) | 25 checks, 0 failures |
| `test_gsi_handshake_b` + `test_gsi_proxy_crypto` + `test_vo_acl` | 74 passed |
| `test_webdav_voms` (client-cert path stays strict) | 3 passed |
| `openssl verify -allow_proxy_certs` on the fixtures | OK |

No temporary instrumentation remains in `src/`.

---

## 7. What was *not* changed, and why

* **The GSI crypto core (`proxy_req.c`) still emits DER.** Its DER output is a real contract
  (`sign_pxyreq`, unit tests). Only the wire representation in `delegation.c` changed.
* **WebDAV/DAVS client-cert verification stays strict.** The AKID-tolerant callback is installed
  only on stores that allow proxy certs; the non-proxy path is untouched.
* **The outbound TPC pull works too (§9).** Capturing the proxy and *using* it to pull from
  the source are distinct phases; the pull needed one more fix, described below.

## 8. Lessons

1. **Build a working reference and diff it.** "The client declines" became actionable only once
   the *same* client was shown to delegate to *stock* but refuse *us*.
2. **Stacked confounds hide real bugs.** A missing test-cert extension (keyUsage) masked a real
   verification bug (AKID/SKID), which masked the real wire bug (DER vs PEM). Peel one layer at
   a time and re-observe.
3. **Read the reference implementation, don't infer it.** The two decisive facts —
   `PEM_read_bio_X509_REQ` and the `hs->Options = PxyReqOpts` client-side trigger — came
   straight from the stock source, not from guessing.
4. **Distinguish wire format from crypto contract.** The fix was one `d2i`/`PEM_write` at the
   edge, not a change to how requests are built.
5. **A "test environment limitation" that survives multiple sessions deserves suspicion.** The
   "needs a real grid host" xfail reason was wrong; the real issue was the trigger (`--tpc
   delegate` vs env var) plus two server bugs.

---

## 9. The outbound pull — using the captured proxy (`kXR_open recv failed`)

Capturing the proxy is only half of TPC-with-delegation; the destination must then **pull** the
file from the source *as the user*. That failed with the client error
`[3012] TPC kXR_open recv failed`, so the fix continued into `src/tpc/`.

### 9.1 Diagnosis

The dest's pull runs on a thread-pool worker (`src/tpc/thread.c`):
`tpc_connect` → `tpc_bootstrap` (handshake/protocol/login + GSI auth) → `tpc_pull_from_source`
(`source.c`: open → read → sync → close). Evidence, layer by layer:

* **The source authenticated the pull as the USER.** The stock source's `-d:2` log showed our
  dest worker connection logging in with `Subject DN='/O=F6Test/CN=F6 User'` → mapped to the
  local user. So the **delegated proxy works** — bootstrap + GSI auth to the source succeed. The
  proxy-tolerant `check_issued` (§4.2) also runs on the *outbound* verify path (the dest verifies
  the source's cert), so that fix was a prerequisite here too.
* **But no `kXR_open` was ever processed by the source** — both the client's and the dest's
  connections sat idle for exactly 15s (the client timeout) then disconnected, with no open in
  the source log.
* **Targeted instrumentation on the pull thread** (temporary `TPCDBG` logs, since the thread
  worker doesn't otherwise narrate) showed the truth: the open *was* sent, and the source
  *replied* — with `status=4006 = kXR_waitresp`. Then the next recv timed out (`errno 11,
  EAGAIN`) after `SO_RCVTIMEO`.

`kXR_waitresp` means *"I'll answer later, unsolicited."* The source deferred the open because our
dest presented `?tpc.key=…&tpc.org=…` — the **anonymous TPC rendezvous** key. In that model the
pulling server is not itself authorized; it proves authorization with a key the **client**
pre-registers on the source, and the source holds the open in `kXR_waitresp` until that
client-side authorization lands. In the **delegate** flow the client never issues that
authorization (it delegates instead), so the source waits forever and the dest times out.

### 9.2 The fix (`src/tpc/source.c`)

When the pull holds a delegated credential, the dest is *authenticated as the user* and can open
the source file **directly** — the rendezvous key is neither needed nor correct:

```c
/* TPC-lite delegation: we authenticated to the source AS THE USER, so open the
 * file directly — no tpc.key opaque. Presenting the anonymous-rendezvous key
 * makes the source defer with kXR_waitresp forever (it waits for a client-side
 * authorization the delegate flow never issues). */
if (t->deleg_cred_pem != NULL && t->deleg_cred_len > 0) {
    opqlen = 0;
    opaque[0] = '\0';
} else if (t->tpc_key[0] != '\0' && t->tpc_org[0] != '\0') {
    …existing rendezvous path (unchanged for anonymous TPC)…
}
```

With the key omitted, the source answered the open with `kXR_ok` immediately and the pull
streamed the file byte-for-byte. The change is gated on `deleg_cred_pem`, so ordinary
(non-delegated) TPC pulls keep the rendezvous key exactly as before.

### 9.3 Verification

```
TPCDBG: kXR_open reply status=0 dlen=4 iter=0      (kXR_ok, was 4006/kXR_waitresp)
pulled.txt == "f6 delegation gate"                 (byte-for-byte)
```

`test_dest_pulls_as_user_via_delegation` flipped from XFAIL to a green hard assertion: the pull
transfers the bytes **and** the source logs the pull's `Subject DN` as the delegating user, never
the gateway. `test_tpc_delegation.py` is now **4 passed**. Non-delegated TPC pull suites
(`test_root_tpc`, `test_tpc_async_open`, `test_tpc_gsi_nginx_source`) stay green (9 passed).

**End-to-end, the F6 chain is now complete:** delegating client → dest captures the user's
key-bearing proxy → dest authenticates to the source as the user → dest opens directly and pulls
the bytes.

---

## 10. The tap-proxy GSI forwarding path (client → proxy → upstream, as the user)

The same capture feeds the **monitoring/MITM tap proxy** (`src/proxy/`, `xrootd_tap_proxy_auth
gsi`): a client delegates its proxy to the tap proxy, which logs in to the *upstream* **as the
user** and relays. Verifying this end-to-end surfaced two more issues.

### 10.1 No client delegates on a plain read — so we taught ours to

The tap proxy is a plain-read reverse proxy, not a TPC destination. As §4.3 established, the stock
client only arms delegation for `--tpc delegate`; on a plain read it sends `clnt_opts=0x80` and
declines. This repo's client had **no delegation-send** at all. So we implemented it (the mirror
of the server-side capture):

* **`src/auth/gsi/gsi_core.c`** — `xrootd_gsi_build_cert_response_ex` now optionally hands the agreed
  AES **session key + cipher + IV flag** back to the caller (the round-2 builder previously wiped
  them). The old signature stays as a thin wrapper, so the TPC caller is untouched.
* **`client/lib/sec/sec_gsi.c`** — `gsi_more` retains that session cipher on the connection, and
  dispatches a follow-up `kXGS_pxyreq` step to a new **`gsi_sigpxy`** handler: it decrypts the
  server's request, PEM→DER-decodes the `kXRS_x509_req`, signs it with the client's proxy
  (`xrootd_gsi_sign_pxyreq`), and returns an AES-encrypted `kXGC_sigpxy` carrying the signed
  proxy. Gated on **`XRDC_GSI_DELEGATE=1`** — handing your credential to a server is opt-in,
  mirroring the stock `XrdSecGSIDELEGPROXY`.
* **`shared/xrdproto/Makefile`** — `proxy_req.o` (`sign_pxyreq`) was missing from the client
  archive; added.
* **`client/lib/xrdc_net.h`** — per-connection GSI delegation state (the client opens parallel
  connections, so this can't be file-static).

### 10.2 A NULL-deref crash in the forward path

With the client delegating, the tap proxy **captured** the proxy — then the worker **SIGSEGV'd**
(gdb: `xrootd_proxy_connect` at `connect_upstream.c:242`) before reaching the upstream. Cause:
`proxy_up_status` (the per-upstream health table) is **allocated lazily and is NULL until a
failure marks an upstream down**; every other accessor (`mark_fail`, `is_down`) is NULL-tolerant,
but the upstream-selection loop dereferenced it unguarded. Fix: guard the loop — a NULL table
means "all upstreams healthy", so the round-robin pick stands. (This latent crash affected any
multi-/array-upstream proxy config on its first request, not just GSI.)

### 10.3 Result — both clients, hybrid nginx+XRootD rig

Topology: this repo's nginx tap proxy (GSI in, delegation capture, GSI-as-user upstream) →
a GSI-only nginx upstream. Driven by `tests/run_tap_proxy_gsi.sh`:

* **This repo's `xrdcp` + `XRDC_GSI_DELEGATE=1`** — a 400 KB read is **byte-exact** through the
  proxy, and the upstream logs the proxy's pull `Subject DN` as the **delegated user**
  (`.../CN=Test User/.../CN=<proxy serial>`).
* **Stock `/usr/bin/xrdcp`** (plain read) — cannot delegate, so it **declines cleanly**
  (`client declined to delegate`) and the proxy **does not crash** — the documented boundary.

Regression: `run_tap_proxy.sh` (non-GSI relay, 4 ok), `run_credential_xroot_gsi` (outbound GSI
login, ALL PASS), and pytest `test_tpc_delegation` + `test_gsi_handshake_b` + `test_proxy_mode`
(85 passed) all stay green; the full client rebuilds clean.

### 10.4 Hybrid rig — official `xrootd` upstream, GSI only (`run_tap_proxy_gsi_hybrid.sh`)

The nginx→nginx test proves the mechanics; the decisive interop question is whether the proxy's
**outbound** GSI login (presenting the captured proxy) works against a **real XRootD server**.
It does. With an official `xrootd` v5.9.5 GSI-only upstream (a `gridmap` for the user's EEC DN)
behind the nginx tap proxy, and GSI on every hop:

* **This repo's `xrdcp` + `XRDC_GSI_DELEGATE=1`** → nginx tap proxy → **official xrootd**: the
  400 KB read is **byte-exact**, and the *xrootd* server maps the delegated proxy DN and logs the
  proxy's pull in **as the user** (`… login as <user>`). This exercises our client's
  delegation-send, the proxy's capture, and — the new coverage — our **outbound GSI client
  interoperating with stock xrootd** using a captured delegated proxy.
* **Stock `/usr/bin/xrdcp`** (plain read): clean decline, no crash — same boundary.
* Baselines: both clients read **directly** from the official xrootd byte-exact (so the rig's GSI
  is sound independent of the proxy).

Complementary hybrid direction — the F6 **TPC pull** — is already covered by
`test_tpc_delegation.py`: official `xrootd` source + nginx dest + official `xrdcp --tpc delegate`,
green. Together the two exercise stock↔repo interop in both roles (server and client) under GSI
only.

---

## 11. Delegated TPC with nginx as a FILESERVER on both ends (`run_tpc_delegation_nginx.sh`)

The tap proxy relays; a fileserver serves its own storage. This verifies delegation for TPC when
**nginx is a real fileserver** as both the *source* and the *destination*, GSI only:
`xrdcp --tpc delegate` → nginx **dest** (captures the proxy, writes to its store) pulling from
nginx **source** (serves the read) — the destination authenticates to the source **as the user**.

### 11.1 The fix: a read-only source must advertise TPC

The first attempt failed with the client error **"Source does not support third-party-copy"**.
The client's `XrdCl::Utils::CheckTPCLite` queries **both** endpoints' `tpc` capability
(`kXR_Qconfig`) before starting. Our `src/query/config.c` computed
`tpc_capable = allow_write && thread_pool` — the **destination** (pull) requirement — so a
read-only **source** reported `tpc=0` and the transfer never began. But a TPC source only serves
reads; any data server qualifies. Fix: advertise `tpc=1` unconditionally (a comment records that
the dest-pull's write+thread-pool requirement is enforced where the pull is launched, in
`src/tpc`, not via the source-facing advertisement). The `tpc` qconfig value stays a parseable
digit, so `test_conf_query2`/`test_conf_client` remain green.

### 11.2 Result — both clients, both nginx ends

With nginx source (read-only GSI) + nginx dest (GSI, `xrootd_tpc_delegate on`), a 400 KB file:

* **Official `xrdcp --tpc delegate only`** and **this repo's `xrdcp --tpc delegate`
  (`XRDC_GSI_DELEGATE=1`)** both transfer **byte-exact**.
* The nginx **source** logs the destination's pull `Subject DN` with the **multi-hop delegated
  identity** — the user's EEC plus *two* trailing proxy CNs (the client's own proxy + the
  destination's freshly-minted delegated proxy) — proving the pull runs **as the user**, not the
  gateway.

Regression: the `tpc=1` change is covered by `test_conf_query2` + `test_conf_client` +
`test_tpc_delegation` + `test_root_tpc` (**175 passed**).

### 11.3 The full delegation matrix, GSI only

| Role of nginx | Peer | Client | Test |
|---|---|---|---|
| **Dest** (capture + pull) | official `xrootd` **source** | official `--tpc delegate` | `test_tpc_delegation.py` |
| **Source + Dest** (fileservers) | nginx ↔ nginx | official **and** repo | `run_tpc_delegation_nginx.sh` |
| **Tap proxy** (capture + forward) | official `xrootd` **upstream** | repo (`XRDC_GSI_DELEGATE`) | `run_tap_proxy_gsi_hybrid.sh` |
| **Tap proxy** (capture + forward) | nginx **upstream** | repo / stock-decline | `run_tap_proxy_gsi.sh` |

In every case the credential delegated by the client is used to authenticate the next hop **as
the user**, byte-exact, with stock↔repo interoperability in both the server and client roles.
