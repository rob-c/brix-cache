# GSI X.509 Proxy Delegation Capture — Root-Cause Investigation (F6)

**Date:** 2026-07-01
**Status:** ✅ **RESOLVED.** Inbound GSI proxy-delegation capture works end-to-end; our nginx
dest captures the delegating user's key-bearing proxy. `test_tpc_delegation.py::
test_dest_captures_delegated_proxy` is now a GREEN hard assertion (was XFAIL). See
**§0 Resolution** below.
**Author:** systematic-debugging session.

---

## 0. Resolution (2026-07-01)

Two independent server-side defects — plus a test-PKI confound — had to be fixed together.
All three are now landed and verified; the capture succeeds:

```
xrootd: GSI delegation: captured delegated proxy (5447 bytes) dn="/O=F6Test/CN=F6 User/CN=888442596"
```

1. **Proxy request encoded as DER, not PEM (the decisive bug).** `brix_gsi_build_pxyreq`
   emits the `X509_REQ` as **DER**, and `src/auth/gsi/delegation.c` put that DER straight into the
   `kXRS_x509_req` bucket. The stock client parses that bucket with `PEM_read_bio_X509_REQ`
   (`XrdCryptosslX509Req`), so a DER request fails to parse and the client declines with
   **"could not resolve proxy request."** Fix: `delegation.c` now re-encodes the request to PEM
   at the wire edge (`gsi_req_der_to_pem`); the crypto core keeps its DER output (still consumed
   as DER by `brix_gsi_sign_pxyreq` and its unit tests).

2. **Client cert chain rejected on an AKID/SKID mismatch.** Real `xrdgsiproxy`/`voms-proxy-init`
   proxies copy the EEC's `authorityKeyIdentifier` verbatim, so the proxy's AKID points at the
   CA rather than the signing EEC. OpenSSL's default `check_issued` then rejects the EEC as the
   proxy's issuer (`X509_V_ERR_AKID_SKID_MISMATCH`) and reports **"unable to get local issuer
   certificate."** This surfaces only once the EEC carries a `subjectKeyIdentifier` (every real
   grid cert does). The reference server (`XrdCryptosslX509Chain`) selects issuers by name +
   signature and ignores the AKID hint. Fix: `src/auth/crypto/pki_build.c` installs a proxy-tolerant
   `check_issued` on proxy-verification stores (scoped to `EXFLAG_PROXY` subjects; the RSA
   signature is still verified, so only issuer *selection* is relaxed).

3. **Test PKI lacked `keyUsage` (confound).** GSI proxy signing (`X509SignProxyReq`) rejects a
   signing chain whose EEC has no `keyUsage`. `tests/pki_helpers.py`, `utils/voms_proxy_fake.py`,
   and the inline PKI in `tests/test_tpc_delegation.py` now mint keyUsage on every cert.

**Trigger correction (supersedes §4d/§4e pessimism):** the stock v5.9.5 client sets its
delegation flags (`kOptsSigReq`/`kOptsDlgPxy`, seen as `opts=0x85` server-side) **only for a
real `xrdcp --tpc delegate` operation** — the plain `XrdSecGSIDELEGPROXY` env var leaves
`dlgpxy=0` ("Proxy delegation option: 0") and the client declines regardless of server
correctness. The capture test therefore drives delegation with `--tpc delegate only`. The
"infeasible / needs a real grid host" conclusion in §4d was **wrong** — it was an artifact of
(a) the env-var trigger not arming delegation and (b) the keyUsage confound masking the two real
server bugs.

**Outbound pull also fixed.** The *use* of the captured proxy — the dest→source TPC pull — then
failed with `TPC kXR_open recv failed`. Root cause: the dest authenticated to the source **as the
user** (delegation working) but presented the anonymous-rendezvous `?tpc.key=` opaque, so the
source deferred the open with `kXR_waitresp` awaiting a client-side authorization the delegate
flow never issues → the dest timed out. Fix (`src/tpc/outbound/source.c`): when a delegated credential is
held, open the source file **directly** (no `tpc.key`), since the dest is authenticated as the
file owner. `test_dest_pulls_as_user_via_delegation` is now GREEN. **The full F6 chain works
end-to-end** (`test_tpc_delegation.py`: 4 passed). See the long-form walkthrough
[`gsi-delegation-capture-fix-walkthrough.md`](gsi-delegation-capture-fix-walkthrough.md) §9.

The historical analysis below (§1–§5) is retained as the investigation trail; where it concludes
"infeasible" or "not pinned to a single line," §0 is authoritative.

---

## 1. Summary (TL;DR)

When a GSI client delegates an X.509 proxy to our nginx XRootD server
(`brix_tpc_delegate on`), our server runs the inbound delegation handshake
(`src/auth/gsi/delegation.c`): it sends `kXGS_pxyreq` and waits for the client's
`kXGC_sigpxy` carrying the delegated proxy. **The stock XRootD client (`/usr/bin/xrdcp`,
v5.9.5) declines** — it returns a `kXGC_sigpxy` whose `kXRS_x509` (signed proxy) bucket is
absent, and emits `Not allowed to sign proxy requests`. Our server logs:

```
xrootd: GSI delegation: sent kXGS_pxyreq (awaiting signed proxy)
xrootd: GSI kXGC_sigpxy: signed proxy (kXRS_x509) missing (client declined to delegate?)
```

**This investigation proves the failure is SERVER-SIDE, in our GSI handshake — and disproves
the codebase's own prior diagnosis.**

`tests/test_tpc_delegation.py` marks the dest-side case XFAIL with:

> *"the stock client declines to return a signed proxy under its usedDNS/hostname delegation
> policy in this synthetic-hostname WSL2 rig (needs a real grid host)."*

That explanation is **false**. With **identical** client configuration in the **same**
environment, the stock client delegates **successfully to a stock `xrootd` source** but
**refuses our nginx server**. The differentiator is the server, not the client, the hostname,
or the environment.

---

## 2. The decisive experiment

Built a controlled rig (FQDN PKI + `xrdgsiproxy`-issued user proxy) and pointed the **same**
delegating client at two servers in turn:

| Target | Result |
|---|---|
| **stock `xrootd` source** (`sec.protocol gsi … -dlgpxy:request`) | **delegates OK** — `xrdcp rc=0`, source logs `Subject DN='/O=F6Test/CN=F6 User'` |
| **our nginx server** (`brix_auth gsi; brix_gsi_signed_dh require; brix_tpc_delegate on`) | **client refuses** — `Not allowed to sign proxy requests`, `kXRS_x509` missing |

Client config for **both** (identical): `XrdSecGSIDELEGPROXY=2 XrdSecGSITRUSTDNS=0`,
`X509_USER_PROXY=<xrdgsiproxy proxy>`, server cert `CN=<lowercased socket.getfqdn()>`, connect
by that FQDN.

→ **Same client + same env + same PKI ⇒ stock server works, ours fails ⇒ defect is in our
server's handshake.**

### Reproduction recipe (important environment gotchas)

These took several iterations to get right; document them so the next person doesn't re-derive:

1. **`XrdSecGSITRUSTDNS=0`** on the client. Default (`1`) makes the stock client refuse
   delegation to any DNS-resolved host (`secgsi: proxy delegation forbidden when trusting DNS
   to resolve '<host>'`). This is a *client* policy and a red herring for our bug — set it to
   `0` to get past it.
2. **Server cert `CN` must equal the lowercased `socket.getfqdn()`**, and the client must
   **connect by that FQDN** (the stock client lowercases the connect host). `localhost` also
   works for the hostname match but see (3).
3. **nginx must `listen` on the FQDN's resolved address.** On this host
   `dilbert.localdomain → 127.0.1.1` (via `/etc/hosts`), **not** `127.0.0.1`. Listening on the
   wrong loopback makes the client hang on connect (looks like a delegation hang; it is not).
4. **User proxy from `xrdgsiproxy init`** (a real RFC-3820 proxy), not an ad-hoc OpenSSL cert.
5. **`Secgsi Proxy delegation option: 0` in the client init trace is a RED HERRING.** It reads
   `0` in the **working** (stock) case too. Do not chase it.

---

## 3. What is NOT the cause (ruled out with evidence)

| Hypothesis | Verdict | Evidence |
|---|---|---|
| "Client policy / needs a real grid host" (the XFAIL claim) | **FALSE** | same client delegates to a stock source in this exact env |
| Client `usedDNS`/hostname policy | **not firing** | with `TRUSTDNS=0` + FQDN-CN cert, the `std::cerr "…forbidden when trusting DNS…"` message does **not** appear; client logs `SAN/CN matches` and `Checking cert is for host <fqdn>` succeeds |
| Native client can't delegate | true but irrelevant | `client/lib/sec/sec_gsi.c` has **no** delegation-send code (`clnt_opts 0x80` = "delegated-proxy off"); the e2e must use the **stock** client, which **can** delegate |
| `XrdSecGSIDELEGPROXY` not honored | **FALSE** | the same env delegates to the stock source; `1` and `2` both tried |
| Proxy not delegatable (pathlen) | **FALSE** | `proxy_std`/`xrdgsiproxy` proxy has `Path Length Constraint: infinite` |
| Our proof-of-possession (`signed_rtag`) wrong | **FALSE** | client logs `secgsi_CheckRtag: Random tag successfully checked` for our pxyreq |
| `EEC not found in chain` (client cert-chain msg) | **benign** | appears in the **working** stock case too |
| `gsi_key` (DH signing key) not loaded | **FALSE** | `src/auth/gsi/config.c:154` loads it from `brix_certificate_key`; non-NULL |
| `gsi_use_signed_dh()` returns 0 under `require` | **FALSE** | `src/auth/gsi/cert_response.c:56` returns `1` for `REQUIRE` unconditionally |

---

## 4. The protocol mechanism (authoritative, from `/tmp/brix-src`)

The stock client source `XrdSecgsi/XrdSecProtocolgsi.cc` shows the client's delegation
decision in `ClientDoPxyReq` (≈ line 3435):

```c
if ((hs->Options & kOptsFwdPxy)) {            // forward mode: export proxy private key (kXRS_x509)
    ...
} else {                                       // sign mode
    if (!(hs->Options & kOptsSigReq)) {        // <-- our failure path
        emsg = "Not allowed to sign proxy requests";
        return 0;                              // sends kXGC_sigpxy WITHOUT kXRS_x509
    }
    // else: sign the kXRS_x509_req CSR …
}
```

So the client refuses iff **both** `kOptsFwdPxy` (2) and `kOptsSigReq` (4) are clear in
`hs->Options`. Those flags originate from the client's `XrdSecGSIDELEGPROXY` (always sets
`kOptsSigReq` when delegation is enabled) and are **cleared** in `ClientDoCert` by exactly two
conditions (≈ lines 3266 and 3316):

```c
// (A) used DNS to resolve the host  →  clear flags + std::cerr "…forbidden when trusting DNS…"
if (usedDNS || (SrvAllowedNames && !ServerCertNameOK(...))) { hs->Options &= ~(kOptsFwdPxy|kOptsSigReq); … }

// (B) server did NOT provide signed DH  →  clear flags + PRINT "…no signed DH parameters… Will not delegate"
if (hs->RemVers >= XrdSecgsiVersDHsigned /*10400*/) { /* read & verify kXRS_cipher (signed DH) */ }
else                                                { hs->Options &= ~(kOptsFwdPxy|kOptsSigReq); … }
```

**Note the model question is settled:** our `delegation.c` uses the **sign-request** model
(sends `kXRS_x509_req`, type 3024), while the stock source uses the **forward** model (sends
**no** `kXRS_x509_req`; the client exports its proxy private key as `kXRS_x509`). Bucket
comparison confirmed: stock sends `kXRS_x509_req` **0×**, ours **3×**. **However**, the
sign-request model is *legitimate* (the client supports it when `kOptsSigReq` survives) — so
the model difference is not, by itself, the bug. The bug is that **`kOptsSigReq` is cleared**
before `ClientDoPxyReq` for our server.

---

### 4a. The precise server-side defect (sharpened)

The stock **server** chooses the delegation *type* from the **client's advertised options**
(`XrdSecProtocolgsi.cc` ≈ lines 3907-3909):

```c
needReq = ((PxyReqOpts & kOptsSrvReq) && (hs->Options & kOptsSigReq)) ||
          (hs->Options & kOptsDlgPxy);
if (needReq || (hs->Options & kOptsFwdPxy)) { … send the appropriate pxyreq … }
```

where `hs->Options` on the server is the client's flags, read from the **`kXRS_clnt_opts`**
bucket (type **3019**) the client marshals during login (`MarshalBucket(kXRS_clnt_opts, …)`).
A stock server therefore sends a **CSR** (`kXRS_x509_req`) only when the client asked for
`kOptsDlgPxy`, and uses the **forward** flow when the client asked for `kOptsFwdPxy`
(`XrdSecGSIDELEGPROXY=2`, the common default).

**Our server does neither.** `src/auth/gsi/delegation.c::brix_gsi_begin_delegation` **hardcodes**
the CSR model — it always builds and sends `kXRS_x509_req` — and **our server never reads the
client's `kXRS_clnt_opts` (3019)** (the constant exists in `src/protocols/root/protocol/gsi.h:48` and we only
ever *send* it as a client in `src/auth/gsi/gsi_core.c:106`; there is no server-side read). So a
forward-mode client receives a CSR it will not sign → `Not allowed to sign proxy requests`.

**This is the concrete thing to fix:** read `kXRS_clnt_opts` on the server during the GSI login,
record the client's delegation mode on `ctx`, and in `begin_delegation`/`handle_sigpxy` honor it
— at minimum implement the **forward** flow (no `kXRS_x509_req`; accept the client's exported
proxy **private key** as `kXRS_x509` and assemble it with the already-captured client chain into
`ctx->gsi_deleg_proxy_pem`).

## 4b. Follow-up findings (2026-07-01, second session) — these REVISE §4/§4a

Deeper reading + empirical capture corrected two assumptions above:

1. **`XrdSecGSIDELEGPROXY=2` is CLAMPED to 0 by the stock client.**
   `XrdSecProtocolgsi.cc:2741`: `opts.dlgpxy = (dlgpxy >= dlgIgnore && dlgpxy <= dlgReqSign)
   ? dlgpxy : 0;` with `dlgReqSign = 1`. The env var can therefore only select `0` (off) or
   `1` (`dlgReqSign`, **sign** mode); `dlgSendpxy = 2` (forward) is marked *"Only client can
   set this!"* and is **not** reachable from the environment. **So every `=2` test in §2/§4 was
   a no-op (no delegation requested by the client at all).** The only env-selectable delegation
   mode is `=1` (sign-request), which uses **our existing CSR model** — and it **still fails**
   against our server.

2. **The client does NOT advertise its delegation intent in `kXRS_clnt_opts`.** Empirically,
   the stock source logged `options req by client: 128` then `160` — i.e. `kOptsCreatePxy`
   (+`0x20`), with **none** of `kOptsDlgPxy(1)/kOptsFwdPxy(2)/kOptsSigReq(4)`. The client keeps
   its delegation mode **local**; the server drives delegation from **its own** config
   (stock `-dlgpxy:request` sets `kOptsSrvReq`). **Reading `kXRS_clnt_opts` on the server is
   therefore NOT the fix** (the flags aren't there). A diagnostic read was added anyway
   (`src/auth/gsi/cert_response.c: gsi_certreq_clnt_opts` → `ctx->gsi_clnt_opts`, logged at INFO) —
   it is regression-safe and useful, but it is **not** a functional change.

**Net:** the "forward vs sign model" framing is a red herring for the *env-driven* client. The
concrete open defect is narrower: **with `=1` (sign mode), the stock client receives our CSR
(`kXRS_x509_req`) and our verified proof-of-possession, yet returns a `kXGC_sigpxy` without the
signed proxy** — while the *same* client signs for a stock `-dlgpxy:request` source.

## 4c. ROOT CAUSE — gdb-verified (2026-07-01, third session)

Stepping the stock client (`/usr/bin/xrdcp` → stripped `libXrdSecgsi-5.so`, function symbols
present) resolved the contradiction **definitively**. `hs->Options` lives at
`*(*(this + 0x1a0) + 0x90)` (derived from the `ClientDoPxyreq` prologue). Breakpoints:

| Observation | Our nginx server | Stock `xrootd` source (delegates OK) |
|---|---|---|
| `ClientDoInit` entry `hs->Options` | `0x0` | — |
| `ClientDoCert` entry `hs->Options` | `0x80` | `0x80` (identical) |
| `ClientDoPxyreq` **called?** | **YES**, `hs->Options = 0xa0` (`fwd=0 sign=0 dlg=0`) → "Not allowed to sign" | **NEVER CALLED** |
| Result | fail | **succeeds (500 bytes)** |

Neither `ClientDoCert` clearing site (`0x20760` = "no signed DH"; `0x20816` = "trusting DNS")
executes — the delegation flags were **never set** in the client's `PxyReqOpts` (`hs->Options`
is `0x80` = `kOptsCreatePxy` only, both against us and against the working stock source).

**Therefore the root cause is architectural, not cryptographic:**

- **Stock delegation is INLINE in the cert exchange.** The server embeds the proxy request in
  its `kXGS_cert` response's `kXRS_main`; the client signs/returns the proxy during
  `ClientDoCert` → its `kXGC_cert` response. **`ClientDoPxyreq` is never involved**, and the
  flow does **not** depend on the client's local `kOptsFwdPxy`/`kOptsSigReq`.
- **Our `delegation.c` does a SEPARATE `kXGS_pxyreq` round** (an extra `kXR_authmore` *after* a
  verified `kXGC_cert`). That round routes to the client's `ClientDoPxyreq`, whose decision
  **does** depend on the client's local delegation flags — which are `0` (the client's
  delegation is **server-driven**, and `XrdSecGSIDELEGPROXY` does not set them the way we
  assumed; `dlgSendpxy=2` is client-set-only and `=1` doesn't survive into `PxyReqOpts`). So the
  stock client always refuses our separate-round request with "Not allowed to sign proxy
  requests".

### The fix (now precisely scoped)

**Move delegation INLINE into the `kXGS_cert` response** (mirror stock `ServerDoCert`,
`XrdSecProtocolgsi.cc` ≈ 3895-3960): when delegation is enabled, build the proxy request (CSR)
and add it to the `kXRS_main` bucket of the `kXGS_cert` we already send (`src/auth/gsi/cert_response.c`),
saving the request key on `ctx`. Then process the returned proxy from the client's `kXGC_cert`
(`src/auth/gsi/parse_x509.c`) — **not** via a separate `kXGS_pxyreq`/`kXGC_sigpxy` round. The existing
`src/auth/gsi/delegation.c` (separate-round machinery) becomes the wrong mechanism for interop and
should be retired or kept only for a peer that advertises the separate-round capability. This is
a real restructuring of the GSI cert exchange, but it is now unambiguous.

## 4d. FEASIBILITY finding — the fix is NOT purely server-side (2026-07-01)

Before implementing the inline restructuring, one more gdb + source check overturned the
implicit assumption that a server-side change can fix this:

- **The client's private key is exported ONLY in `ClientDoPxyreq`** (`kpxy->ExportPrivate`,
  forward branch) **or a CSR is signed ONLY in `ClientDoPxyreq`** (sign branch). There is **no
  key-export / CSR-sign anywhere in `ClientDoCert`**.
- **`ClientDoPxyreq` is rigorously verified NEVER called** in the successful inline flow
  (`ClientDoInit → ClientDoCert` only, for the confirmed-delegating stock `-dlgpxy:request`
  source). Empirically, **no key-bearing delegated-proxy file is ever exported** via
  `-exppxy:<file>` (the source logs a "template" but writes nothing).

**Conclusion:** the stock `-dlgpxy:request` source's inline "Delegated proxy saved" is at most
the client's **proxy CERT CHAIN (no private key)** — **not** a usable credential to authenticate
onward *as the user*. **Usable (key-bearing) delegation requires `ClientDoPxyreq`** (sign or
forward), which fires only when the **client's own** `kOptsSigReq`/`kOptsFwdPxy` flags are set —
and the **stock v5.9.5 client does not set them via `XrdSecGSIDELEGPROXY`** (gdb: `hs->Options`
stays `0x80`; `dlgSendpxy=2` is client-set-only, `=1` does not survive `Init`; the env value
appears clobbered by the `opts.dlgpxy = (dlgpxy … ) ? dlgpxy : 0` line at ≈2741).

**Therefore no change to OUR server can make the Phase-4b e2e pass with this stock,
env-configured client:** it never offers a usable delegated credential to *any* server.
Implementing the inline restructuring would neither help (still no key) nor be verifiable here.
The codebase's XFAIL note was **right about the environment** ("needs a real grid host" / a
genuinely delegating client) even though its stated *mechanism* (usedDNS/hostname policy) was
wrong. Real key-delegation (as used by production TPC) needs a client whose delegation flags are
actually set — via a client build/config that isn't reachable from the env in this rig.

**Recommendation:** do **not** implement a server-side delegation change against this rig. To
progress Phase-4b GSI, obtain a genuinely delegating client (correct client version/config or a
real grid endpoint) and re-test; only then is the inline-vs-separate-round server work
meaningfully verifiable. The threaded upstream-login + fd-handoff forwarding (already built) is
independent and ready for that credential once a real delegating client provides one.

## 4e. Stock-to-stock TPC delegation experiment (2026-07-01) — a MAJOR confound found

Set up **two official `xrootd` v5.9.5 instances** (source + dest, both GSI + `ofs.tpc … pgm
/usr/bin/xrdcp` + `sec.protocol gsi … -dlgpxy:request`) and drove a delegated TPC copy
(`xrdcp --tpc delegate only <src> <dst>`). Instrumenting it overturned/​qualified §4d:

1. **`--tpc delegate` DOES set the client's delegation flags** — the source logs
   `options req by client: 421` (= `kOptsDelPxy|kOptsCreatePxy|kOptsDelChn|kOptsSigReq|
   kOptsDlgPxy`), including the delegation flags that the **env var alone never sets**. So
   delegation *is* triggerable — the env-only path (§4d) was simply the wrong trigger. The
   client then attempts the **sign** model (`X509SignProxyReq`) — exactly what our
   `delegation.c` implements.

2. **GSI proxy delegation REQUIRES the cert/proxy to carry a `keyUsage` extension.** The first
   attempt failed **stock-to-stock** with `cryptossl_X509SignProxyReq: wrong extensions in
   request: 1, 0` — the request had a ProxyCertInfo but **no keyUsage** (`XrdCryptosslgsiAux.cc`
   ≈ line 1148 requires `haskeyusage`). Root cause: **the test PKI's EEC lacked `keyUsage`**
   (created with a bare `openssl x509 -req`), so `xrdgsiproxy` produced a proxy with no
   keyUsage, and signing was rejected. **Adding `keyUsage=critical,digitalSignature,
   keyEncipherment,dataEncipherment` to the EEC** (→ inherited by the proxy) cleared this.
   **This confound was present in EVERY earlier delegation test in this investigation**
   (including those against our nginx server) — a real reason delegation could never have
   succeeded regardless of the server. Real grid certs always carry keyUsage.

3. **After keyUsage, the blocker moved to `Destination does not support delegation`** — a
   stock **TPC-lite** dest-config matter (the dest advertises TPC-lite via the Open/`kXR_query
   tpcdlg`; the dest log still shows `Proxy delegation option: ignore` / `Delegated proxies
   options: 0` despite `-dlgpxy:request`). Getting stock-to-stock TPC-lite to fully succeed
   needs more XRootD TPC config nuance (`ofs.tpc … fcreds`, the dest's delegated-TPC
   advertisement) and was not cracked in this session.

**Bearing on Phase-4b:** the keyUsage finding means the earlier "infeasible" conclusion (§4d)
is **not proven** — the tests that reached the signing step were doomed by missing keyUsage,
not (only) by architecture. The two open questions for a real re-test are now precise: (a) use
**keyUsage-bearing** certs, and (b) trigger delegation via a real delegating client
(`--tpc delegate` / a client that sets the flags — the env var does **not**). Whether our
separate-round `delegation.c` then succeeds, or still needs the inline restructuring (§4c), is
newly testable once (a)+(b) hold. Harness recipe: two `xrootd` instances with GSI + `ofs.tpc`,
EEC with `keyUsage`, `xrdgsiproxy` proxy, `xrdcp --tpc delegate only`.

## 5. The residual contradiction — RESOLVED (see §4c, §4d, §4e)

For our server, `kOptsSigReq` is demonstrably cleared (client says "Not allowed to sign"), but
**neither documented clearing condition is observed to fire**:

- **Condition (A) usedDNS:** the `std::cerr` "forbidden when trusting DNS" message (which is
  **not** debug-gated) does **not** appear with `TRUSTDNS=0` + FQDN-CN cert. `usedDNS` is
  false.
- **Condition (B) no-signed-DH:** our server advertises version **10600** (`secgsi_getCredentials:
  version run by server: 10600`) ≥ `XrdSecgsiVersDHsigned` (10400), and `brix_gsi_signed_dh
  require` makes `gsi_use_signed_dh()` return 1 with `gsi_key` loaded — so we send `kXRS_cipher`
  (signed DH), and the client's later `CheckRtag` succeeds (so the session cipher *was*
  established). The signed branch should be taken, and on failure it would be a **hard error**
  (`"decrypting server DH public parameters"`), not a silent disable — and no such error appears.

So either (a) there is a **third** flag-clearing path / the client computes `hs->Options` from
the **server-echoed** options in `ParseServerInput` (not yet read), or (b) our `kXGS_cert`
signed-DH bucket is subtly malformed such that the client's `DecryptPublic` returns a value
that neither errors **nor** counts as "signed" (e.g. an IV/`useIV` mismatch — note
`useIV = (RemVers >= 10400)`; or signing the DH `Public()` blob differently than the client
verifies). 

### Concrete next steps

1. **Read the stock client `ParseServerInput`** (how the client derives/keeps `hs->Options`
   from the **server's** kXGS_cert — does the server need to echo `kOptsSrvReq`/options in a
   bucket we omit?). Grep targets in `XrdSecProtocolgsi.cc`: `kXRS_clnt_opts`, `hs->Options`,
   `ParseServerInput`, lines 3699/3735/3907 (server-side request gating).
2. **Byte-diff our `kXGS_cert` vs a stock signed-DH server's** at the bucket level (types,
   sizes, and the `kXRS_cipher` signed-DH blob + IV handling). Use `XrdSecDEBUG=3` and dump the
   `IN: kXGS_cert` buckets from each client log. Our `src/auth/gsi/cert_response.c` builds the
   signed DH at ≈ lines 220-245 (`EncryptPrivate` of the `Public()` blob as `kXRS_cipher`);
   compare against the stock server path (`XrdSecProtocolgsi.cc` ≈ line 3016 onward, note
   `useIV`).
3. **Add a temporary server-side trace** of the exact `kXRS_cipher` bytes + whether `useIV`
   is set, and confirm the client's `DecryptPublic` actually validates them (a stock client
   built with `-g` can be stepped, or add prints to a local XrdSecgsi build).

---

## 6. Phase-4b status (what IS done)

The terminating tap proxy's **forwarding** half is complete and compiles (see
`docs/superpowers/plans/2026-06-30-gsi-delegation-tap-proxy-phase4b.md`):

- `brix_tap_proxy_auth gsi` mode + auto-enable of delegation capture
  (`src/net/proxy/directives.c`, `src/core/config/runtime_server.c`).
- `src/net/proxy/gsi_upstream.c` — secure-temp writer for the delegated proxy (unit-tested).
- `src/net/proxy/gsi_upstream_login.c` — threaded blocking GSI login to the upstream **as the
  user**, reusing the proven cache origin client, then fd-handoff into the async relay.

This forwarding path behaved **correctly** in testing (it requested delegation and would have
forwarded the captured proxy). It is gated entirely by the **capture** defect documented above.
The foundation (blocking in-process GSI client authenticating a GSI upstream with an X.509
proxy) is verified independently by `tests/run_credential_xroot_gsi.sh` (passes).

**Bottom line:** once `delegation.c`'s capture is fixed so the stock client returns a signed
proxy, the existing forwarding completes the end-to-end path, verifiable with
`tests/run_tap_proxy_gsi.sh` (the harness exists, currently fails at capture).
