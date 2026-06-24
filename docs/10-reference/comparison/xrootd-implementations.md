# The `root://` Protocol Across Five Implementations (+ the gfal2 WLCG Client) — A Code-Level Comparison

> **Scope.** A deep, code-level comparison of how the XRootD `root://` wire
> protocol — framing, handshake, login, security/GSI, and the data plane — is
> implemented across five codebases, plus one client *consumer* (gfal2) included
> because it is what production WLCG transfers (FTS, Rucio) actually run:
>
> | Codebase | Language | Role analyzed |
> |---|---|---|
> | **XRootD** | C++ | the reference (`XrdXrootd`, `XrdSec*`, `XrdCrypto`) |
> | **EOS** | C++ | CERN storage; XRootD plugin consumer |
> | **dCache / xrootd4j** | Java (Netty) | clean-room protocol reimplementation |
> | **go-hep** | Go | clean-room protocol reimplementation |
> | **nginx-xrootd** | C | this project — nginx stream module (server) + native client |
> | **gfal2** | C++ (delegates) | *consumer / aggregator* — `root://` via the official `libXrdCl`, `davs://` via `davix`; the FTS/Rucio data-management layer (§7.6) |
>
> **gfal2 is not a sixth protocol implementation.** Its xrootd plugin
> (`libgfal_plugin_xrootd.so`) links and drives the reference `libXrdCl`, so on the
> `root://` wire it *is* the XRootD C++ column — it therefore gets no separate
> byte-level rows in the framing/handshake/GSI tables (they would merely duplicate
> XRootD C++). It is analyzed as a real-world *client* (§7.6): what testing it
> revealed, and where its multi-protocol abstraction (davix for `davs://`) exposed
> a server-side conformance bug. Findings:
> [`gfal-interop-findings.md`](gfal-interop-findings.md); tests:
> `tests/test_gfal_interop.py`.
>
> All five trees were read locally. File:line citations refer to the upstream
> source at the revision checked out during analysis (XRootD `/tmp/xrootd-src`,
> others cloned shallow from GitHub master); treat them as navigational anchors,
> not eternal coordinates.
>
> **Status:** reference document. The GSI interoperability findings here were
> verified live against real EOS (`eoslhcb.cern.ch`) and real dCache
> (`lhcbdcache-kit.gridka.de`) with an LHCb VOMS proxy.

---

## 0. Executive summary — there are four protocol implementations, not five

The codebases fall into four strategies:

* **Reference** — XRootD C++ defines the wire and the canonical GSI behavior.
* **Reuse** — **EOS does not implement the protocol at all.** It loads into the
  stock `xrootd` daemon as `XrdSfsFileSystem`/`XrdOss` plugins. Every byte of
  framing, handshake, login, and `XrdSec`/GSI is inherited, unmodified, from
  XRootD C++. EOS's contribution lives strictly *above* the protocol (a
  capability-signed MGM→FST redirect model and an `XrdSecEntity`→virtual-identity
  mapping).
* **Reimplement** — **dCache (Java/Netty)**, **go-hep (Go)**, and **nginx-xrootd
  (C)** each parse `kXR_*` PDUs themselves, because none can load a C++ plugin
  into their runtime (JVM / Go / nginx). These are the three genuinely
  independent reimplementations.
* **Consume / aggregate** — **gfal2 does not touch the wire either**, but on the
  *client* side: it is a uniform data-management API (open/copy/stat/checksum/TPC)
  over pluggable backends, and for `root://` it delegates to the reference
  `libXrdCl`, for `davs://` to `davix`. It is the client analogue of EOS's reuse —
  zero protocol code of its own, value added *above* the transport (multi-protocol
  abstraction, third-party-copy orchestration, retries, Want-Digest checksums).
  It matters here because it is the dominant production WLCG client (FTS, Rucio).

Consequently the interesting axis of comparison is **XRootD C++ vs. xrootd4j vs.
go-hep vs. nginx-xrootd**, with EOS standing in for "stock C++ + storage
semantics."

**One-line characterization of each:**

* **XRootD C++** — event-driven server (continuation/`Resume` pattern) + a fully
  asynchronous client (thread-pool `PostMaster`); the source of every wire fact.
* **EOS** — maximal reuse: stock XRootD daemon + OFS/MGM/FST plugins + signed
  capability redirects + VID mapping + optional protobuf/ZMQ remote auth.
* **dCache/xrootd4j** — a clean Netty pipeline; full GSI (server + TPC client) but
  pinned to an older GSI dialect (sha1/md5, 512-bit DH) and **no paged I/O**.
* **go-hep** — an idiomatic, well-factored, but deliberately narrow Go port
  pinned to **protocol v3.1 (2012)**: no TLS, no GSI/token/SSS, no readv/pgread.
* **nginx-xrootd** — the only event-loop reimplementation; full GSI/token/SSS +
  TLS + readv + pgread; unique **shared client/server crypto core** making the
  two ends provably wire-inverse.
* **gfal2** — not an implementation but the *production client*: one API over
  `libXrdCl` (`root://`) + `davix` (`davs://`) + gridftp/srm/s3; what FTS and Rucio
  drive. Its value (and its interop risk) is the abstraction layer, not the wire.

---

## 1. Architecture and concurrency model

### XRootD C++ (`/tmp/xrootd-src`)
* **Server (`XrdXrootd/`)**: non-blocking, with a **continuation pattern** rather
  than blocking reads. Each connection is a pooled `XrdProtocol` implementing
  Match/Process/Recycle (`XrdXrootdProtocol.hh:187-195`); a partial socket read
  stashes state and returns to be rescheduled via the `Resume` member function
  pointer (`XrdXrootdProtocol.hh:589`, driven from `Process()`).
* **Client (`XrdCl/`)**: fully async. A single `PostMaster` owns ~10 poller
  threads (`XrdSys::IOEvents`, built-in poller only — the libevent backend is not
  present in this tree), 3 `JobManager` callback workers, and 1 `TaskManager`
  timer thread. Ownership: `PostMaster`→`Channel`→`Stream`→`AsyncSocketHandler`.

### EOS (`/tmp/xrootd-cmp/eos`)
Two stock `xrootd` daemons, each loading an EOS OFS plugin via `xrootd.fslib`:
* **MGM** (`libXrdEosMgm.so`): `XrdMgmOfs : public XrdSfsFileSystem`
  (`mgm/ofs/XrdMgmOfs.hh:254`). The plugin factory `XrdSfsGetFileSystem2`
  (`mgm/ofs/XrdMgmOfs.cc:272`) returns the singleton and sets
  `IsRedirect = true` — the MGM is a metadata redirector.
* **FST** (`libXrdEosFst.so` + `libEosFstOss.so`):
  `XrdFstOfs : public XrdOfs` (`fst/XrdFstOfs.hh:84`),
  `XrdFstOss : public XrdOss` (`fst/XrdFstOss.hh:46`).

The concurrency model is therefore *exactly* stock XRootD's; EOS only supplies
virtual-method overrides.

### dCache / xrootd4j (`/tmp/xrootd-cmp/xrootd4j`)
A pure **Netty `ChannelHandler` pipeline** (`DataServerChannelInitializer.java:60-123`):
`handshaker → encoder → decoder → session-handler → chunk-writer → data-server`.
The chosen `XrootdAuthenticationHandler` is **inserted into the pipeline lazily**,
"just at the time of the authentication request" — a clean use of Netty's dynamic
pipeline. Raw bytes → typed `XrootdRequest` (decoder) → `doOnXxxRequest` dispatch
→ `XrootdResponse` (encoder). The decoder also performs **write-request
segmentation** (`AbstractXrootdDecoder.verifyMessageLength():182-250`): only
`kXR_write` may exceed `maxWriteBufferSize`; other oversized frames disconnect.

### go-hep (`/tmp/xrootd-cmp/gohep/xrootd`)
**Goroutine-per-connection.** Client `cliSession` (`session.go:40`) runs a single
`consume()` reader goroutine that fans responses out by StreamID through a `mux`
(`internal/mux/mux.go`); caller goroutines block on per-request channels. Server
spawns **one goroutine per request** (`server.go:183`) and writes each response in
a single `Write` to avoid write-serialization. The protocol is built on four
small interfaces — `Request`, `Response`, `Marshaler`, `Unmarshaler`
(`xrdproto/xrdproto.go:21-54`) — with a `gen-marshal.go` code generator. Two
sharp edges: it **panics** on an initial-session read error (`session.go:177`,
acknowledged TODO) and on an unroutable StreamID (`:263`); and the mux's
`SendData` blocks into an unbuffered channel while holding the mutex
(`mux.go:214`), so one slow caller stalls fan-out for the whole connection.

### nginx-xrootd (`src/`, `client/`)
The only **event-loop** reimplementation. Registers as `NGX_STREAM_MODULE`
(`src/stream/module_definition.c:18`); protocol logic is single-threaded per
worker (epoll/kqueue). The recv path (`src/connection/recv.c`) is a
byte-accumulating state machine: `HANDSHAKE(20B) → REQ_HEADER(24B) →
REQ_PAYLOAD(dlen) → dispatch`, with suspend states (`SENDING`, `AIO`, `UPSTREAM`,
`TLS_HANDSHAKE`, …) that return to the loop immediately. **Blocking work is
exiled from the loop**: file I/O and DH keygen go to a thread pool / per-worker
keypool, and results re-enter via done-callbacks. The native client (`client/`)
is the inverse — **synchronous/blocking** with `poll(2)` deadlines.

> **Architectural consequence unique to nginx-xrootd.** Because the protocol runs
> on nginx's shared worker loop, *every* potentially-blocking crypto primitive
> must sit behind a pool or cache or it stalls unrelated traffic. This is why the
> module has a GSI handshake in-flight gauge (sheds with `kXR_wait`), a per-worker
> DH keypool (so `ffdhe2048` keygen never runs inline under a `certreq` burst),
> and always-on per-worker token L1 + optional SHM L2 validation caches (so
> RSA/ECDSA verify never re-runs on the loop). XRootD C++ avoids the problem with
> threads, go-hep with goroutines, dCache with Netty's executor group.

---

## 2. Wire framing — universal agreement

This is the most stable layer; all five are byte-identical.

* **Endianness:** network byte order (big-endian) everywhere. Netty `ByteBuf`
  (dCache) and Go `binary.BigEndian` (go-hep) default to it; C/C++ use
  `htonl`/`ntohl`.
* **Client request header (24 bytes):** `streamid[2] | requestid[2] | body[16] |
  dlen[4]`. (XRootD `XProtocol.hh:157`; dCache `CLIENT_REQUEST_LEN=24`,
  decoder reads dlen at offset 20; go-hep `ReadRequest` reads a fixed 24-byte
  prefix and extracts dlen from bytes `[20:24]`; nginx-xrootd
  `src/protocol/wire_core_requests.h:98`, parsed in `recv.c:375`.)
* **Server response header (8 bytes):** `streamid[2] | status[2] | dlen[4]`.
* **`streamid` is opaque** — matched/echoed as raw bytes, **never byte-swapped**,
  in *all* implementations. Only `requestid`/`status`/`dlen` and per-opcode body
  fields are swapped. Any reimplementation that byte-swaps the streamid would
  fail to match responses.

Dispatch mechanism is the only difference, and it is purely stylistic:
XRootD splits the `switch` "to help the compiler" (`XrdXrootdProtocol.cc:439`);
xrootd4j maps opcode→typed object then switches on type; go-hep uses the
`Marshaler`/`Unmarshaler` interface pair; nginx-xrootd uses a cascade of
single-purpose dispatchers with macro-encoded auth gates (`src/handshake/dispatch.c`).

---

## 3. Handshake, `kXR_protocol`, and TLS — the first divergence

The **20-byte initial handshake** `{0,0,0,4,2012}` (the trailing `0x000007dc` =
2012 is the historical magic) is identical everywhere. Notably XRootD C++
validates it *loosely* — the real gate is "first three words zero, fourth word
== 4"; the magic word is historical (`XrdXrootdProtocol.cc:311-325`). dCache and
go-hep, by contrast, do **exact** byte-vector matches (`XrootdHandshakeHandler`
compares against a fixed array; go-hep does `reflect.DeepEqual`), and nginx-xrootd
validates `fourth==4 && fifth==ROOTD_PQ` (`src/handshake/client_hello.c:66`).

The divergences are **reported protocol version** and **TLS support**:

| | Version reported | TLS / `roots://` |
|---|---|---|
| XRootD C++ | `0x520` (5.2) | full negotiation: `kXR_haveTLS/gotoTLS/tlsLogin/tlsSess/tlsData` |
| EOS | stock (`0x500`+) | full (stock) |
| dCache xrootd4j | `0x500` (5.0) | TLS-aware flags; standalone server can `startTls(true)` |
| **go-hep** | **`0x310` (3.1, 2012)** | **none** — no `crypto/tls`, no `gotoTLS`, no path to upgrade |
| nginx-xrootd | 5.x | full: `haveTLS\|gotoTLS\|tlsLogin`, upgrade via `ngx_ssl_create_connection` |

> **go-hep is frozen at the 2012 v3.1 protocol** and never negotiates TLS. For
> modern WLCG endpoints (increasingly TLS-required) this is disqualifying on its
> own, independent of its auth gaps (§5).

`kXR_protocol` negotiation: all advertise server flags (`kXR_isServer`,
capability bits). nginx-xrootd, when the client sets `kXR_secreqs`, appends a
SecurityInfo trailer enumerating enabled plugins as 8-byte entries plus the
signing security level (`src/session/protocol.c:144`). dCache forces
`SigningPolicy.OFF` when TLS is active (TLS already provides integrity) — a
sensible optimization the others could adopt.

---

## 4. Login

Converged: 8-byte username, pid, capver (async bit `0x80` + protocol version in
the low bits), 16-byte session id, optional trailing CGI/security blob.

* **Session id:** XRootD derives it from FD/Inst/PID/SID then masks
  (`XrdXrootdXeq.cc:1105`); go-hep and nginx-xrootd generate 16 random-ish bytes
  (nginx-xrootd explicitly notes its sessid is *not* crypto-grade,
  `src/connection/handler.c:80`).
* **Anonymous handling differs:** nginx-xrootd rejects non-printable usernames
  (`src/session/login.c:88`) and only sets `auth_done=1` immediately for
  `XROOTD_AUTH_NONE`; dCache leaves anonymity to the application; go-hep's default
  server is anonymous-only (echoes the sessid with no security blob).
* **Auth trigger:** when security is configured, the login response carries the
  `&P=...` list and forces a follow-up `kXR_auth` (XRootD sets
  `XRD_LOGGEDIN|XRD_NEED_AUTH`; nginx-xrootd leaves `auth_done=0`).

---

## 5. Security / authentication — the substantive divergence

### 5.1 Mechanism coverage

| Mechanism | XRootD C++ / EOS | dCache xrootd4j | go-hep | nginx-xrootd |
|---|---|---|---|---|
| GSI (X.509 proxy) | ✅ (signed-DH, delegation, VOMS) | ✅ (server + TPC client) | ❌ **absent** | ✅ (server + native client) |
| ztn / WLCG token | ✅ | ✅ | ❌ | ✅ (JWKS + L1/L2 cache) |
| krb5 | ✅ | ✅ | ✅ (real, via `gokrb5`) | ✅ |
| sss (shared secret) | ✅ | ✅ | ❌ | ✅ |
| unix / host | ✅ | ✅ | ✅ | ✅ |
| sigver (request signing) | ✅ | infra present, OFF in bundled server | ✅ (SHA-256 framing) | ✅ (shared HMAC, fail-closed) |

> **go-hep cannot authenticate to grid storage.** It implements only unix, host,
> and krb5 (the krb5 path is genuine, using `github.com/jcmturner/gokrb5/v8`).
> There is no GSI, no token, no SSS. Since GSI/X.509 proxies remain the dominant
> WLCG mechanism, go-hep is unusable against a typical production endpoint.

### 5.2 The GSI handshake — the byte-exact, interop-critical layer

All implementations that do GSI share the same *shape*: two rounds
(`kXGC_certreq` → `kXGS_cert`/authmore → `kXGC_cert` → ok), a serialized vector
of typed buckets terminated by `kXRS_none=0`, Diffie-Hellman key agreement, an
AES-CBC session cipher keyed by the **first N bytes of the DH shared secret**, and
RSA proof-of-possession (each side signs the peer's random tag with its private
key). The bucket types are constant across all
(`kXRS_cryptomod=3000, main=3001, puk=3004, cipher=3005, rtag=3006,
signed_rtag=3007, x509=3022, cipher_alg=3025, md_alg=3026`).

The **details diverge in exactly the places that determine interop**:

| GSI detail | XRootD C++ (reference) | dCache xrootd4j | nginx-xrootd |
|---|---|---|---|
| `XrdSecgsiVers` advertised | 10400 / 10600 | **10400** | 10600 (signed-DH default) |
| Digests offered | `sha256:sha1:…` | **`sha1:md5` only** | `sha256:sha1`; client prefers sha256 else echoes server's first |
| `kXRS_md_alg` bucket | present | **mandatory** — NPE (`digestBucket null`) if absent | always emitted |
| Cipher | `aes-128-cbc` first | **`aes-128-cbc` only** | allowlist `{aes-128/256-cbc, bf-cbc, 3des}`, aes-128 preferred |
| **IV decision** | `useIV = (RemVers≥10400)`; length carried as `cipher_alg "name#ivlen"` (`XrdSecProtocolgsi.cc:3336`) | `_sessionIVLen` from version; **parses `#ivlen`** | `use_iv = signed_dh`; bare cipher name; server parses `#ivlen` defensively |
| DH secret padding | `nopad` cryptomod tag; pad iff both support (`set_dh_pad`) | `paddedKey` flag: `generateSecret()` vs `"TlsPremasterSecret"` + encrypt-only trailing-zero re-pad | `dh_pad=1` signed / `0` unsigned, negotiated vs peer `nopad` |
| AES key | first 16 B of secret (AES rejects variable keylen → `SetBuffer(ldef)`) | first 16 B (`SecretKeySpec(encoded,0,16)`) | first `key_len` B |
| IV byte distribution | **alphanumeric-only** (`XrdSutRndm` opt 3) | **alphanumeric-only** (rejection-sampled `[.-9A-Za-z]`) | random binary (transported, length-stripped) |
| `kXRS_none` terminator | written | **parses *until* terminator** — overruns buffer if absent | appended on inner buffer |

#### How the IV mechanism actually works (the subtle bit)

The reference is unambiguous and contradicts a tempting misreading: **`useIV` is
gated on the negotiated GSI version, not on the cipher-name suffix.** For
`RemVers ≥ XrdSecgsiVersDHsigned(10400)` the client both prepends a fresh IV to
the encrypted main *and* advertises its length by appending `#<ivlen>` to the
`kXRS_cipher_alg` value it sends (`XrdSecProtocolgsi.cc:3336-3343`):

```cpp
if (hs->RemVers >= XrdSecgsiVersDHsigned) {
   String cipiv; String::form(cipiv, "%s#%d", cip.c_str(), sessionKey->MaxIVLength());
   br->UpdateBucket(cipiv, kXRS_cipher_alg);
} else {
   br->UpdateBucket(cip, kXRS_cipher_alg);     // legacy: bare name, no IV
}
```

The server splits on `#` to learn the IV length (`:3674-3692`). The corollary is
that **the IV-present bit and the `#ivlen` suffix must agree**: prepending an IV
under a bare cipher name (or advertising a suffix while sending no IV) desyncs the
CBC block alignment and the peer fails to decrypt. This is precisely the failure
mode that surfaced during nginx-xrootd interop testing — see §5.4.

#### The DH-padding dance (dCache's brittleness)

`DHSession.translate()` (`xrootd4j-gsi/.../DHSession.java:325-386`) has two
secret-derivation paths switched by a `paddedKey` boolean:

```java
if (paddedKey)  encoded = _keyAgreement.generateSecret();                 // BC-pads to prime size
else            encoded = _keyAgreement.generateSecret("TlsPremasterSecret").getEncoded(); // unpadded, pre-1.50 BC
```

plus an **encrypt-only** trailing-zero re-pad (`Arrays.copyOf(defective,
blocksize)`, `:365`) whose comment explicitly says the non-Tls encoding "pads by
prepending, not appending; this seems to be unacceptable to servers using the ssl
`DH_compute_key` (unpadded) method." This entire mechanism exists to match
OpenSSL's `DH_compute_key` vs `DH_compute_key_padded` byte-for-byte, and it is
sensitive to the BouncyCastle version. The post-4.9 server flips `paddedKey=true`
before the cert step; the default is `false`. XRootD C++ achieves the same
agreement far more simply via the `nopad` cryptomod tag and
`EVP_PKEY_CTX_set_dh_pad`.

### 5.3 EOS's auth is a different axis

EOS does the *transport* handshake with stock `XrdSec` — the
`&P=krb5…&P=gsi,v:10600,c:ssl…&P=sss…&P=unix` list is **pure configuration**
(`sec.protocol` + `sec.protbind` in `misc/etc/xrd.cf.mgm`), not code. It then maps
the resulting `XrdSecEntity` to an EOS **VirtualIdentity**
(`common/Mapping.cc:187`), branching per protocol (`gsi:`/`krb5:`/`sss:`/`https:`/
`ztn:` gridmap keys) to derive uid/gid. Optionally it forwards the entire
`XrdSecEntity` over **protobuf/ZMQ** to a remote MGM via `libEosAuthOfs.so`
(`auth_plugin/proto/XrdSecEntity.proto`). None of the §5.2 byte-level GSI logic is
EOS code — it is inherited.

### 5.4 Interop landmines (empirically confirmed)

The following broke nginx-xrootd against **real dCache** and **real EOS** in turn;
each row maps to a column in the §5.2 table. They are the practical takeaways of
this whole comparison:

1. **Missing `kXRS_md_alg` → dCache server NPE** (`StringBucket.getContent()` on a
   null `digestBucket`). Fix: always emit the digest bucket.
2. **dCache offers no sha256** (`sha1:md5` only) and rejects any digest not in its
   offered set ("all sender digests are unsupported"). Fix: echo a digest from the
   server's offered list, preferring sha256 when present.
3. **The IV must follow the version-gated rule, not a guess.** An "IV-less"
   experiment (bare cipher name, no IV) satisfied old dCache but **broke modern
   EOS** (`client certificate missing: kXGC_cert` — EOS expected the IV). The
   correct, universal behavior is the reference's: IV on for signed-DH
   (`≥10400`), advertised via the `#ivlen` suffix. Verified working against EOS
   (`v:10600`) *and* dCache (`v:10400`) simultaneously.
4. **`kXRS_none` terminator** on the encrypted inner bucket list — dCache parses
   buckets until the terminator and overruns (`readerIndex exceeds writerIndex`)
   without it.
5. **CA trust** — the client must load the IGTF grid CAs
   (`/etc/grid-security/certificates`, an OpenSSL *CApath* hash directory), not
   the system bundle, or TLS verification fails with "unable to get local issuer
   certificate" before GSI even begins.

### 5.5 Request signing (sigver)

XRootD C++, go-hep, and nginx-xrootd all implement `kXR_sigver`; dCache has the
infrastructure but ships it OFF in the bundled standalone server. nginx-xrootd's
implementation is notable for using the **shared** HMAC kernel
(`xrootd_gsi_sigver_hmac` over `seqno_be(8) || hdr24 || [payload unless nodata]`),
a shared opcode→level policy table, constant-time compare (`CRYPTO_memcmp`), and
**fail-closed** enforcement (`src/handshake/sigver.c`): unsigned mutating ops are
rejected, and in pedantic mode `nodata`-with-payload is rejected.

---

## 6. Data plane

| Feature | XRootD C++ / EOS | dCache xrootd4j | go-hep | nginx-xrootd |
|---|---|---|---|---|
| open/read/write/stat/dirlist | ✅ | ✅ | ✅ (server subset narrower than client) | ✅ |
| **readv** (`kXR_readv`) | ✅ | ✅ (chunked) | ❌ **absent** | ✅ (coalesced `preadv`, ≤64 iovecs) |
| **pgread/pgwrite + `kXR_status(4007)` + per-page CRC32c** | ✅ | ❌ **absent** (constants exist, no handler) | ❌ **absent** | ✅ |
| async / partial | `kXR_oksofar`, `kXR_attn`, `kXR_waitresp` | chunked / zero-copy reads | `kXR_oksofar` only | output-ring pipelining + windowed TLS reads |
| redirect | ✅ | `RedirectResponse` (door) | follows, **but not after open** (TODO) | ✅ (manager mode) |

> **Paged I/O (`pgread`/`pgwrite` with `kXR_status` and per-page CRC32c) exists in
> only two of the reimplementations: XRootD C++ and nginx-xrootd.** dCache and
> go-hep stop at legacy `kXR_oksofar` chunking. EOS implements it as genuine OFS
> overrides (`fst/XrdFstOfsFile.cc:978,1280`). The `kXR_status` frame carries its
> own CRC32c over the response header — a transport integrity check *distinct*
> from the per-page data CRCs — so a conformant pgread/pgwrite implementation
> reproduces a dual-CRC design.

nginx-xrootd's pgread uses a **gapped in-place layout**: `preadv` reads page data
into positions that leave a 4-byte gap before each ≤4096-byte page, then a
single pass writes each CRC into its preceding gap — no copy
(`src/read/pgread.c:88-150`; this was a 27.6%→10% module-CPU optimization).

---

## 7. Per-implementation additional observations

### 7.1 XRootD C++ (reference)
* **Continuation over blocking.** The `Resume` member-function-pointer pattern
  (`XrdXrootdProtocol.hh:589`) is how a single-threaded-ish handler survives short
  reads — an elegant alternative to both threads-per-link and an explicit state
  machine.
* **`Process2` is deliberately several small switches** "to help the compiler"
  (`XrdXrootdProtocol.cc:439-609`), with a strict pre-login gate (only
  protocol/login/bind permitted before `Status` is set).
* **Alphanumeric IV is a fossil.** The session IV is drawn from
  `XrdSutRndm::GetBuffer(…, 3)` where option `3` restricts each byte to
  `[A-Za-z0-9./]` (`XrdCryptosslCipher.cc:1136`, `XrdSutRndm.cc:48`). This sharply
  reduces IV entropy (~64 values/byte) and is preserved purely for historical
  compatibility — both XRootD *and* dCache carry it.
* **`kXR_status` carries its own crc32c** over the body
  (`XrdXrootdResponse.cc:492`), separate from pgread/pgwrite page CRCs.
* **Built-in poller only** in this tree (`XrdClPollerLibEvent.cc` is absent),
  contradicting older docs that mention a libevent backend.
* **Proxy delegation is lost on unsigned-DH** (`XrdSecProtocolgsi.cc:3315`); pure
  cert/key (no proxy) auth requires `XrdSecgsiVersCertKey=10600`.

### 7.2 EOS
* **The capability-signed redirect is the heart of EOS `root://`.**
  `XrdMgmOfsFile::open()` assembles `mgm.fid/cid/sec/lid/...`, signs it with a
  shared symmetric key (`SymKey::CreateCapability`, `mgm/ofs/XrdMgmOfsFile.cc:3220`),
  appends it to the redirect host, and returns `SFS_REDIRECT`. The FST verifies
  the signature (`SymKey::ExtractCapability`) — a bearer-token-in-redirect model
  built entirely on stock redirect semantics.
* **Two-tier auth**: stock XrdSec for transport, then `XrdSecEntity→VirtualIdentity`
  in-process (`common/Mapping.cc:187`), with an *optional* protobuf/ZMQ remote
  front-end (`libEosAuthOfs.so`) that serializes the entity field-for-field.
* **Own checksum engine** (`fst/checksum/`: Adler, CRC32/32C/64, MD5, SHA*,
  XXHASH64, BLAKE3, HWH64) hooked into the framework `chksum` virtual.
* **Namespace in QuarkDB** (`libEosNsQuarkdb.so`), served from the MGM without an
  FST round-trip for stat/dirlist.
* **Lesson for reimplementers:** to be EOS-compatible you don't need to match EOS
  at all — you need to match *stock XRootD*, because that is all EOS speaks on the
  wire. (Confirmed: zero `XrdSecProtocol`/`XrdXrootdProtocol` definitions in the
  EOS tree.)

### 7.3 dCache / xrootd4j
* **Cryptographically dated GSI.** `SUPPORTED_DIGESTS = "sha1:md5"`
  (`GSIRequestHandler.java:88`) — no SHA-256; and a **hard-coded 512-bit DH prime**
  server-side (`DHSession.java:69`). Both are weak by modern standards and are the
  reason a client must negotiate *down* to interoperate.
* **`kXRS_main` is parsed by trial.** `deserialize()` *attempts* a nested-bucket
  parse and catches the exception to decide "encrypted vs. plaintext"
  (`GSIBucketUtils.java:213`) — there is no explicit encrypted flag; the
  discriminator is a step-range sanity check.
* **NPE-prone bucket access.** `validateDigests()`/`validateCiphers()` dereference
  `map.get(kXRS_md_alg)` without a null check — a peer that omits the bucket
  triggers a Java NPE rather than a clean protocol error. (This is the exact
  failure a conformant client must avoid provoking.)
* **Asymmetric encrypt/decrypt re-pad** (`DHSession.java:365`, ENCRYPT only) can
  desync if the peer's secret length differs on the decrypt side.
* **Strengths:** the Netty pipeline is clean and idiomatic; write-segmentation and
  chunked/zero-copy reads are well done; the TPC client (`org/dcache/xrootd/tpc/`)
  is a real, separate GSI-capable client.

### 7.4 go-hep
* **Cleanest code, narrowest scope.** The `Marshaler`/`Unmarshaler` interface pair
  + `gen-marshal.go` generator make it the most readable protocol reference in the
  set — *where it exists*. But it is pinned to **v3.1 (2012)** and omits TLS, GSI,
  token, SSS, readv, pgread/pgwrite, and `kXR_status`.
* **Robustness gaps:** `panic` on initial-session read error and on unroutable
  StreamID (`session.go:177,263`); a blocking mux (`mux.go:214`) where one slow
  caller stalls the whole connection; `kXR_wait` honored by an unbounded sleep +
  resend; **redirect-after-open is unhandled** (`client.go:153` TODO).
* **Server is narrower than the client** — it rejects chmod/statx/query/locate/
  prepare/bind/endsess/verifyw with `InvalidRequest`.
* **The krb5 path is genuinely complete** (real AP_REQ via `gokrb5`), which is
  unusual and worth noting — most reimplementations skip krb5.
* **Net assessment:** an excellent, idiomatic library for plaintext metadata +
  basic byte-range I/O against a cooperating server; not viable for production
  WLCG `root://`.

### 7.5 nginx-xrootd (this project)
* **The shared `gsi_core` seam is the headline architectural choice.** One
  OpenSSL+libc file (bucket codec, DH, cipher negotiation, RSA POP, sigver HMAC +
  policy) compiles byte-identically into both the server module and the client
  library (`shared/xrdproto/`, `-DXRDPROTO_NO_NGX`, enforced by an
  ngx-free-symbol check). Client and server are therefore *provably* wire-inverse,
  eliminating the "two implementations drift" bug class that dCache's
  encrypt/decrypt asymmetry exemplifies.
* **Event-loop discipline** (see §1) — the only implementation that must cache or
  pool every blocking crypto primitive.
* **Table/cascade dispatch + a no-`goto`, functional coding standard**; cleanup via
  bundle-struct destructors rather than goto ladders.
* **Fail-closed throughout** — payload size gated before allocation; auth gates as
  dispatch macros (`require_auth` for reads, `require_write` = auth ∧ `allow_write`
  for writes); sigver enforcement rejects unsigned mutating ops.
* **CApath CA loading** — `trusted_ca` is `stat`'d and, when a directory, loaded as
  an OpenSSL CApath (`src/gsi/config.c`) so on-demand hash lookup verifies
  arbitrary grid proxy chains a single bundle cannot.
* **Verified interoperability** against three independent stacks — its own server,
  real EOS (stock XRootD C++, `v:10600`), and real dCache (Java, `v:10400`,
  sha1/md5) — exercising the full read-only surface (ls/stat/statvfs/locate/cksum/
  cat/head/readv/du/tree/find/download) with end-to-end checksum verification.
* **Distinctive positive vs. the field:** it is the only reimplementation (besides
  the C++ reference) that implements **both** the modern paged-I/O integrity path
  (pgread/pgwrite + `kXR_status` + per-page CRC32c) **and** the full GSI/token/SSS
  + TLS auth surface.

### 7.6 gfal2 (the WLCG data-management layer)

* **It is a client consumer, not a protocol implementation.** gfal2 exposes one
  POSIX-ish data-management API (`gfal2_open/copy/stat/checksum/...`) over pluggable
  backends and dispatches by URL scheme:
  `libgfal_plugin_xrootd.so` → the reference **`libXrdCl`** for `root://`/`roots://`,
  `libgfal_plugin_http.so` → **`davix`** for `http(s)://`/`davs://`, plus
  gridftp/srm/sftp/s3/dcap. On the `root://` wire it is therefore byte-identical to
  XRootD C++ (§2–§6 all apply unchanged); the interesting surface is the *layer
  above* and the *second protocol* (`davs://`).
* **What it adds above the transport:** scheme-agnostic transfers, **third-party
  copy** orchestration (the FTS engine), automatic protocol fallback, retry/timeout
  policy, and checksum integration (`gfal-sum`; for HTTP it issues RFC 3230
  **Want-Digest** and reads the `Digest:` response). This is exactly why it is the
  client FTS and Rucio run in production — and why "interoperates with gfal2" is a
  stronger statement than "interoperates with `xrdcp`."
* **`root://` result (this module):** the full lifecycle works — `gfal-mkdir`,
  upload, `gfal-ls`, `gfal-stat` (correct size), byte-identical download,
  `gfal-sum` adler32 **and** crc32c (crc32c matches our own `xrdcrc32c`), rename,
  cat, rm. Because this path is `libXrdCl`, it also transitively validates our
  server against the reference client at a higher API layer than `xrdcp`.
* **`davs://` result + the bug it exposed (now fixed).** Data transfers worked, but
  `gfal-stat` reported a garbage, run-to-run-varying size (~TB). Root cause was
  **ours, not gfal's**: our WebDAV `PROPFIND` emitted the RFC 4331 quota properties
  (`<D:quota-used-bytes>` = the *filesystem* used bytes) on **file** resources, and
  `davix` maps `quota-used-bytes` onto `st_size` — so a file's size became the
  partition's used bytes. `curl` proved the server returned the correct
  `getcontentlength` (HEAD *and* PROPFIND), isolating the cause to the extra quota
  property. RFC 4331 defines quota as a **collection** property, and stock XrdHttp
  never emits it per-file (`XrdHttpReq.cc` emits only
  getcontentlength/getlastmodified/resourcetype/iscollection/executable). **Fix:**
  gate the quota block to directories (`S_ISDIR`) in `src/webdav/propfind.c` — files
  now carry only `getcontentlength`, and `gfal-stat` returns the true size;
  collections still report quota. (Full write-up: `gfal-interop-findings.md`.)
* **Lesson — the abstraction layer is its own interop surface.** Unlike a
  raw-protocol reimplementation, gfal2's risk is not in the bytes (it reuses
  `libXrdCl`/`davix`) but in *which properties and headers each backend extracts*.
  davix is stricter/different from `curl` about PROPFIND property→`stat` mapping, so
  a server can be perfectly RFC/`curl`-correct on the value yet still mislead davix
  by emitting a *semantically misplaced* property. Validating against gfal2 (not
  just `xrdcp`/`curl`) is what surfaced this.
* **Environmental note:** gfal's davix/neon TLS backend was intermittently flaky in
  the test environment (`SSL handshake failed: packet length too long`), independent
  of the size bug; run gfal with the system `libXrdCl` (`unset LD_LIBRARY_PATH`) and
  the grid CApath (`X509_CERT_DIR`) for `davs://` TLS verification.

---

## 8. Conclusions

* **The wire framing and handshake bytes are a solved, stable layer** — every
  reimplementation reproduces them identically. The only handshake-level
  divergences are the **version reported** (go-hep frozen at 3.1) and **TLS**
  (go-hep has none).
* **GSI is the hard part and the source of every real interop break.** The
  failure surface is concentrated in version-gating, digest negotiation (dCache's
  sha1/md5 + mandatory `md_alg` bucket), the `useIV` / `#ivlen` split, DH padding,
  and the bucket terminator. A conformant client must negotiate *down* to the
  peer's dialect on every one of these.
* **Feature completeness for production WLCG `root://`:**
  **XRootD C++ ≈ EOS ≈ nginx-xrootd** (full GSI/token/SSS + TLS + readv + pgread)
  > **dCache xrootd4j** (full auth + TLS, but no paged-I/O / readv-CRC path)
  > **go-hep** (plaintext krb5/unix metadata + basic I/O only).
* **Architecturally**, the five span the full reuse↔reimplement spectrum: EOS
  (maximal reuse via plugins) at one pole, the three clean-room reimplementations
  (dCache/go-hep/nginx-xrootd) at the other, and the C++ reference defining the
  contract. nginx-xrootd is unique in being event-loop-based and in sharing a
  single crypto core between its server and client. **gfal2** sits off this axis
  entirely as the production *consumer* — reusing `libXrdCl`/`davix` rather than
  speaking the wire — and is the client analogue of EOS's plugin reuse.
* **The interop surface is not only the wire.** go-hep (a strict reimplementation)
  exposed three *protocol* bugs; gfal2 (a pure consumer that touches no protocol
  bytes) still exposed a *semantics* bug — a property emitted on the wrong resource
  type that `curl` tolerated but `davix` mis-mapped into `stat`. Validating against
  the clients production actually runs (gfal2/FTS/Rucio), not just `xrdcp`/`curl`,
  is what catches these. See [`gfal-interop-findings.md`](gfal-interop-findings.md)
  and [`gohep-interop-findings.md`](gohep-interop-findings.md).

---

### Appendix A — key source anchors

| Concern | XRootD C++ | dCache xrootd4j | go-hep | nginx-xrootd |
|---|---|---|---|---|
| Wire structs | `XProtocol/XProtocol.hh` | `XrootdProtocol.java` | `xrdproto/xrdproto.go` | `src/protocol/` |
| Server dispatch | `XrdXrootd/XrdXrootdProtocol.cc:439` | `XrootdRequestHandler.java:229` | `server.go:242` | `src/handshake/dispatch.c` |
| Client transport | `XrdCl/XrdClXRootDTransport.cc` | `org/dcache/xrootd/tpc/` | `client.go`, `session.go` | `client/lib/conn.c`, `frame.c` |
| Handshake | `XrdXrootdProtocol.cc:311` | `XrootdHandshakeHandler.java:60` | `xrdproto/handshake/handshake.go` | `src/handshake/client_hello.c` |
| GSI | `XrdSecgsi/XrdSecProtocolgsi.cc`, `XrdCrypto/XrdCryptosslCipher.cc` | `xrootd4j-gsi/.../{DHSession,GSIRequestHandler}.java` | — (absent) | `src/gsi/`, `client/lib/sec/sec_gsi.c`, shared `src/gsi/gsi_core.c` |
| Data plane | `XrdXrootdXeq.cc`, `XrdXrootdXeqPgrw.cc` | `DataServerHandler.java` | `xrootd/file.go`, `xrdproto/read` | `src/read/`, `src/write/`, `src/response/status.c` |
| EOS integration | — | — | — | (EOS) `mgm/ofs/XrdMgmOfsFile.cc`, `fst/XrdFstOfsFile.cc`, `common/Mapping.cc` |

### Appendix B — verification provenance

GSI interoperability claims (§5.4) were established by running the nginx-xrootd
native client against live endpoints with an LHCb VOMS proxy
(`/tmp/x509up_u<uid>`):

* **EOS** `root://eoslhcb.cern.ch` — `v:10600`, signed-DH, requires the IV.
* **dCache** `root://lhcbdcache-kit.gridka.de:1094` — dCache 11.2.4, `v:10400`,
  `sha1:md5`, mandatory `md_alg` bucket and `kXRS_none` terminator.

Both authenticate and serve reads correctly with the version-gated IV + `#ivlen`
suffix + terminator + digest-negotiation behavior described in §5.2.
