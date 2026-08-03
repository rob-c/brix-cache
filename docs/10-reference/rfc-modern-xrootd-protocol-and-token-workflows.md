# RFC — The XRootD Wire Protocol: A Definition, its Design Rationale, and an Independent Re-Implementation with XrdHttp and Token-Aware Workflows

| | |
|---|---|
| **Status** | Informational / Working Draft (for review by WLCG, the XRootD collaboration, and HEP data-federation operators) |
| **Defines** | The XRootD binary wire protocol as spoken by current (v5-era) clients and servers, byte-level, with the design choices behind it |
| **Reference tree** | Official XRootD source pinned at `/tmp/brix-src/src` (release-series 6.x; its `XProtocol/XProtocol.hh` defines `kXR_PROTOCOLVERSION 0x00000511`, version string `"5.1.0"`) |
| **Subject implementation** | The nginx stream+http module in this repository (`src/`, `client/`) — "the module" — which advertises protocol `0x00000520` (5.2.0, a superset adding `kXR_clone`) |
| **Date** | 2026-08-03 |
| **Audience** | Protocol implementers, spec editors, site security officers, and federation architects |

> **Why this document exists.** The XRootD protocol has an unusual specification situation: the normative artifact is a C++ header (`XProtocol.hh`), explicitly licensed for independent reimplementation, plus prose documents that lag it. A large amount of the *actual* wire contract — the part a from-scratch implementation must honor to interoperate with `xrdcp`, `XrdCl`, and stock servers — is defined only by the behavior of the reference implementation and its clients. This RFC does three things: (1) **defines the on-the-wire protocol** at byte level, (2) records the **design choices** the official implementation embodies and why they are good (or contested), and (3) states, for every behavior, its **provenance** — whether it came from the header, from reading the reference C++, from reverse-engineering live clients, or is a local choice where the protocol is silent. The subject implementation is a clean-room C re-implementation inside nginx — *not* a translation of the C++ — so every provenance tag below reflects how that contract was actually recovered.

---

## Table of contents

1. [Introduction, conventions, and provenance taxonomy](#1-introduction-conventions-and-provenance-taxonomy)
2. [The protocol's design model](#2-the-protocols-design-model)
3. [Wire specification — session layer](#3-wire-specification--session-layer)
4. [Wire specification — the operation set](#4-wire-specification--the-operation-set)
5. [Wire specification — integrity, paged I/O, and request signing](#5-wire-specification--integrity-paged-io-and-request-signing)
6. [Security protocols on the wire and token-aware workflows](#6-security-protocols-on-the-wire-and-token-aware-workflows)
7. [The HTTP plane — XrdHttp equivalence](#7-the-http-plane--xrdhttp-equivalence)
8. [Third-party copy](#8-third-party-copy)
9. [Provenance ledger — cloned, source-recovered, reverse-engineered, local](#9-provenance-ledger)
10. [Conformance posture versus the reference](#10-conformance-posture-versus-the-reference)
11. [Areas of ambiguity — where experts need to weigh in](#11-areas-of-ambiguity--where-experts-need-to-weigh-in)
12. [Implementation invariants](#12-implementation-invariants)
13. [Questions for reviewers](#13-questions-for-reviewers)
14. [References](#14-references)

---

## 1. Introduction, conventions, and provenance taxonomy

### 1.1 The specification situation

`XProtocol.hh` opens with a modified BSD license stating that "The XRoot protocol definition, documented in this file … may be freely used to reimplement it," with the governance clause that derived software may not use the names *XRootD* or *cmsd* "if the protocol documented in this file is changed in any way." The header is therefore both the normative spec and the compatibility contract. Everything in §3–§5 is defined against it, against the reference implementation's behavior (`XrdXrootd/XrdXrootdXeq.cc` et al.), and against live-client observation.

### 1.2 Requirement language

MUST / MUST NOT / SHOULD / MAY are used per RFC 2119. Because there is no IETF-blessed XRootD spec, these express what an implementation must do **to interoperate with the current client fleet** (`XrdCl`-based `xrdcp`/`xrdfs`, the FUSE clients, gfal2), which is the only interoperability test that matters in production.

### 1.3 Provenance taxonomy

Every non-obvious statement in this document carries one of five tags. This is the answer to "what was cloned versus reverse-engineered":

| Tag | Meaning |
|---|---|
| **[SPEC]** | Stated in `XProtocol.hh` (or official prose docs). Constants and struct layouts were *cloned* — deliberately, byte-for-byte, as the license invites. |
| **[SRC]** | Not stated in the header; recovered by **reading the reference C++** (`XrdXrootdXeq.cc`, `XrdXrootdResponse.cc`, `XrdXrootdProtocol.cc`) as an oracle for semantics the header doesn't carry. |
| **[WIRE]** | Recovered by **reverse-engineering live behavior** — running real clients against the module (and the module's client against stock servers) and packet-reading until it worked. These are behaviors in *neither* the header *nor* obvious in the source; the repo's ledger of them is `docs/10-reference/protocol-notes.md` (30 numbered findings). |
| **[LOCAL]** | The protocol is silent; the module made a deliberate local design choice, documented and defensible, that an expert may wish to ratify or contest. |
| **[EXT]** | A vendor extension, deliberately out-of-band of the standard registry and capability-negotiated so stock peers never see it. |

### 1.4 Version numbers, precisely

The protocol version is encoded as three base-10 digits `x.y.z` in a 32-bit word (per the header's own comment). The pinned reference header defines:

```
kXR_PROTOCOLVERSION  0x00000511     kXR_PROTOCOLVSTRING "5.1.0"
kXR_PROTSIGNVERSION  0x00000310     (signing available)
kXR_PROTTLSVERSION   0x00000500     (TLS available)
kXR_PROTPGRWVERSION  0x00000511     (pgread/pgwrite available)
kXR_PROTXATTVERSION  0x00000500     (fattr available)
```

Note the internal inconsistency: `0x511` decodes to 5.1.**1** under the stated encoding, while the string says "5.1.**0**" — a small but real example of header-as-spec fragility (§11.1). The module advertises **`0x00000520` (5.2.0)** — the vocabulary that adds `kXR_clone` (3032) — making its advertised level a strict superset of the pinned header's registry. **[SPEC]** for the constants; **[LOCAL]** for the choice to advertise 5.2.0.

---

## 2. The protocol's design model

Before the byte layouts, the design choices the official protocol embodies — because each one explains a family of wire details, and several are exactly where expert judgment is needed.

**D1 — One persistent TCP connection; requests are self-framed and pipelined.** Every request is a fixed **24-byte header** (+ optional payload of declared length); every response is a fixed **8-byte header** (+ body of declared length). There is no per-message length-prefix negotiation, no varint, no TLV: dispatch reads exactly 24 bytes and knows everything. This buys single-`read()` dispatch and trivial pipelining at the cost of per-opcode argument blocks being squeezed into 16 bytes (larger arguments overflow into the payload — the source of several framing ambiguities, §11.1). **[SPEC]**

**D2 — The `streamid` is client-owned and opaque.** The 2-byte `streamid` is a client-relative tag the server MUST echo verbatim (never byte-swap, never interpret). All multiplexing intelligence lives in the client; the server is stateless about ordering beyond "respond with the tag you were given." This is the enabling choice for client-side pipelining, `kXR_bind` parallel streams, and async (`kXR_waitresp`/`kXR_attn`) completion. **[SPEC]** (opacity is [SRC]: the header types it `kXR_char[2]`, and the reference never swaps it).

**D3 — All integers are big-endian.** "All binary data is sent in network byte order" is one of the few normative prose sentences in the header. **[SPEC]**

**D4 — POSIX-shaped errors.** The error registry (3000–3035) is designed around `errno`: the reference ships `mapError()` (errno → kXR code) and `toErrno()` (back) as protocol-level utilities *in the header itself*. The design choice: an XRootD server is presumed to sit on a POSIX-ish filesystem, and the protocol forwards that worldview to the client, which reconstitutes errno for POSIX shims (FUSE, `XrdPosix`). The header even documents its own compromise — `ENOTEMPTY` deliberately maps to `kXR_ItExists` "until the next major release." **[SPEC]**

**D5 — Federation is in-protocol: redirect, wait, and attn are first-class response types.** `kXR_redirect` (go elsewhere), `kXR_wait` (retry in N seconds — server-paced backpressure), `kXR_waitresp`/`kXR_attn(kXR_asynresp)` (deferred completion pushed later) make a *federation's* control flow part of the file protocol, instead of out-of-band as in HTTP ecosystems. This is XRootD's defining architectural feature — and the reason a re-implementation must treat "which ops consult the redirect map" as a semantic question (§10). **[SPEC]** for the frames, **[SRC]** for which ops may return them.

**D6 — In-band TLS upgrade (STARTTLS-style), version-gated.** TLS is negotiated *inside* `kXR_protocol` (client flags `kXR_ableTLS`/`kXR_wantTLS`; server response flags `kXR_haveTLS|kXR_gotoTLS` + granular `kXR_tls*` bits), then the same TCP connection upgrades. One port serves both cleartext and TLS. The granularity bits (`tlsLogin`, `tlsSess`, `tlsData`, `tlsTPC`, `tlsGPF`) express *per-category* TLS requirements — a sophistication the module deliberately collapses (§11.5). **[SPEC]**

**D7 — Integrity is end-to-end, not transport-level: paged I/O.** `kXR_pgread`/`kXR_pgwrite` interleave a CRC32c per 4 KiB page *through the whole path* — client memory to server disk — because at HEP transfer volumes TCP's 16-bit checksum demonstrably passes corruption. The accompanying response type `kXR_status` (4007) is a second-generation, self-checksummed response envelope. The recovery design ("accept-then-correct": take the good pages, report the bad ones for surgical retransmit) is a deliberate choice to never restart multi-GB transfers (§5.2). **[SPEC]** for framing; **[SRC]** for the recovery machine.

**D8 — Request signing as a middle trust tier.** `kXR_sigver` (3029) prefixes a request with a signed digest (SHA-256, monotonic `seqno`), letting a deployment protect *control* operations from tampering without paying TLS on the *data* path. Security levels (`kXR_secNone`…`kXR_secPedantic`) map each opcode to `signIgnore/signLikely/signNeeded`. **[SPEC]**

**D9 — Capability negotiation is layered and additive.** Client ability bits in `kXR_login` (`kXR_hasipv64`, `kXR_readrdok`, …), server capability bits in the `kXR_protocol` flags word (`kXR_suppgrw`, `kXR_supposc`, `kXR_supgpf`, `kXR_ecRedir`, …), and free-text `kXR_query Qconfig` key lookups. New features ride new bits; old peers ignore them. The module's vendor opcodes (§4.9) follow this same pattern via a `Qconfig` key. **[SPEC]**

**D10 — The header is the spec; prose lags.** A consequence worth stating as a design property: struct layouts and constants are normative and stable, but *semantics* (what a server should do with `kXR_rm` on a directory; whether `kXR_sigver` gets an ack; how `ckpXeq` frames its payload) live in the reference implementation. Every [SRC]/[WIRE] tag in this document is a direct measurement of that gap — and §11.1 argues the highest-value ones should be promoted to normative text.

---

## 3. Wire specification — session layer

### 3.1 Transport

TCP, default port 1094. All multi-byte integers big-endian [SPEC]. A connection passes through: **handshake → `kXR_protocol` → (optional TLS upgrade) → `kXR_login` → (optional `kXR_auth` rounds) → operations**, or is a *bound* secondary channel (`kXR_bind`, no login — §4.8).

### 3.2 Initial handshake

Client sends 20 bytes — five BE32 words [SPEC]:

```
offset 0   first   = 0
offset 4   second  = 0
offset 8   third   = 0
offset 12  fourth  = 4
offset 16  fifth   = 2012        (ROOTD_PQ magic)
```

The header defines a legacy 12-byte `ServerInitHandShake{msglen, protover, msgval}` reply. **A modern server MUST NOT send it.** **[WIRE]** (protocol-notes #1): v5 clients read *every* server frame — including the handshake reply — as a standard 8-byte `ServerResponseHeader` + body. The correct reply is:

```
ServerResponseHeader{ streamid={0,0}, status=kXR_ok, dlen=8 }
body: protover (BE32) ‖ msgval (BE32)        msgval = kXR_DataServer(1) | kXR_LBalServer(0)
```

Sending the legacy 12-byte form misparses as `status=0x0008, dlen=1312` and the client hangs awaiting 1312 phantom body bytes. Furthermore, v5 clients coalesce the 20-byte hello and the 24-byte `kXR_protocol` request into **one 44-byte TCP segment**; a server that blocks for them separately stalls. **[WIRE]** These two facts are nowhere in the header and are mandatory for interop.

### 3.3 Request framing

Every request is `ClientRequestHdr`, 24 bytes [SPEC]:

```
offset 0   streamid[2]    opaque client tag — echo verbatim, never swap
offset 2   requestid      BE16, 3000…3032 (see §4)
offset 4   body[16]       per-opcode argument block (overlaid per-op structs)
offset 20  dlen           BE32, length of payload that follows
```

`dlen` is untrusted input. The reference bounds it implicitly via buffer management; the module bounds it **explicitly, per-opcode, before any allocation**: writes ≤ 16 MiB, `kXR_readv` ≤ 16 KiB, `kXR_auth` ≤ 32 KiB, `kXR_prepare` ≤ 64 KiB, everything else ≤ path-sized (~4 KiB). **[LOCAL]** — and the "writes need a separate limit from paths" lesson is [WIRE] #12: with one path-sized cap, `xrdcp` connects, opens, then dies silently on the first 8 MiB write.

**Payload NUL convention [WIRE] #19:** real clients may include exactly one trailing `\0` *inside* `dlen` on path-carrying requests. The interoperable rule: accept one trailing NUL at `payload[dlen-1]`, reject any earlier embedded NUL (defeats `"a\0evil"` splicing), then convert.

### 3.4 Response framing

`ServerResponseHeader`, 8 bytes [SPEC]: `streamid[2]` (echo) ‖ `status` BE16 ‖ `dlen` BE32 (body length). Status registry [SPEC]:

| status | name | body |
|---|---|---|
| 0 | `kXR_ok` | final result (may be empty) |
| 4000 | `kXR_oksofar` | partial result; more frames follow with the same streamid; final frame is `kXR_ok`. Large responses MUST be chunked this way [WIRE] #26 |
| 4001 | `kXR_attn` | server push — see below |
| 4002 | `kXR_authmore` | auth needs another round; body = next challenge |
| 4003 | `kXR_error` | `errnum` BE32 ‖ `errmsg` — the message SHOULD carry its trailing NUL; several clients treat it as a C string [SRC] |
| 4004 | `kXR_redirect` | `port` BE32 ‖ `host[?opaque-cgi]` — client reissues at the new endpoint |
| 4005 | `kXR_wait` | `seconds` BE32 ‖ optional infomsg — retry after N s (server-paced backpressure) |
| 4006 | `kXR_waitresp` | `seconds` BE32 — the *real* answer will arrive later as `kXR_attn(kXR_asynresp)` |
| 4007 | `kXR_status` | second-generation self-checksummed envelope; REQUIRED for pgread/pgwrite (§5.1) |

**`kXR_attn` framing [SPEC]:** body starts with `actnum` BE32. Only two action codes survive in v5 (the rest of 5000–5007 are marked "no longer supported" in the header): `kXR_asyncms` (5002) — unsolicited text notification, outer `streamid={0,0}`, body = `actnum ‖ reserved[4] ‖ inner ServerResponseHeader ‖ text`; and `kXR_asynresp` (5008) — the deferred completion of a `kXR_waitresp`'d request, same envelope, the *inner* header carrying the original streamid and real status. The module implements both, and its proxy relays upstream `kXR_attn` transparently.

### 3.5 `kXR_protocol` (3006) — capability and TLS negotiation

Request body [SPEC]: `clientpv` BE32 ‖ `flags` (bit 0x01 `kXR_secreqs` "tell me signing requirements", 0x02 `kXR_ableTLS`, 0x04 `kXR_wantTLS`, 0x08 `kXR_bifreqs`) ‖ `expect` (what comes next: `ExpBind/ExpGPF/ExpLogin/ExpTPC/ExpGPFA`) ‖ reserved.

Response body [SPEC]: `pval` BE32 (server protocol version) ‖ `flags` BE32, where flags packs three registries:

- **Role**: `kXR_isServer 0x1`, `kXR_isManager 0x2`, plus `attrProxy/attrMeta/attrCache/attrSuper/attrVirtRdr`.
- **Feature support**: `kXR_suppgrw 0x00200000` (paged I/O), `kXR_supposc 0x00100000` (POSC), `kXR_supgpf/anongpf` (GPF — never set by the module, nor by default upstream), `kXR_ecRedir 0x4000` (erasure-coded redirect — defined, set by neither).
- **TLS**: `kXR_haveTLS 0x80000000`, `kXR_gotoTLS 0x40000000`, and the granular requirement bits `tlsLogin 0x04000000`, `tlsSess 0x08000000`, `tlsData 0x01000000`, `tlsTPC 0x10000000`, `tlsGPF/tlsGPFA`. If the client set `kXR_wantTLS` and the listener has no TLS context, the server MUST fail with `kXR_TLSRequired` (3028). On agreement the connection upgrades in-band after the response drains.

If `kXR_secreqs` was set, a signing-requirements trailer follows, tagged `'S'` [SPEC]: `theTag='S' ‖ rsvd ‖ secver ‖ secopt ‖ seclvl ‖ secvsz` then `secvsz` 2-byte pairs `(reqindx, reqsreq)` with `reqsreq ∈ {signIgnore, signLikely, signNeeded}`; `secopt` bit `kXR_secOData 0x01` extends signing to data ops. A `'B'` (bind-preference) trailer exists for `kXR_bifreqs`.

> **Reconciliation note (§11.1):** the repo's reverse-engineered ledger (protocol-notes #2) records a *different* working shape for the security trailer — a 4-byte header (`0, required, count, 0`) followed by 8-byte entries of 4-char protocol name + 4 zero bytes — describing what real clients accepted during bring-up. The header's `'S'`-tagged struct and that observed layout do not obviously coincide. This deserves an authoritative statement in the spec: the observable symptom of getting it wrong is a **silent disconnect** after the protocol exchange, with no error on either side.

### 3.6 `kXR_login` (3007) and session establishment

Request body [SPEC]: `pid` BE32 ‖ `username[8]` ‖ `ability2` (`kXR_ecredir`) ‖ `ability` (`kXR_fullurl`, `kXR_readrdok`, `kXR_hasipv64`, `kXR_onlyprv4/6`, `kXR_lclfile`, `kXR_redirflags`) ‖ `capver[1]` (low 6 bits = client generation, `kXR_ver005` = 2019 TLS-era; bit 0x80 = async-capable) ‖ reserved. The 8-byte username is *not* NUL-terminated at fixed length; the module rejects embedded NUL / non-printables to prevent `"a\0evil"` impersonation **[LOCAL]** (stock is laxer), and rejects a duplicate login with `kXR_InvalidRequest` **[SRC]**.

Response [SPEC]: 16-byte `sessid` ‖ a **plain-text** security token. **[WIRE]** #3/#23: the token MUST be the `&P=` text dialect, not a binary `XrdSutBuffer` — e.g. `&P=ztn,v:10000` (token), `&P=gsi,v:10000,c:ssl,ca:<hash>` (GSI), or both concatenated with the preferred protocol first. Sending a binary buffer makes the client print "No protocols left to try" and disconnect. Anonymous mode completes login in one round-trip with an empty sec token.

`kXR_endsess` (3023) kills a named session (16-byte sessid in the body block); `kXR_ping` (3011) is a login-gated liveness no-op.

**Post-login gate ordering [LOCAL, security-relevant]:** the module's dispatch chain is *pending-sigver verify → signing enforcement → session ops → minimum-security floor → proxy gate (keyed on `auth_done`, never `logged_in`) → rate-limit → reads (impersonation-bracketed) → writes*. Keying the proxy gate on `auth_done` closes the "login then skip `kXR_auth`" hole. Auth attempts are capped at 10.

---

## 4. Wire specification — the operation set

### 4.1 The opcode registry

Requestids 3000–3032 [SPEC]. All are implemented by the module except `kXR_gpfile` — for which the reference's own default handler also returns `kXR_Unsupported`, and neither side advertises `kXR_supgpf`, so the practical surface is at parity [SRC].

| id | op | arg block (16-byte body) highlights | payload |
|---|---|---|---|
| 3000 | `kXR_auth` | reserved[12] ‖ `credtype[4]` | credentials (§6) |
| 3001 | `kXR_query` | `infotype` BE16 ‖ rsvd[2] ‖ `fhandle[4]` ‖ rsvd[8] | subtype-specific text/args |
| 3002 | `kXR_chmod` | rsvd[14] ‖ `mode` BE16 | path |
| 3003 | `kXR_close` | `fhandle[4]` | — |
| 3004 | `kXR_dirlist` | rsvd[15] ‖ `options` (`kXR_online/dstat/dcksm`; dcksm implies dstat) | path |
| 3005 | `kXR_gpfile` | (header marks its own struct "all wrong; correct when implemented") | retired in practice |
| 3006 | `kXR_protocol` | §3.5 | — |
| 3007 | `kXR_login` | §3.6 | token/opaque |
| 3008 | `kXR_mkdir` | `options[1]` (`kXR_mkdirpath`) ‖ rsvd[13] ‖ `mode` BE16 | path |
| 3009 | `kXR_mv` | rsvd[14] ‖ `arg1len` BE16 | `src ‖ 0x20 ‖ dst` — **space separator** [WIRE] #13 |
| 3010 | `kXR_open` | `mode` BE16 ‖ `options` BE16 ‖ rsvd[12] | path[?cgi] |
| 3011 | `kXR_ping` | — | — |
| 3012 | `kXR_chkpoint` | `fhandle[4]` ‖ rsvd[11] ‖ `opcode` (`ckpBegin/Commit/Query/Rollback/Xeq`) | sub-request for Xeq (§11.1) |
| 3013 | `kXR_read` | `fhandle[4]` ‖ `offset` BE64 ‖ `rlen` BE32 | optional `read_args` (pathid) |
| 3014 | `kXR_rm` | — | path — **file semantics only; MUST NOT recurse** [SRC] (§10) |
| 3015 | `kXR_rmdir` | — | path (empty dir) |
| 3016 | `kXR_sync` | `fhandle[4]` | — |
| 3017 | `kXR_stat` | `options` (`kXR_vfs`) ‖ rsvd[11] ‖ `fhandle[4]` | path (or by handle) |
| 3018 | `kXR_set` | rsvd[15] ‖ `modifier` (should be 0) | text hint — advisory, always `kXR_ok` [SRC]/[WIRE] #24 |
| 3019 | `kXR_write` | `fhandle[4]` ‖ `offset` BE64 ‖ `pathid` ‖ rsvd[3] | data |
| 3020 | `kXR_fattr` | `fhandle[4]` ‖ `subcode` ‖ `numattr` ‖ `options` ‖ rsvd[9] | name/value vectors |
| 3021 | `kXR_prepare` | `options` ‖ `prty` ‖ `port` BE16 ‖ `optionX` BE16 (`kXR_evict`) | newline-separated paths |
| 3022 | `kXR_statx` | — | newline-separated paths; reply = 1 flag byte per path [SRC] |
| 3023 | `kXR_endsess` | `sessid[16]` | — |
| 3024 | `kXR_bind` | `sessid[16]` | — → reply 1-byte `substreamid` |
| 3025 | `kXR_readv` | rsvd[15] ‖ `pathid` | `read_list` vector (§4.4) |
| 3026 | `kXR_pgwrite` | `fhandle[4]` ‖ `offset` BE64 ‖ `pathid` ‖ `reqflags` ‖ rsvd[2] | CRC-first page stream (§5.2) |
| 3027 | `kXR_locate` | `options` BE16 (shares open's locate-tagged bits) | path |
| 3028 | `kXR_truncate` | `fhandle[4]` ‖ `offset` BE64 | (or path) |
| 3029 | `kXR_sigver` | `expectrid` BE16 ‖ `version` ‖ `flags` ‖ `seqno` BE64 ‖ `crypto` | signature (§5.3) |
| 3030 | `kXR_pgread` | `fhandle[4]` ‖ `offset` BE64 ‖ `rlen` BE32 | optional pathid/reqflags (dlen 0/1/2) |
| 3031 | `kXR_writev` | `options` (`doSync 0x01`) ‖ rsvd[15] | `write_list` vector (§11.1) |
| 3032 | `kXR_clone` | server-side range copy | (5.2.0 vocabulary — absent from the pinned header; implemented by the module) |

An unrecognized requestid MUST get `kXR_error(kXR_InvalidRequest)` — **not** `kXR_Unsupported`, which is reserved for a *recognized* operation the backend cannot perform. **[SRC]** — the header does not say this; the reference's dispatch does, and clients distinguish the two.

### 4.2 `kXR_open` (3010)

`mode` is a POSIX-oid permission bitset (`kXR_ur 0x100 … kXR_ox 0x001`) [SPEC]. `options` [SPEC] with semantics that are only fully defined by client behavior:

- `kXR_open_read 0x10` / `kXR_open_updt 0x20` / `kXR_open_apnd 0x200` — access mode.
- `kXR_new 0x08` alone → `O_CREAT|O_EXCL`; **`kXR_new|kXR_delete` together → create-or-truncate** (no `O_EXCL`) — this combination is what `xrdcp` actually sends for overwrite and its meaning appears nowhere in the spec. **[WIRE]** #14. Violating it either silently truncates (missing `O_EXCL`) or breaks every overwrite copy. `kXR_new` on an existing file MUST fail `kXR_ItExists` (3018), not `kXR_FileLocked` [SRC] (§10).
- `kXR_mkpath 0x100` — create intermediate directories (interacts with path resolution: the parents don't exist yet, so `realpath`-based confinement must switch to lexical `..`-scanning [WIRE] #15).
- `kXR_posc 0x1000` — persist-on-successful-close: writes go to a hidden staging file, renamed into place only on clean `kXR_close`; anything else MUST NOT leave a partial at the final path [SRC]+[WIRE] #29 (+[LOCAL]: the disconnect case is a genuine semantic fork — §11.4).
- `kXR_retstat 0x400` — append stat info to the open reply; `kXR_compress 0x1` — return compression page size.
- `kXR_refresh`, `kXR_force`, `kXR_replica`, `kXR_nowait`, `kXR_seqio`, `kXR_open_wrto` — hints/consistency flags; several bits are locate-overloaded (`kXR_prefname`, `kXR_4dirlist`).

**Reply sizing is semantic [SRC]:** the body is the 4-byte `fhandle` **alone** unless `kXR_compress` or `kXR_retstat` was requested (then `cpsize`+`cptype`, then optional stat text). Always sending the 12-byte form is a real bug (the module had it; stock clients tolerate it, but the module's *own* origin-client over-specified 12 bytes and broke when the server was fixed — §10.2).

**Path CGI [WIRE] #9:** clients append `?oss.asize=…&xrdcl.requuid=…` (and TPC: `?tpc.key=…&tpc.src=…`); servers MUST strip CGI before filesystem use and MUST parse it for protocol meaning (TPC rendezvous, §8).

**Directory guard [WIRE] #16:** Linux happily `open(2)`s a directory; the protocol requires `kXR_isDirectory` on read-open of one — an explicit stat check is mandatory.

### 4.3 `kXR_stat` / `kXR_statx` / `kXR_dirlist` — the text-response family

The stat reply is a NUL-terminated ASCII line — and its field order is a classic trap [WIRE] #7:

```
"<id> <size> <flags> <mtime>\0"        (size BEFORE flags)
```

The same ordering serves `kXR_open(retstat)` and `dirlist(dstat)` entries. Implementing from struct-order intuition rather than the wire makes clients read `flags` as the file size. `flags` bits [SPEC]: `kXR_xset 1, isDir 2, other 4, offline 8, readable 16, writable 32, poscpend 64, bkpexist 128, cachersp 512`. `kXR_stat(kXR_vfs)` returns the 6-field `statvfs` line instead [SRC] (a 4-field guess makes stock clients print "Invalid response" — §10).

`kXR_dirlist` streams newline-separated names (chunked `kXR_oksofar`, final `\0` on the last frame, no interior NULs). With `kXR_dstat` (and `kXR_dcksm`, which implies it) the body MUST begin with the exact 10-byte sentinel

```
".\n0 0 0 0\n"
```

— `XrdCl`'s `DirectoryList::HasStatInfo` keys stat-pairing mode off that prefix; without it every stat line is parsed as a filename. **[WIRE]** #17. Entries then alternate `name\n` / `id size flags mtime[ [ algo:hex ] ]\n`. Filenames containing control bytes MUST be skipped — a newline-framed format cannot carry them [WIRE] #27. `kXR_statx` takes newline-separated paths and answers one flag byte per path, newline-separated; a missing path is an error, not `offline` [SRC] (§10).

### 4.4 Vector I/O — `kXR_readv` / `kXR_writev`

`read_list` element [SPEC]: `fhandle[4] ‖ rlen BE32 ‖ offset BE64` (16 bytes). Limits [SPEC]: vector ≤ 16384 bytes (1024 elements); response buffer floor `minRVbsz` = 2 MiB; each returned segment is prefixed by its own `readahead_list` echo. The module validates counts/offsets against overflow and coalesces contiguous same-handle runs into grouped `preadv()` preserving wire order **[LOCAL]**. `write_list` mirrors it (`wlen` instead of `rlen`); `kXR_writev` carries `doSync 0x01`. The `writev` payload layout ambiguity — is it `[vector][data]` with the split recovered by `n·16 + Σwlen == dlen`? — was a genuine wire ambiguity the module once resolved by heuristic, divergently from stock (§11.1).

### 4.5 `kXR_read` serving semantics

Reads larger than one server window MUST be chunked as `kXR_oksofar…kXR_ok` [WIRE] #26. The module's three serve paths (zero-copy `sendfile` on cleartext with 32 MiB response frames; windowed 2 MiB memory chunks under TLS; single-shot small reads) are **[LOCAL]** geometry — wire-visible only as frame boundaries, which clients MUST treat as arbitrary. Raising the sendfile chunk 16 → 32 MiB was validated as byte-identical; the frame geometry is explicitly *not* part of the contract.

### 4.6 `kXR_query` (3001)

Subtypes [SPEC]: `QStats 1, QPrep 2, Qcksum 3, Qxattr 4, Qspace 5, Qckscan 6, Qconfig 7, Qvisa 8, Qopaque 16, Qopaquf 32, Qopaqug 64` (the module also serves `QFinfo 9`/`QFSinfo 10`, which the pinned header does not define — flagged §11.1). All answers are text. Sharp edges:

- `Qcksum` answers `"<algo> <hex>"`; trailing CGI/NUL/CRLF junk in the request path MUST be trimmed before algorithm lookup — a folded NUL broke every non-default algorithm via `xrdcp --cksum` [SRC] (§10).
- `Qconfig` is key-by-key; **the `tpc` key MUST be answered as a bare `1\n` or `0\n`** — `XrdCl::CheckTPCLite` parses with `isdigit()`/`atoi()`, so a well-meaning `tpc=1` breaks TPC capability detection. **[WIRE]** #28. Unanswered keys are echoed back — with the consequence that `<key>=0` is indistinguishable from an answered zero (§11.1).
- `Qspace` answers the `oss.space=…&oss.free=…` text dialect; `Qconfig xrdfs.ext` is the module's vendor-extension advertisement channel [EXT].

### 4.7 `kXR_fattr` (3020)

Subcodes `Del/Get/List/Set` [SPEC]; limits [SPEC]: ≤ 16 vars/request, name ≤ 248, value ≤ 65536; options `isNew 0x01`, `aData 0x10`. Name/value vectors use the header's `NVec`/`VVec` micro-format (per-name 2-byte rc in replies). Attributes map to POSIX xattrs under a namespace prefix. The module adds `kXR_fattrRecurse 0x20` **[EXT]** — not in the upstream registry; interop with non-brix peers is undefined by construction (§11.7).

### 4.8 `kXR_bind` (3024) — parallel data streams

Sent on a **fresh TCP connection with no login**, carrying the primary session's 16-byte `sessid`; reply is a 1-byte `substreamid` (1–253). Bound channels are restricted to data movement (`read`/`readv`/`pgread` against handles opened by the primary) — they MUST NOT open/close/stat independently. **[SPEC]** for framing, **[SRC]/[WIRE]** #25 for the restriction set. Requests carrying `pathid` route their *response* to the named substream; `kXR_AnyPath 0xff` means "any".

### 4.9 Vendor extensions [EXT]

`kXR_setattr 3500` (utimens/chown), `kXR_symlink 3501`, `kXR_readlink 3502`, `kXR_link 3503` — POSIX-completeness ops the standard registry lacks (there is no wire op for `cp -p`, `touch -d`, `ln`). Deliberately placed far above `kXR_clone` (3032) to dodge future registry growth, and **capability-negotiated**: the server advertises via `Qconfig "xrdfs.ext"` and the native client emits them only when advertised — a stock server never receives one. This is the extension pattern §2-D9 implies, and §13-Q6 asks whether the registry wants an official vendor range.

---

## 5. Wire specification — integrity, paged I/O, and request signing

### 5.1 The `kXR_status` (4007) envelope

`ServerResponseBody_Status`, 16 bytes, always preceded by the 8-byte response header [SPEC]:

```
crc32c     BE32   — RFC 7143 CRC32c over the following bytes of the status body
streamID   [2]    — repeats the outer header's streamid
requestid  [1]    — original requestcode − 3000   (pgwrite → 26)
resptype   [1]    — 0 final, 1 partial, 2 progress
reserved   [4]
dlen       BE32   — length of the data (not info) section
```

then an op-specific `info` extension (pgread/pgwrite: the BE64 `offset`), then data. CRC32c = Castagnoli, poly `0x82F63B78`, init/final-XOR `0xFFFFFFFF`, test vector `crc32c("123456789") = 0xE3069283` [SPEC/WIRE]. **The fixed CRC covers only the streamID…info head, not the page data** — exactly what `XrdXrootdResponse.cc` computes; data pages carry their own CRCs. **[SRC]** — computing it over the data is a plausible misreading that breaks every v5 client.

**A successful `kXR_pgwrite` MUST be answered with this 32-byte envelope, not an 8-byte `kXR_ok`** — the client parses `ServerResponseV2` unconditionally and reads 24 bytes past a plain OK, then hangs or crashes. **[WIRE]** #10 — arguably the single most important undocumented fact in the v5 protocol. The full observed byte layout: outer header (status 4007, dlen 24), then `crc32c` over the following 20 bytes, `streamID`, `requestid=26`, `resptype=0`, `reserved[4]`, `dlen=0`, `offset` BE64.

### 5.2 Paged I/O

Geometry [SPEC]: page 4096 (`pgPageSZ`), unit 4100 (`pgUnitSZ`, page+CRC), ≤ 128 checksum errors per request (`pgMaxEpr`), ≤ 256 outstanding (`pgMaxEos`); `kXR_pgRetry 0x01` in `reqflags`.

**pgread** response: status envelope (info = BE64 file offset) followed by `[data ≤4096 ‖ crc32c]` per page — data-then-CRC. Page boundaries are **absolute-offset aligned**: an unaligned read's *first* page is the runt that re-aligns the stream to 4 KiB multiples of the file offset, not of the read start. The header does not say this; the reference's `AsyncPageReader` requires it, and getting it wrong desyncs the client's page accounting mid-stream. **[SRC]** (was a live module bug — §10). pgread is always plaintext-path (never compressed) [SRC].

**pgwrite** payload: `[crc32c ‖ data ≤4096]` per page — **CRC-first**, the mirror image of pgread [WIRE] #11. Verification implements the reference's **corrective-send-error machine** [SRC], and this is a designed *recovery protocol*, not just detection:

1. Verify every page; write good and bad alike (accept-then-correct).
2. Reply **success** (`kXR_status`) carrying a `pgWrCSE` extension: `cseCRC ‖ dlFirst BE16 ‖ dlLast BE16 ‖ bof[]` — the BE64 offsets of corrupt pages (first/last data lengths disambiguate runt pages).
3. The client retransmits exactly the listed pages with `kXR_pgRetry` set; a retry MUST correct exactly one page.
4. Corrupt offsets are held in a per-handle ledger; `kXR_close` MUST fail `kXR_ChkSumErr` while any remain — a committed file never retains known-bad bytes.

The design rationale (§2-D7): at multi-GB scale, "abort on first bad page" is operationally unusable; "accept silently" is corruption. Accept-then-correct with surgical retransmit is the deliberate third way, and it lives entirely in [SRC] behavior.

### 5.3 Request signing — `kXR_sigver` (3029)

The signing request *precedes* the request it protects: `expectrid` (the opcode of the next request) ‖ `version` (0) ‖ `flags` (`kXR_nodata 0x1` = payload not hashed) ‖ `seqno` BE64 monotonic ‖ `crypto` (`kXR_SHA256 0x01`, hash mask `0x0f`; `kXR_rsaKey 0x80`) ‖ payload = signature over `seqno ‖ request-header[‖ payload]` under the session key (GSI: derived from the DH secret) [SPEC].

Semantics only the reference defines [SRC]: **a valid sigver gets *no response*** — it is an envelope; acking it desyncs the client's stream accounting (a fixed module bug, §10). A failed verification answers `kXR_SigVerErr` *for the signed request*. Which opcodes need signing comes from the §3.5 `seclvl`/`secvec` negotiation; the module enforces the negotiated level on the dispatch path and rejects unsigned must-sign ops.

### 5.4 Error registry and the `mapError` design choice

The full registry runs `kXR_ArgInvalid 3001 … kXR_TimerExpired 3035` [SPEC]. The header's `mapError()` is worth reading as a design document: `ENOENT→NotFound`, `EPERM/EACCES→NotAuthorized`, `ENETUNREACH/EHOSTUNREACH/ECONNREFUSED→noserver`, `EISDIR→isDirectory`, `EEXIST→ItExists` (with `ENOTEMPTY` deliberately falling through to it "until the next major release"), `EDQUOT→overQuota`, `EILSEQ→SigVerErr`, `EPROTOTYPE→TLSRequired`, `ETXTBSY→inProgress`, default→`FSError`; `toErrno()` inverts it (`FileLocked→EDEADLK` notable). The module re-expresses both tables in one nginx-free C unit shared by server and FUSE client [SPEC], then extends where `mapError` is silent: `EBUSY→FileLocked` (stock defaults it to `FSError`), `EAGAIN` reserved for nearline-recall→`kXR_wait`, kernel path-escape `EXDEV`/`ELOOP→NotAuthorized` **[LOCAL]** — richer than stock, flagged for ratification.

### 5.5 Checksums at rest and on request

`Qcksum`/HTTP `Want-Digest` converge on one engine: `adler32, crc32, crc32c, md5, sha1, sha256, crc64, crc64nvme, zcrc32`, cached in `user.XrdCks.<alg>` xattrs keyed by mtime+size (the stock `XrdCks` convention [SRC]). `crc64` is CRC-64/XZ and `crc64nvme` is CRC-64/NVME — **different polynomials**; kernels produce raw values and each protocol edge encodes its own dialect (root/WebDAV: 16-hex; S3: base64 of 8 BE bytes) **[LOCAL]** invariant 9, because conflating them yields plausible-looking wrong digests.

---

## 6. Security protocols on the wire and token-aware workflows

### 6.1 `kXR_auth` framing

Body block: 12 reserved bytes ‖ 4-byte `credtype` (`"gsi\0"`, `"ztn\0"`, `"sss\0"`, `"krb5"`, `"unix"`, …); payload = protocol-specific credential; multi-round protocols continue via `kXR_authmore` challenges. The server routes on credtype through one front door; the offered set and order were advertised at §3.5/§3.6. The module implements every standard scheme's wire form (gsi, ztn, sss, krb5, unix, host, pwd) — only *third-party custom* sec plugins are out of scope, because there is no loadable sec-plugin ABI [LOCAL].

### 6.2 GSI — the X.509 handshake, reverse-engineered

The GSI exchange is two `kXR_auth` rounds (`kXGC_certreq` 1000 → server DH key + signed nonce; `kXGC_cert` 1001 → proxy chain encrypted under the DH session key). Nothing below is in any spec; all of it is **[WIRE]** (protocol-notes #4–#6, #8) and is why GSI is the hardest surface to re-implement:

- The `kXRS_puk` bucket carries a **DH** public key as text: `<DH PARAMETERS PEM>---BPUB---<hex BIGNUM>---EPUB--` — and the trailer is **9 characters** (`---EPUB--`), not 10. An RSA PEM in that slot (superficially similar) yields "could not instantiate session cipher."
- The group MUST be RFC 7919 `ffdhe2048`.
- Shared-secret derivation MUST be **unpadded** (`EVP_PKEY_CTX_set_dh_pad(0)`): v:10000 sets `HasPad=false`, and a padded secret produces a wrong session key that *neither side detects* until the proxy blob decrypts to garbage. Session key = first `keylen(cipher)` bytes of the secret; IV all zeros.
- The server's ephemeral DH private key MUST persist across the two rounds (per-connection state).
- RFC 3820 proxy verification requires `X509_V_FLAG_ALLOW_PROXY_CERTS` on **both** the `X509_STORE` and the `X509_STORE_CTX` — store-only silently fails.

Above the handshake, chain policy is where the module is deliberately **stricter than stock** — Globus `signing_policy` enforcement, RFC 3820 limited-proxy monotonicity, CRL-expiry rejection, GT2/GT3 legacy-proxy rejection — with identity keyed on the **EEC DN, not the proxy leaf** (stable across proxy re-mints; the enabler for zero-provisioning multi-user). All [LOCAL] strictness choices, tabled for experts in §11.3. VOMS attributes are extracted via `libvomsapi` at runtime; delegated proxies (direct upload and GridSite two-step CSR) are chain-verified rather than DN-trusted.

### 6.3 `ztn` — bearer tokens on the binary plane

`credtype="ztn\0"`, payload = `ztn` prefix + the compact JWT (single round, no challenge) [WIRE] #23; the module also accepts the stock `XrdSecProtocolztn` TokenResp framing [SRC]. The advertisement is `&P=ztn,v:10000` at login, listed *first* when both token and GSI are offered.

**The same validator serves ztn and HTTP `Authorization: Bearer`** — one pipeline, one policy [LOCAL]:

structural split → JOSE-header policing **before any signature work** (alg allow-list RS256/ES256 only; reject `alg:none` and any `crit`) → signature (exact-`kid` match when present, no single-key fallback; all-keys rotation grace when absent) → claims (`exp` mandatory; non-string `sub` rejected) → **exact issuer pin** + audience membership (plus the WLCG any-wildcard `https://wlcg.cern.ch/jwt/v1/any`) → skewed time window (saturating arithmetic; `nbf` zero-skew) → scope parse.

Scopes (`storage.read/write/create/modify/stage`) are matched by exact-length compare and boundary-checked path prefixes (`/data` ≠ `/database`); the global `allow_write` gate runs *before* any token logic (fail-closed ordering, invariant 3). Multi-issuer support parses the upstream `scitokens.cfg` INI dialect verbatim with per-issuer JWKS/audience/base-path/restricted-path.

### 6.4 SSS, Kerberos, and the rest

**sss** [SRC]: Blowfish-CFB64 + CRC32 over a shared keytab, mandatory replay window, `O_NOFOLLOW` keytab open, cleansed scratch. The CRC (not HMAC) integrity check is safe *because* secrecy lives in the Blowfish key — a subtle stock design worth preserving verbatim. **krb5** [SRC]: inbound `krb5_rd_req` against the host keytab (no server-side KDC round-trip — event-loop-safe); optional forwarded-TGT delegation captures a `KRB_CRED` into a 0600 FILE ccache (wire form: `"krb5\0"` + raw AP-REQ) and replays it outbound via a full mutual-auth `gss_init_sec_context` loop framed as `kXR_auth`/`kXR_authmore`. **pwd** (DH-bootstrapped, password never in clear) and **host** (reverse-DNS allowlist, fail-closed) complete the set.

### 6.5 Credential delegation to backends [LOCAL]

Where the module is a gateway, the origin leg re-authenticates **as the requesting user**: per-principal credentials (`x509_proxy` | `bearer` | `s3` | `ceph-keyring`) selected by EEC DN / token `sub` / access-key-id through a single decision gate, with **refuse-rather-than-downgrade** (an expired proxy hard-declines; `fallback=deny` fails `EACCES` *before* any origin op can ride the service credential). Bearer passthrough enforces an **audience gate**: the client token's `aud` must accept the target backend (or carry the WLCG wildcard) before verbatim forwarding — a directive that was once parsed-but-unenforced, i.e. a silent fail-open, until wired (§11.2). S3 backends cannot do passthrough at all — SigV4 proves knowledge of a secret that never transits — so STS `AssumeRole` mints short-lived per-principal credentials instead; this structural asymmetry is invariant 6 and §11.6.

---

## 7. The HTTP plane — XrdHttp equivalence

The same storage semantics exposed over HTTP(S), coexisting with the binary plane two ways [LOCAL]: a **single-port handoff** (first-byte classification — an XRootD hello starts with a zero word, so an HTTP method letter or TLS `0x16` is unambiguous; non-root bytes are spliced to a local HTTP listener with the prefix replayed) and a **"notroot" security guard** (root-only ports *drop* non-root bytes and emit one fail2ban-consumable audit line instead of splicing).

XrdHttp compatibility surface [SRC]: request side honors `X-Xrootd-Proto`, `?xrd.*`/`?tpc.*` CGI, `X-Xrootd-Requuid`, `X-Xrootd-Tpc-Token`; response side always emits `X-Xrootd-Status` (the kXR code mapped *out of* the HTTP status — the inversion of the binary plane, where kXR is native), echoes the requuid, and carries `X-Xrootd-Wait`/`X-Xrootd-Retry` as the HTTP rendering of `kXR_wait` semantics. There is no HTTP `readv`; vector reads are RFC 7233 `multipart/byteranges`. `Want-Digest` (RFC 3230) fronts the §5.5 engine.

Beyond XrdHttp's method set, the module serves full RFC 4918 WebDAV (PROPFIND/PROPPATCH-as-xattrs/MKCOL/MOVE/COPY), xattr-backed LOCK/UNLOCK with recursive child-lock enforcement on collection ops (invariant 5), RFC 5323 SEARCH, and read-only RFC 3744 ACL discovery [LOCAL] — for desktop and rucio clients. An S3 endpoint (SigV4, §6.5) shares the same VFS. One brix protocol per listen port is enforced at config time. The errno→HTTP mapping mirrors §2-D4 (`ENOENT`→404, `EACCES`→403, kernel path-escape `EXDEV`/`ELOOP`→403-not-500 [LOCAL], `EEXIST`/`ENOTEMPTY`→409).

---

## 8. Third-party copy

Two disjoint transports sharing only a neutral spine [LOCAL architecture; wire contracts SRC/WIRE]:

**Native TPC** — destination-pull, driven entirely through `kXR_open` CGI (`tpc.src`, `tpc.key`, `tpc.org`, `tpc.dst`) [WIRE] #30. The rendezvous key is single-use with expiry (the module holds it in a cross-worker SHM registry — 256 slots, consume-on-match replay protection [LOCAL]); the pull is **two-phase keyed off `kXR_sync`** (first sync arms, second fires) [SRC — the stock client's sequence], executed by a from-scratch outbound XRootD client session speaking GSI/ztn.

**HTTP TPC** — WebDAV `COPY` with `Source:` (pull) or `Destination:`+`Credential:` (push), `202 Accepted` + chunked WLCG performance markers, multi-stream via parallel Range-GETs [SRC — the WLCG HTTP-TPC profile]. SSRF hardening [LOCAL]: HTTPS-only, peer verification forced, resolved IP pinned via `CURLOPT_RESOLVE` to kill DNS-rebind TOCTOU.

`Qconfig tpc` MUST answer bare `1\n` (§4.6). S3 remote copy is refused (501).

---

## 9. Provenance ledger

The direct answer to "what was cloned, what was reverse-engineered, what is original." The implementation shares **no code** with the reference — it is C inside nginx's event loop, not translated C++ — so *everything* below was recovered through one of these four channels.

### 9.1 Cloned from the header, deliberately [SPEC]

Constants and layouts, byte-for-byte, as the license invites: the opcode registry (3000–3032), request/response header layouts, all per-opcode argument blocks, the status registry (0/4000–4007), the error registry (3000–3035), open mode/option bits, stat flags, page geometry (4096/4100/128/256), signing levels and `secvec` codes, TLS flag word, query subtypes, fattr limits, `read_list`/`write_list` geometry, attn action codes, and the `mapError`/`toErrno` tables.

### 9.2 Recovered by reading the reference C++ [SRC]

Semantics the header is silent on: unrecognized-op → `InvalidRequest` (vs `Unsupported`); open-reply sizing (4-byte unless compress/retstat); `kXR_rm` file-only never-recursive; sigver success = silence; the `kXR_status` fixed-CRC covering head-only; pgread absolute-offset page alignment; the full pgwrite CSE accept-then-correct machine with close-blocked bad-page ledger; statvfs 6-field text; statx per-path flag bytes and missing-path-is-error; `Qcksum` trailing-CGI trimming; `kXR_ItExists`-not-`FileLocked` for `kXR_new` on an existing file; which ops consult the redirect map; bind-channel restrictions; duplicate-login rejection; `kXR_set`-is-advisory; the stock `XrdCks` xattr caching convention; the ztn TokenResp framing; the two-phase `kXR_sync` TPC pull sequence.

### 9.3 Reverse-engineered from live behavior [WIRE]

The 30-item `protocol-notes.md` ledger; none of it is in the header or evident in a source skim — its own banner reads "None of these are in the specification — they were found by running the client against the server and reading the source when something didn't work." Headliners: modern-framing handshake reply + 44-byte coalescing (#1); the SecurityInfo trailer's necessity and silent-disconnect failure mode (#2); plain-text `&P=` login tokens (#3); the entire GSI byte-craft — DH-blob `kXRS_puk` format with 9-char trailer, `ffdhe2048`, unpadded derive, cross-round DH state, dual proxy-verify flags (#4–#6, #8); size-before-flags stat text (#7); CGI stripping (#9); the mandatory 32-byte pgwrite status (#10) and CRC-first pgwrite pages (#11); separate write-payload bound (#12); `kXR_mv` **space** separator with `arg1len` excluding any terminator (#13); `kXR_new|kXR_delete` = overwrite (#14); mkdir-path lexical resolution (#15); directory-open guard (#16); the dirlist `".\n0 0 0 0\n"` sentinel (#17); the in-`dlen` trailing NUL convention (#19); ztn single-round framing (#23); `kXR_set` always-`kXR_ok` (#24); no-login bind channels (#25); >16 MiB `oksofar` chunking (#26); control-byte dirlist exclusion (#27); bare-numeric `Qconfig tpc` (#28); POSC staging semantics (#29); TPC CGI rendezvous (#30).

### 9.4 Local design where the protocol is silent [LOCAL]

Choices an expert may ratify or contest, none wire-breaking: per-opcode `dlen` bounds before allocation; login-username printability policing; proxy gate keyed on `auth_done`; pipelining depth cap with non-pipelinable-op parking; 32 MiB sendfile frames (geometry only); readv coalescing into `preadv`; the SHM TPC key registry; POSC unlink-on-disconnect (vs stock's reconnect window — §11.4); richer errno mapping than stock's `mapError` (§5.4); interior-`..` rejection; EEC-DN identity; every §11.2/§11.3 strictness choice in the token and X.509 stacks; availability-biased CMS selection when a heartbeat drops (working around a documented stock defect where a dropped cmsd control connection yields false `kXR_NotFound` while the data plane still serves — a policy choice about trusting stale control-plane state that a federation operator should ratify); the notroot guard; single-validator ztn/Bearer convergence; UDP XrdMon replaced by Prometheus/SRR (aggregate parity; per-event granularity deliberately not reproduced).

### 9.5 Vendor extensions [EXT]

Opcodes 3500–3503; `kXR_fattrRecurse 0x20`; the `Qconfig xrdfs.ext` capability channel; (and `QFinfo 9`/`QFSinfo 10`, whose registry status needs clarification — §11.1).

---

## 10. Conformance posture versus the reference

Working rule of the module's differential program: **a divergence from the reference is a bug in the module unless there is positive evidence otherwise.** The candid ledger (`docs/10-reference/comparison/xrootd-vs-nginx/11-gaps-divergences-and-extras.md`) records 23 fixed divergences, each now pinned by a regression test. Representative:

| Area | Reference behavior | The module's former bug | Severity |
|---|---|---|---|
| `kXR_rm` on a **directory** | never recurses | **recursively deleted the subtree (data loss)** | Critical |
| `kXR_sigver` success | no response (envelope) | ACKed it → stream desync | High |
| redirect map | consulted by all ops | only open/locate consulted it | High |
| open reply | 4-byte unless compress/retstat | always 12-byte | High |
| `Qcksum` CGI junk | trimmed before algo lookup | NUL folded into algo name | High |
| `statvfs` | 6-field | 4-field ("Invalid response") | Med |
| `statx` | 1 flag byte/path; missing = error | 4 bytes; missing = ok+offline | Med |
| `open(kXR_new)` on existing | `kXR_ItExists` | `kXR_FileLocked` | Med |
| pgread pages | absolute-offset aligned | read-start aligned | Med |

**10.1** The `kXR_rm` finding is the argument for differential testing over spec-reading: "delete the named thing" is a *plausible* reading of an underdocumented op — and a data-loss bug.

**10.2** The self-consistency lesson: fixing the open-reply sizing broke the module's *own* cache-fill origin client, which had over-specified the old 12-byte framing. A spec-correct change can break any internal peer that encoded the bug — every in-tree client leg must track the same wire contract the external differentials assert.

**10.3** Honesty caveat, stated once and applying wherever "stricter than stock" appears: the WLCG-token and X.509 differential goldens note their **stock-XRootD columns were not fully populated** (no SciTokens-configured stock server; baseline CA config). Those claims presently rest on the pinned-source read plus partial live runs; they are source-verified, pending a fully-configured live re-run the project should perform.

---

## 11. Areas of ambiguity — where experts need to weigh in

### 11.1 The wire spec itself — behaviors that should be promoted to normative text

The [WIRE] ledger *is* the case that the header-as-spec model under-specifies. Candidates for normative promotion, with the header's own internal nits as supporting evidence:

1. The modern handshake reply framing and 44-byte coalescing (§3.2) — the legacy 12-byte struct is still what the header shows.
2. `kXR_mv`'s space separator and `arg1len`-excludes-terminator (§4.1).
3. The one-trailing-NUL-inside-`dlen` convention (§3.3).
4. The mandatory 32-byte `kXR_status` on successful pgwrite, CRC-first pgwrite pages, and absolute-offset pgread alignment (§5).
5. `kXR_new|kXR_delete` = overwrite (§4.2).
6. Plain-text `&P=` login security tokens, and an authoritative byte layout for the `kXR_protocol` security trailer — the header's `'S'` struct and the observed working layout do not obviously coincide (§3.5), and the failure mode is a silent disconnect.
7. The dirlist dstat sentinel and control-byte exclusion rule (§4.3).
8. Bare-numeric `Qconfig tpc`; and whether `<key>=0` echo-for-unanswered is acceptable given it collides with a genuine zero answer (§4.6).
9. **`kXR_chkpoint ckpXeq` / `kXR_writev` payload streaming**: stock frames `ckpXeq` with `dlen==24` (the embedded sub-request header only) and streams the sub-payload *after* the frame; the module expects it inline. Both in-tree peers agree with each other — which is exactly the trap (§10.2). The historical `writev` layout heuristic (`n·16 + Σwlen == dlen`) existed only because this same class of framing was ambiguous. **The streaming contract should be stated normatively.**
10. Header nits that show the fragility: `kXR_PROTOCOLVERSION 0x511` vs `"5.1.0"` under the header's own encoding rule; `kXR_ckpMinMax = 104857604` commented "10 MB" (it is ~100 MiB + 4 — 10 MiB is 10485760); `ClientGPfileRequest` self-annotated "all wrong; correct when implemented"; `QFinfo 9`/`QFSinfo 10` absent from the pinned `XQueryType` yet in circulation.

### 11.2 WLCG token profile — contested readings [found, not fixed; documented deviations]

1. **RFC 6750 divergence:** invalid/absent bearer → **403, not 401**, and no `WWW-Authenticate: Bearer`; dual credential transports → 200 not 400; no `Cache-Control: no-store` on query-token responses. Deliberate (storage-server convention + regression-surface risk); a strict 6750 reviewer may object.
2. `wlcg.ver` parsed but advisory — the profile arguably doesn't mandate rejection; genuine interpretation dispute.
3. **No `jti` replay cache** — tokens replayable until `exp`; high-value write endpoints may want one.
4. Effective payload cap ~4096 bytes (stricter than the 8192 raw-token guard) — rich `wlcg.groups` tokens could be rejected; undocumented in the profile.
5. Under-checked semantics: `iat > exp` unchecked; lifetime > 6 h not rejected (a WLCG SHOULD).
6. **SciTokens compatibility deliberately absent** — no `ANY` audience, no `read:`/`write:` scopes; "this is a WLCG server, `storage.*` only." A migration concern for SciTokens-native issuers.
7. `kid`-less verification = try-every-key rotation grace — the spec is silent; a policy call.
8. Asymmetric skew: configurable on `exp` (default 30 s), zero on `nbf`.
9. The WLCG any-wildcard is honored in **two** places that must stay in sync — the front-door audience pin and the backend-passthrough gate — and the latter was a silent fail-open until wired: "parsed" ≠ "enforced" is a review axiom this codebase re-learned.

### 11.3 X.509 / IGTF — stricter than stock, sometimes because stock has a defect

1. **Source-verified: stock XrdHttp does not enforce Globus `signing_policy`, does not enforce RFC 3820 limited-proxy monotonicity, and only warns on CRL expiry.** The module enforces all three by default; differentials record `xrootd=accept⚠ / spec=reject` on those rows. Consequence worth stating starkly: **a site moving from this module *to* stock would lose enforcement.** (Caveat §10.3 applies.)
2. `brix_crl_mode` defaults to `try` — a deliberate softening of the old "any CRL loaded ⇒ required for all"; sites wanting hard CRL must opt into `require`.
3. **Legacy GT2/GT3 proxies (no `proxyCertInfo`) are rejected** — stricter than stock; breaks sites still minting them.
4. Not implemented, shared with stock: RFC 5280-grade encoding-independent DN equality / RFC 4518 folding (`signing_policy` matches the `oneline` rendering); CApath hash-collision retry; delta-CRL *un*-revocation and CRLNumber precedence (any revoking CRL revokes — fail-safe).
5. nginx's TLS layer applies OpenSSL's `SSL_CLIENT` purpose check *before* the module sees the chain — anyEKU-only leaves rejected; inherent to terminating TLS in nginx, stricter than RFC 5280.

### 11.4 Recovery-shape forks

1. **POSC on disconnect:** the module unlinks the staging temp immediately; stock keeps the partial pending a reconnect window. Both defensible; documented `xfail`. Sites with flaky-WAN clients relying on reconnect-resume should weigh in.
2. **Interior `..`** (`/sub/../f`) now rejected rather than normalized — the reference doesn't normalize; a namespace-literalness call (escape was always kernel-confined; this is conformance, not a new boundary).

### 11.5 TLS granularity advertised but not independently enforced

`kXR_tlsData` is negotiated but not independently enforced; `kXR_tlsSess` follows login TLS; the GPF TLS bits are moot (GPF deferred). **The module treats TLS as a session-wide property fixed at login.** A federation posture requiring "TLS for data only" or per-category enforcement is not fully honored — the concrete gap behind §13-Q4. (Related nginx-inherent nit: cleartext-to-TLS-port yields HTTP 400, not stock's bare handshake reset.)

### 11.6 Multi-user identity and the S3 impedance mismatch

1. Enforced cache-transparency invariant: `verdict_cached ≡ verdict_cold` per (principal, path, op, protocol) — any cache-hit ALLOW where cold DENIES is a cross-user leak and a release blocker; the full authz gate runs *before* the residency stat to kill the cache-timing oracle.
2. **S3 cannot express per-user identity** — one SigV4 keypair per backend, token scope never consulted on the S3 leg (invariant 6's concrete cost). Sites wanting per-user S3 authorization cannot get it here; STS session-tagging is the partial mitigation.
3. Ambiguous/unscopable credential situations fail closed — deny the whole mapping on any denial.
4. Runtime `setfsuid` byte-ownership is only partially exercised in the multi-user fleet — auditors of on-disk uid/gid provenance should read the tracking note.

### 11.7 Deferred, untested, or gateway-shaped — validate before relying

**Correctness-deferred:** stream write-mirroring (never e2e+ASAN-completed); AIO-disconnect UAF guard unexercisable here; S3-STS/krb5 origin hooks call-ready but not fully live-driven. **Perf-deferred to a trustworthy host:** concurrent-AIO flip, pipeline-depth raise, S3 write offload, pgread windowing. **Gaps:** cache/write-through origin legs authenticate anonymously (no outbound ztn/GSI `kXR_authmore` completion); native-TPC-to-TLS-origins and multi-hop delegation unvalidated; tape (`prepare`/`query prep`/evict/recall) is a *gateway* to a site's storage manager, not an XrdFrm — **the largest single operator-must-validate item**; no OSS/sec plugin ABI, no PSS/PFC, `kXR_ecRedir` never set; Ceph needs the site namelib. **Untested-but-claimed:** `kXR_set` untested with unknown-option policy "TBD"; `kXR_fattrRecurse` is interop-undefined outside brix.

---

## 12. Implementation invariants

Twelve enforced invariants, each the compressed resolution of an ambiguity above (full text: `docs/09-developer-guide/agent-guide-extended.md`):

| # | Invariant | Resolves |
|---|---|---|
| 1 | pgread/pgwrite → `kXR_status`(4007) + per-page CRC32c | the v5 integrity contract, §5 |
| 2 | TLS = memory buffers only; cleartext = file-backed sendfile; never mixed | plane confusion → cleartext leak or lost zero-copy |
| 3 | global `allow_write` before token scope | fail-closed ordering, §6.3 |
| 4 | `resolve_path()` before every `open()` | confinement; the `..` seam of §11.4 lives here |
| 5 | collection DEL/MOVE/COPY → recursive child-lock checks | RFC 4918 lock scope |
| 6 | S3 SigV4 ≠ WLCG token, never shared logic | two identity models, §11.6 |
| 7 | stat via handle metadata | TOCTOU + per-read syscall cliff |
| 8 | low-cardinality metric labels only | cardinality explosion, [WIRE] #21 |
| 9 | `crc64` ≠ `crc64nvme`; encode at the edge | silent wrong digests, §5.5 |
| 10 | SHM mutex spin+yield, never semaphore mode | a lost-wakeup freeze (60–450 s) on the open path |
| 11 | VFS is the sole storage truth | who owns a syscall; one confinement/metrics/integrity path |
| 12 | machine-enforced seam guard for #11 | CI, not convention |

---

## 13. Questions for reviewers

1. **Spec editors:** should the §11.1 list — headed by the pgwrite 32-byte status, the handshake reply framing, the `&P=` text dialect, the security-trailer layout, and the `ckpXeq`/`writev` payload-streaming contract — be promoted from reference-behavior to normative text? The header's own nits (§11.1.10) argue the header alone cannot carry this weight.
2. **WLCG security:** is the stricter-than-stock X.509 posture (§11.3) the desired default — and will the project's fully-configured differential re-run (§10.3) be accepted as the evidence bar?
3. **Token profile owners:** which §11.2 deviations are acceptable (403-not-401 foremost), and is a `jti` replay cache warranted for write endpoints?
4. **Federation architects:** is session-wide TLS acceptable where `kXR_tlsData`/`tlsSess` granularity is advertised (§11.5)?
5. **Storage operators:** per-user S3 identity (§11.6) — accept the STS mitigation, or is a design change needed? Tape/Ceph/EC profiles: gateway model sufficient, or plugin-ABI parity required (§11.7)?
6. **The collaboration:** does the registry want an official vendor-extension range (the module squats 3500–3503 with capability negotiation, §4.9) and an official POSIX-completeness answer (`utimens`/`symlink`/`link`)?
7. **Release honesty:** should the §11.7 untested surfaces ship as *supported* or *documented-experimental* until end-to-end tested?

---

## 14. References

**Normative-by-practice:** `/tmp/brix-src/src/XProtocol/XProtocol.hh` (protocol definition + reimplementation license; `mapError`/`toErrno`); `XrdXrootd/XrdXrootdXeq.cc`, `XrdXrootdResponse.cc`, `XrdXrootdProtocol.cc` (semantic oracle); `XrdSec*`, `XrdHttp/`, `XrdHttpTpc/`, `XrdCks/` (auth, HTTP, TPC, checksum conventions).

**The module:** protocol core `src/protocols/root/protocol/opcodes.h` and siblings, `connection/`, `handshake/`, `session/`, `read/`, `write/`, `response/`; auth `src/auth/`; HTTP `src/protocols/{webdav,s3,shared}/`; TPC `src/tpc/`; VFS `src/fs/`; error mapping `src/core/compat/`.

**In-repo analyses this RFC synthesizes:** `docs/10-reference/protocol-notes.md` (the 30-item [WIRE] ledger); `docs/10-reference/{source-verified-xrootd-comparison.md,protocol-gaps-vs-xrootd.md,quirks.md,upstream-xrootd-defects.md,wlcg-token-differential-findings.md,wlcg-x509-differential-findings.md}`; `docs/10-reference/comparison/xrootd-vs-nginx/11-gaps-divergences-and-extras.md`; `docs/09-developer-guide/{agent-guide-extended.md,wlcg-token-conformance.md,wlcg-ca-conformance.md,multiuser-conformance.md,multi-user-backend-credentials-through-the-vfs.md,xrdsecgsi-handshake.md,pgread-write.md}`.

---

*Informational working draft. It defines the protocol as interoperability requires, not as any single document states it; where the two differ, the difference is tagged and tabled for expert adjudication. No drop-in claim is made for any deployment profile — the correct proof for a profile is a site-specific conformance matrix, not a feature list.*
