# XRootD SSI — Protocol Deep Dive

How the **Scalable Service Interface (SSI)** works on the wire, how it relates to
the rest of XRootD, and what our native nginx implementation does. Everything
here was traced from the XRootD source (`/tmp/xrootd-src/src/XrdSsi`,
`src/XrdCl`, `src/XProtocol`) and **validated against the real `libXrdSsi`
client** driving our module.

---

## 1. What SSI is (and isn't)

SSI turns an XRootD data server into a generic **request/response RPC host**. A
client sends an opaque request blob to a named *service* and gets back a response
blob (plus optional metadata, alerts, and streamed data). It is the substrate
behind things like the EOS/`FST` query services and other "ask the storage a
question" use cases.

The crucial architectural fact: **SSI is not a new protocol.** It is a
*sub-protocol tunnelled through the ordinary `root://` file protocol*. There are
no new opcodes. An SSI conversation is a sequence of perfectly normal
`kXR_open` / `kXR_write` / `kXR_query` / `kXR_read` / `kXR_truncate` requests —
the SSI control information is **smuggled into fields that the file protocol
otherwise uses for byte offsets and file handles**.

This is the single most important thing to understand about SSI, and it's what
makes it both elegant and slightly maddening.

```text
  THE SLEIGHT OF HAND: same opcode, fields mean something else
  ───────────────────────────────────────────────────────────
  ordinary kXR_write                    SSI kXR_write
  ┌──────────────────────────┐          ┌──────────────────────────┐
  │ fhandle = real open file │          │ fhandle = SSI SESSION id  │
  │ offset  = byte position  │          │ offset  = XrdSsiRRInfo    │
  │           in the file    │          │   {cmd, reqId, size}      │
  │ body    = bytes to store │          │ body    = RPC request blob│
  └──────────────────────────┘          └──────────────────────────┘
            writes to disk                   dispatches an RPC call

  To a stock proxy/redirector in between, the SSI request is indistinguishable
  from file I/O at a weird offset — which is exactly why SSI traverses them
  unchanged. The 24-bit reqId in the offset multiplexes many calls on one fd.
```

---

## 2. The control word: `XrdSsiRRInfo`

Every SSI operation carries an 8-byte control word, `XrdSsiRRInfo`, that the file
protocol thinks is a *file offset* (in `kXR_read`/`kXR_write`) or is passed as the
*body* of a `kXR_query`. It packs three fields:

| Field | Bits | Meaning |
|---|---|---|
| `Cmd` | 8 | `Rxq`(0) data exchange, `Rwt`(1) response-wait, `Can`(2) cancel |
| `reqId` | 24 | request id — multiplexes many in-flight requests on one fd |
| `Size` | 32 | request size (on the write) |

**Wire layout (the 8 bytes as they appear in the big-endian kXR offset):**

```
[id_lo][id_mid][id_hi][cmd][size as little-endian uint32]
```

Golden values generated from the real `XrdSsiRRInfo` class (this is the byte-exact
oracle our codec is tested against):

```
Rxq id=5      size=100   -> 0500000064000000
Can id=0x123456 size=4096 -> 5634120200100000
Rwt id=1      size=0     -> 0100000100000000
```

The odd mixed endianness is an artifact of `XrdSsiRRInfo` storing each field with
`htonl` and then combining them; on the wire it nets out to the layout above. It
assumes a consistent host endianness between peers — fine in practice (everything
is little-endian x86/ARM64-LE).

---

## 3. The response-attention prefix: `XrdSsiRRInfoAttn`

Responses (whether delivered as a `kXR_query` reply or pushed via `kXR_attn`) are
prefixed with a 16-byte `XrdSsiRRInfoAttn` header:

```
[tag:1][flags:1][pfxLen: BE u16][mdLen: BE u32][reserved:8]
```

- `tag`: `':'` fullResp (data present), `'*'` pendResp (more via read / pending),
  `'!'` alrtResp (this is an alert, not the response).
- `pfxLen`: prefix length, always 16.
- `mdLen`: length of the metadata blob that follows.

A complete response payload is therefore:

```
[XrdSsiRRInfoAttn 16][metadata mdLen][data dbL]
```

and the client (`XrdSsiTaskReal::GetResp`) recovers the data length as
**`dbL = total - mdLen - pfxLen`**, reads metadata at `+pfxLen`, data at
`+mdLen+pfxLen`. Golden: a fullResp with `mdLen=0x11223344` →
`3a000010112233440000000000000000`.

---

## 4. The full conversation on the wire

A unary request/response, exactly as the real `libXrdSsi` client performs it:

```
client                                   server
  | kXR_open  "/<resource>"  (+kXR_retstat)  |
  |----------------------------------------->|   bind SSI session -> fhandle
  |<-----------------------------------------|   ServerOpenBody + StatInfo string
  |                                          |
  | kXR_write  fhandle, offset=RRInfo{Rxq,   |
  |   reqId, size},  body=<request bytes>    |
  |----------------------------------------->|   accumulate request; dispatch
  |<-----------------------------------------|   kXR_ok (write ack)
  |                                          |
  | kXR_query  infotype=kXR_Qopaqug(64),     |   (this is XrdCl File::Fcntl!)
  |   fhandle, body=RRInfo{Rwt, reqId}       |
  |----------------------------------------->|   response-wait
  |<-----------------------------------------|   [RRInfoAttn ':'][meta][data]
```

Key, non-obvious facts (each cost real debugging to discover):

1. **Response-wait is `kXR_query`, not `kXR_read`.** The client uses
   `XrdCl::File::Fcntl`, which on the wire is `kXR_query` with
   `infotype = QueryCode::OpaqueQ = kXR_Qopaqug = 64`, the `fhandle` of the SSI
   session, and the 8-byte `RRInfo{Rwt}` as the request *body*. The server replies
   to *that* query with the response payload.
2. **Open uses `kXR_retstat`.** The libXrdSsi client opens the resource with the
   `kXR_retstat` option and **refuses the reply unless a StatInfo string follows
   the 12-byte `ServerOpenBody`** (`"id size flags mtime"`). For a virtual SSI
   resource the server synthesizes one.
3. **The login frame is 24 bytes** including the 4-byte `pid` field — easy to
   under-fill to 20 and hang.

### Streaming, async, alerts, cancel

- **Streaming / large response:** the query reply uses tag `'*'` pendResp with
  metadata only (no inline data). The client's `GetResp` maps any non-`fullResp`
  tag to `isStream` and pulls the body with `kXR_read` (offset = `RRInfo{Rxq}`),
  reading until a short read signals the last chunk.
- **Async (deferred) response:** if the response isn't ready when the query
  arrives, the server replies `kXR_waitresp` and later pushes the answer
  *unsolicited* as `kXR_attn` with `actnum = kXR_asynresp (5008)` carrying an
  inner `ServerResponseHdr` whose streamid matches the deferred request. (This is
  the same `kXR_attn`/`waitresp` mechanism XRootD uses for FRM tape recall.)
- **Alerts:** out-of-band progress messages pushed as `kXR_attn` with the
  `alrtResp '!'` tag before the final response.
- **Cancel:** `RRInfo{Can}` delivered via `kXR_query`/`kXR_truncate`.

---

## 5. The client and server stacks

**Client** (`libXrdSsiLib`, exported global `XrdSsiProviderClient`):

```
XrdSsiProviderClient->GetService(eInfo, "host:port")
   -> XrdSsiService
service->ProcessRequest(XrdSsiRequest&, XrdSsiResource&)
   -> XrdSsiTaskReal  (per-request state machine)
       -> XrdCl::File  Open / Write / Fcntl(=query) / Read
   callbacks back into your XrdSsiRequest subclass:
       GetRequest()           supply request bytes
       ProcessResponse()      response metadata arrived (isData/isStream/isError)
       ProcessResponseData()  data chunk(s); last=true ends it
       Alert()                out-of-band alert
```

**Server (stock XRootD)** is a chain of C++ plugins:

```
xrootd.fslib / ofs.osslib  ->  XrdSsiSfs  (an SFS filesystem plugin)
   -> XrdSsiFileSess   (per-open session: open/write/read/fctl/truncate)
   -> XrdSsiFileReq    (per-request state)
   -> XrdSsiService / XrdSsiResponder   (the actual service — YOUR C++ plugin)
```

The service author implements `XrdSsiService::ProcessRequest` and drives an
`XrdSsiResponder` (`SetMetadata`, `SetResponse`, `Alert`, `SetErrResponse`).

---

## 6. How SSI compares to other XRootD components

| Component | Transport | New opcodes? | Control mechanism |
|---|---|---|---|
| **XrdXrootd** (data server) | `root://` (xroot binary) | the opcodes themselves | offset = real byte position; fhandle = real file |
| **SSI** | **rides** `root://` | **none** — reuses open/write/query/read | offset/Fcntl-body = `XrdSsiRRInfo`; fhandle = session |
| **CMS** (clustering) | separate binary on its own port | own `kYR_*` opcode space | 8-byte `CmsRRHdr` + XrdOucPup payload |
| **XrdHttp / WebDAV** | HTTP(S) | HTTP verbs | headers + URL + opaque CGI |
| **TPC** (third-party copy) | `root://`/HTTP | reuses open | opaque CGI tokens (`tpc.key`, …) in the path |
| **pgread/pgwrite** | `root://` | reuses read/write | extended `kXR_status` (4007) frames + per-page CRC32c |

Two big families emerge:

**(a) Sub-protocols that tunnel through the file protocol** — SSI, TPC,
pgread/pgwrite. None add opcodes; they overload existing request fields (offset,
CGI, status frames). The payoff is **transparency**: an SSI or TPC request flows
through any stock xroot proxy/redirector unchanged, because to the proxy it's just
an open/write/read on a file. SSI is the most extreme example — it turns the file
*offset* into an RPC control word and the file *handle* into a session/mux id.

**(b) Genuinely separate protocols** — CMS is the contrast: a different opcode
space (`kYR_*`), a different framing (`CmsRRHdr` + Pup), usually a different port.
It is *not* tunnelled through anything; it's the cluster control plane. (Our
module implements both; see the CMS manager-breadth work.)

**The shared async substrate.** `kXR_attn` (4001) is XRootD's one unsolicited
server→client push channel, and several components ride it: SSI deferred
responses (`asynresp`) and alerts (`alrtResp`), `kXR_waitresp` completions, and
FRM async tape-recall replays. So while SSI invents its own *request* encoding, it
reuses the *standard* async-delivery plumbing.

**Plugin shape.** On a stock server, SSI is delivered as the same kind of
loadable C++ plugin as an OSS/CFS backend (`xrootd.fslib libXrdSsi...`). This is
why a faithful native re-implementation has to replace the `XrdSsiService` /
`XrdSsiResponder` ABI with a native interface — which is exactly what we did.

---

## 7. Design assessment

**Strengths**
- No new opcodes → works through existing proxies/redirectors untouched.
- One TCP connection multiplexes many concurrent requests via the 24-bit `reqId`.
- Supports the full RPC surface: metadata, streamed responses, out-of-band
  alerts, async/deferred completion, cancel.

**Weaknesses / sharp edges**
- Control-in-offset is opaque and tooling-hostile: a packet trace looks like
  random file I/O at absurd offsets.
- Endianness is assumed consistent between peers (works in practice, not
  formally portable).
- The server side is a heavyweight C++ plugin ABI.
- The client request lifecycle (`XrdSsiTaskReal`) is a non-trivial callback state
  machine.

---

## 8. How our nginx module implements SSI natively

We re-implement the **server** side natively (no C++ plugin ABI), in `src/ssi/`:

| File | Role |
|---|---|
| `ssi_rrinfo.{c,h}` | byte-exact `XrdSsiRRInfo` + `XrdSsiRRInfoAttn` codec (golden-validated vs the real class) |
| `ssi_service.{c,h}` | native `xrootd_ssi_responder_t` (`set_metadata`/`set_response(last)`/`alert`/`error`) + service registry; built-ins `echo`/`meta`/`stream`/`err` |
| `ssi_reply.{c,h}` | builds the `[RRInfoAttn][meta][data]` reply payload |
| `ssi.{c,h}` | wire glue: `open` (resolves service, honours `kXR_retstat`), `write` (decode RRInfo, accumulate, dispatch), `query` (intercepts `kXR_Qopaqug` → response-wait / cancel), `read` (stream pull) |

Integration points in the hot path: `src/read/open_request.c` (SSI path match →
`ssi_open` with options), `src/write/write.c` (passes the raw offset bytes →
`ssi_write`), `src/query/dispatch.c` (intercepts `kXR_Qopaqug` when the fhandle is
an SSI session), `src/read/read.c` (stream pull). A native compiled-in service
replaces the C++ `XrdSsiService` plugin; the resource path is `/.ssi/<service>`.

**Proven working** against the real `libXrdSsi` client (`tests/ssi_client.cc`,
linked against the system `libXrdSsiLib`): unary request/response, metadata,
streaming, error, and cancel. Verified by 33 standalone unit checks +
`tests/test_ssi_wire.py` (raw-wire + real-client).

**Still to do:** genuinely-async services (`kXR_waitresp` + deferred
`kXR_attn(asynresp)` push — the `xrootd_send_attn_asynresp` helper exists) and
out-of-band alerts (`alrtResp` push). Both reuse the existing `kXR_attn` infra.

---

## 9. Gotchas worth remembering

1. Response-wait is `kXR_query`/`kXR_Qopaqug` (XrdCl `File::Fcntl`), **not** read.
2. `kXR_open` from libXrdSsi sets `kXR_retstat`; the reply must append a StatInfo
   string after `ServerOpenBody` or the client rejects it ("Unable to parse
   StatInfo").
3. The login request header is 24 bytes — include the 4-byte `pid`.
4. `RRInfo` offset layout = `[id_lo][id_mid][id_hi][cmd][size LE32]`.
5. The client distinguishes inline-data from stream purely by the attn `tag`:
   `fullResp` → inline `isData`; anything else → `isStream` → it reads via
   `kXR_read`.
6. Validate byte-exactness by compiling a tiny C++ program against the header-only
   `XrdSsiRRInfo.hh` and printing the bytes — the real class is the oracle.
