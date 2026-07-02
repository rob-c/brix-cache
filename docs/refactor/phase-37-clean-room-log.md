# Phase 37 — Clean-room ledger

This ledger is the audit artifact for the clean-room claim of the native
`xrdcp`/`xrdfs` clients (see `phase-37-native-xrdcp-xrdfs-clients.md` §2). It records
**every** upstream XRootD source consulted, the specific *wire fact* extracted, and an
assertion that **no implementation logic was copied** from `XrdCl`/`XrdApps`/`XrdSec*`.

**Permitted inputs:** `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` (the published wire
contract), this project's already-derived `src/protocol/*.h`, the `xrdcp.1`/`xrdfs.1`
man pages, and black-box CLI behaviour (stdout/stderr/exit-code diff, packet capture)
against a reference server. **Forbidden inputs:** the C++ implementation bodies in
`XrdCl/`, `XrdApps/`, `XrdSec*/`, `XrdSut`, `XrdCrypto`.

Each code site that uses a non-obvious wire detail carries a
`/* wire: XProtocol.hh <field> — <fact> */` provenance comment that points back to an
entry here.

---

## M0 — libxrdproto extraction

**Upstream files consulted:** none.

M0 only re-packaged files **already present in this project** (`src/protocol/*.h`,
`src/core/compat/{crc32c,hex,crypto,error_mapping}.{c,h}`) into an ngx-free static library
build. It derived no new wire facts and copied nothing from upstream. The wire
vocabulary in `src/protocol/*.h` was established (and cross-checked) in earlier phases;
its own provenance is documented in `src/protocol/README.md`.

---

## M1 — connection spine + xrdfs stat/ls

**Upstream files consulted:** none beyond the project's own `src/protocol` headers
(themselves derived/cross-checked in earlier phases) and the project's own
server-side handlers (read to learn the *server's* response framing — that is our
own code, not XrdCl). The behavioural contract was then confirmed by **black-box
observation**: running the system `xrdfs` against the same servers and diffing
output/exit codes (clean-room-permitted observation, not source reading).

Wire facts used, each annotated in code with a `wire:` comment:

| Fact | Source (interface side) | Used in |
|---|---|---|
| 20B ClientInitHandShake = {0,0,0,htonl(4),htonl(2012=ROOTD_PQ)} | wire_core_requests.h / XProtocol.hh | conn.c |
| Handshake reply (streamid {0,0}) is distinct from the kXR_protocol reply (streamid = request's); key on streamid to tolerate either | project server handlers + XProtocol.hh framing | conn.c (do_handshake) |
| ServerProtocolBody = pval[4] flags[4]; caps in flags | wire_core_requests.h | conn.c |
| Anonymous kXR_login reply = sessid[16] only (dlen 16); any trailing bytes are a "&P=..." security list | opcodes.h XROOTD_SESSION_ID_LEN + observation | conn.c (do_login) |
| kXR_stat body = ASCII "<id> <size> <flags> <mtime>" | wire_core_requests.h | ops_meta.c |
| kXR_dirlist: kXR_oksofar chunks then final kXR_ok; with kXR_dstat a ".\n0 0 0 0" lead-in precedes name/stat line pairs | wire_core_requests.h | ops_meta.c |
| Stat flag bits (kXR_isDir=2, kXR_readable=16, ...) | flags.h | xrdfs.c, ops_meta.c |

Validation: native `xrdfs stat`/`ls` produce identical id/size/flags and identical
exit codes to the system `xrdfs` against both nginx (`:11094`) and the reference
xrootd daemon (`:11098`); `ls` output is byte-identical after sort.

## M2/M3 — file ops (xrdcp download + upload)

**Upstream files consulted:** none beyond `src/protocol` + black-box observation
(diffing native vs system `xrdcp` md5 round-trips).

| Fact | Source | Used in |
|---|---|---|
| kXR_open: mode[2] options[2] optiont[2] ... fhtemplt[4]; read = options kXR_open_read(0x10) | wire_core_requests.h, flags.h | ops_file.c |
| Write open options: kXR_open_updt \| kXR_mkpath \| (kXR_new \| kXR_delete) [\| kXR_posc] | flags.h | ops_file.c (open_write) |
| ServerOpenBody: fhandle[4] cpsize[4] cptype[4]; fhandle echoed in all later ops | wire_core_requests.h | ops_file.c |
| kXR_read: fhandle[4] offset[8 BE] rlen[4]; body = raw bytes across kXR_oksofar* then kXR_ok | wire_core_requests.h | ops_file.c (read) |
| kXR_write: fhandle[4] offset[8 BE] pathid[1]; payload = data (dlen) | wire_write_extended_requests.h | ops_file.c (write) |
| kXR_close: fhandle[4] | wire_core_requests.h | ops_file.c (close) |
| POSC (kXR_posc 0x1000): an abandoned write handle (connection torn down without a clean close) is discarded by the server → upload atomicity on error | flags.h + observation | copy.c (copy_upload) |

Validation: native `xrdcp` download is md5-exact for 5 MB, 200 MB, and stdout vs
origin; upload round-trips md5-exact; `-f`/no-`-f`/`-P` behave correctly; against
both nginx and (download) the reference xrootd.

## M4 — authentication (token / unix / GSI) + M7 — in-protocol TLS

**Upstream files consulted:** none beyond our own server code (`src/session/login.c`,
`src/auth/gsi/{auth,buffer,cert_response,parse_x509,parse_crypto_helpers,keypool}.c`,
`src/handshake/sigver.c`, `src/auth/token/token.c`) + `src/protocol/{gsi,flags,
wire_write_extended_requests}.h` + black-box runs of the system client. No
XrdSec*/XrdCrypto `.cc` read.

| Fact | Source | Used in |
|---|---|---|
| kXR_auth: credtype[4] at body bytes 16-19; kXR_authmore=more, kXR_ok=done | wire_core_requests.h + auth.c | auth.c |
| Login sec list `&P=<proto>[,args]&P=...` grammar | src/session/login.c | auth.c |
| ztn payload = "ztn\0" + JWT (server skips 4-byte tag) | src/auth/token/token.c | sec_token.c |
| unix payload = "unix\0" + user | src/auth/unix/auth.c | sec_unix.c |
| GSI buffer = name\0 + step[4 BE] + {type[4] len[4] data}* + kXRS_none(0) | src/auth/gsi/buffer.c | gsi_bucket.c |
| kXGS_cert (parse): kXRS_puk("...---BPUB---<hex>---EPUB--") + cipher_alg + md_alg + x509 + kXRS_main | src/auth/gsi/cert_response.c | sec_gsi.c |
| kXGC_cert (build): kXRS_puk(our pub) + kXRS_cipher_alg("aes-256-cbc") + kXRS_main(AES) ; inner = "gsi\0"+kXGC_cert+kXRS_x509(proxy PEM)+none | src/auth/gsi/parse_x509.c | sec_gsi.c |
| DH ffdhe2048 (EVP_PKEY group); derive dh_pad=0; AES-256-CBC key = **first 32 bytes** of secret, IV=0; signing_key = SHA256(secret) | src/auth/gsi/{keypool,parse_x509}.c | sec_gsi.c |
| Client DH pub blob format "---BPUB---<UPPERCASE hex>---EPUB--" (BN_bn2hex) | src/auth/gsi/parse_crypto_helpers.c | sec_gsi.c |
| kXR_sigver frame = ClientSigverRequest{expectrid,version,flags,seqno[8 BE],crypto} + 32-byte HMAC; HMAC = HMAC-SHA256(signing_key, seqno_be(8) ‖ hdr(24) ‖ payload); server replies kXR_ok; opcode/level policy | src/handshake/sigver.c, src/session/signing.c | sigver.c |
| TLS flags kXR_ableTLS/wantTLS (client), kXR_haveTLS/gotoTLS (server); upgrade after protocol reply, before login | flags.h + src/session/protocol.c | conn.c, tls.c |

## Minimization — shared `gsi_core` (single source for module + client)

To keep the client minimal and genuinely "built atop the module", the pure GSI/
sigver kernels were consolidated into `src/auth/gsi/gsi_core.{c,h}` (ngx-free: OpenSSL +
libc + protocol/gsi.h only) and compiled **build-in-place** into BOTH the nginx
module (via `config` NGX_ADDON_SRCS) and `libxrdproto` (via shared/xrdproto/Makefile)
— the same single-source pattern as crc32c/hex/crypto. Contents: `gsi_find_bucket`,
the bucket builder, ffdhe2048 `dh_keygen`, DH pub encode/decode, `build_peer`,
`derive`, and the `sigver` opcode policy.

Both sides now call it (no duplication): client `sec_gsi.c`/`sigver.c` use it
directly; module `src/auth/gsi/{keypool,buffer,parse_crypto_helpers}.c` and
`src/handshake/sigver.c` were rewired to thin wrappers/calls. The client's
`gsi_bucket.c` was deleted; client code shrank 3560→~3220 lines. (One small,
intentional dup remains: the inline DH derive in `src/auth/gsi/parse_x509.c`, left on the
server's critical decrypt path; gsi_core's derive is byte-identical.) The ngx-free
guard still passes; the module rebuilds clean under -Werror; the 30-test native suite
still passes — server and client interoperating through the one shared core.

Validation: token (nginx :11097) and GSI (cleartext :11095, GSI+TLS roots:// :11096)
stat/ls/download all succeed with md5-exact bytes vs origin; TLS peer verification
against $X509_CERT_DIR is enforced (empty CA dir → fail), no silent downgrade
(roots:// to a non-TLS port refused), `--noverifyhost` relaxes only the name check.
**kXR_sigver is implemented per the server verifier but NOT live-validated** — every
harness GSI server runs at security_level 0, so signing is dormant (gated on
sec_level>=2); the code is byte-for-byte the inverse of src/handshake/sigver.c.

## M5 — redirect / cluster follow

Wire facts (verified against the module's own emitters, not XrdCl):

| Fact | Module source (truth) | Client consumer |
|---|---|---|
| `kXR_redirect`(4004) body = `port[4 BE] + host[]` (host bare, already IPv6-bracketed by the server) | src/response/control.c `xrootd_send_redirect()` | lib/frame.c `parse_redirect()` |
| `kXR_wait`(4005) body = `seconds[4 BE]`; client backs off then RE-SENDS the same request on the SAME connection | src/response/control.c `xrootd_send_wait()` | lib/frame.c `xrdc_roundtrip()` |
| tried/triedrc loop-guard is purely client-side (the module does not track it) | — | lib/frame.c tried-set + redir_depth |

Design: `xrdc_recv` now surfaces `kXR_redirect`/`kXR_wait` as normal (status+body)
outcomes instead of `XRDC_EPROTO`. `xrdc_roundtrip()` wraps every path-based op
(stat/dirlist/open-read/open-write): on redirect it parses the target, enforces a
depth cap (`XRDC_REDIR_MAX`=16) and a visited-set loop guard (`host:port` strings),
then `xrdc_reconnect()`s and replays; on wait it sleeps (capped 30s) and re-sends.
`conn.c` was refactored into `xrdc_bringup()` (connect→handshake→[TLS]→login→auth on
`c->host`/`c->port`/`c->opts`) shared by both `xrdc_connect()` and `xrdc_reconnect()`
(teardown-without-endsess → bring up the new target, preserving creds/opts). Handle-
based reads/writes/close stay on the post-redirect DS connection, so redirects are
resolved once at open/stat time. `xrdc_copy()` gained client-mediated remote→remote
(two sessions, bytes transit the client — NOT server TPC, which stays out of scope).

Build hardening: `client/Makefile` now emits `-MMD -MP` auto-dependencies — editing a
header that changes struct layout (e.g. lib/xrdc.h) now reliably recompiles every
dependent object. Without this, an incremental `make` after the `xrdc_conn` size
change left stale mixed-ABI objects that read garbage (empty host → "connect :0").

Validation: the full `test_e2e_redirector_xrdcp.py` (8/8) passes with the native
binaries through the CMS redirector :11160 → DS :11162 — stat, ls, download, upload,
parallel, GSI, metrics, and cross-server (client-mediated) copy, all md5-exact. Three
new self-contained stub tests in `test_native_xrdcp_xrdfs.py` (in-process TCP servers,
no cluster) cover redirect-followed-to-target (success), redirect-to-self (loop
refused, security-neg), and wait-then-served (kXR_wait honored, ≥1s back-off). Native
suite now 33/33 (serial); 5 transient `ls /` timeouts seen only under parallel xdist
load are the known harness contention flake, not the client.

## M6 — paged I/O integrity (kXR_pgread/pgwrite) + --cksum

Wire facts (verified against src/read/pgread.c, src/write/pgwrite.c,
src/response/status.c, wire_core_requests.h):

| Fact | Module source (truth) | Client consumer |
|---|---|---|
| kXR_pgread=3030, kXR_pgwrite=3026 (opcodes.h; struct comment "3031" is stale) | opcodes.h | ops_file.c |
| Per-page unit is **[crc32c_be 4][data ≤4096]** — CRC FIRST, then data — aligned to the FILE offset (short first page) | src/read/pgread.c:83-87 | decode_pages / pgwrite build |
| Reply uses kXR_status(4007): hdr.dlen=24 (Status16+offset8, NOT page data); bdy.dlen = page-data length that follows; trailing offset[8] | src/response/status.c:59-83 | read_status_frame |
| kXR_status header crc32c covers the 20 bytes streamID..offset | src/response/status.c:66,85 | read_status_frame |
| inner requestid = opcode−kXR_1stRequest (pgread→30, pgwrite→26); resptype 0=Final/1=Partial | status.c:78-79 | — |
| pgwrite CRC failure → plain kXR_error/kXR_ChkSumErr (NOT the pgWrCSE bad-page list) | src/write/pgwrite.c:245 | xrdc_file_pgwrite |
| **crc32c is STANDARD Castagnoli** (init/xorout 0xFFFFFFFF, "123456789"→0xe3069283) — the header comment "init 0" in wire_core_requests.h is misleading; the libxrdproto routine the server, the client and Qcksum all use is the standard one | src/core/compat/crc32c.* (verified C-vs-Python) | checksum.c, decode_pages |
| kXR_Qcksum(3) via kXR_query(3001): payload "<algo> <path>" (server splits on first ':'/' '), reply "<algo> <hex>"; manager mode redirects the query to the DS | src/query/checksum_qcksum.c | xrdc_query_cksum (roundtrip) |

Implementation: `xrdc_file_pgread`/`xrdc_file_pgwrite` in ops_file.c share a
`read_status_frame()` helper (validates the kXR_status header CRC, surfaces
kXR_error, returns resptype + page-data length + offset) and a `decode_pages()`
that verifies each page's CRC32c via libxrdproto `xrootd_crc32c_value`. New
`lib/checksum.c` does streaming local adler32 (zlib) / crc32c (xrootd_crc32c_extend)
/ md5 (OpenSSL EVP) plus `xrdc_query_cksum`. `xrdcp --pgrw` switches the copy engine
to paged I/O; `xrdcp --cksum <t>[:source|:print|:<value>]` computes the local digest
and compares to the server's Qcksum / a literal / prints it (mismatch → drop dest +
fail). `client/Makefile` gained `-lz`.

Validation (40/40 native suite, serial): --pgrw download/upload byte-exact incl. a
200 MB round-trip (every page CRC32c checked); --cksum adler32:source and crc32c:source
agree with the server; md5:print correct; --cksum:<bad> drops the destination. A
self-validating stub pair proves the page-digest path: a clean kXR_status frame
(correct header+page CRC, built with a Python crc32c verified byte-identical to the C
routine) downloads successfully, and the same frame with one data byte flipped is
rejected with a CRC diagnostic and no destination left behind.

## M9 — full xrdfs (subcommands + REPL)

Wire facts (verified against the module handlers):

| Op | Request struct | Notes | Module truth |
|---|---|---|---|
| mkdir | ClientMkdirRequest | options[0]=kXR_mkdirpath(0x01) for -p; mode at offset 18 | wire_write_extended_requests.h |
| rm/rmdir | ClientRm/RmdirRequest | path payload | " |
| mv | ClientMvRequest | payload = **"src ' ' dst"**, arg1len=htons(len(src)); server requires payload[arg1len]==0x20 | src/write/mv.c:80-89 |
| chmod | ClientChmodRequest | mode at offset 18 | " |
| truncate | ClientTruncateRequest | offset[8]=new length, fhandle=0 ⇒ path-based | " |
| query | ClientQueryRequest | infotype at offset 4; Qconfig/Qspace/Qcksum/QStats; reply is text | wire_core_requests.h |
| statvfs | ClientStatRequest, options=kXR_vfs(1) | reply text "<id> <size> <flags> <mtime>"-style vfs body | src/read/stat.c |
| locate | ClientLocateRequest | reply "S<rw><host>:<port>" token | src/read/locate.c:189 |
| prepare | ClientPrepareRequest | options=kXR_stage etc; newline-separated paths | wire_core_requests.h |

Implementation: new `lib/ops_fs.c` — one small function per op, all routed through
`xrdc_roundtrip` (redirect-aware), with `fs_simple` (expect kXR_ok) and `fs_text`
(return the server's reply text) helpers. `apps/xrdfs.c` was rewritten around a
table-driven dispatch (`COMMANDS[]`) shared by one-shot and an interactive REPL
(getline-based; `cd`/`pwd`/`help`/`exit`, prompt `[host:port] cwd >`), with a
`build_path()` that resolves relative paths against the CWD and collapses `.`/`..`.
cat/tail reuse open-read + read. fattr left as a follow-up (TLV-heavy; not required by
the harness). No new module changes; build stays warning-free; client links no libXrd.

Validation (native suite, 55/55 serial): every subcommand round-trips against the
writable data dir under an autocleaned `_fstest_` directory — mkdir/-p, stat, rmdir,
mv, chmod (verified on disk), truncate (size shrinks), cat (byte-exact), tail -c,
locate (S-token), query checksum (== zlib.adler32 of the bytes), query config, statvfs,
and the REPL over piped stdin. Security-neg: rmdir-nonempty, rm-missing, and an
mv whose destination escapes the export root are all refused with no out-of-root write.

## M10 — conformance gate

`tests/test_native_client_conformance.py` runs the SAME operation through the
native binaries (TEST_XRDCP_BIN/TEST_XRDFS_BIN) and the system tools
(/usr/bin/xrdcp, /usr/bin/xrdfs), against both the nginx anon endpoint (direct)
and the CMS redirector (:11160 → :11162), asserting identical observable
behaviour: success/failure exit-code class, parsed stat Size, query-checksum hex,
the ls directory-entry SET, and md5 for copies — including cross-tool
(native-upload→system-download and the reverse) and cross-tool namespace interop
(native mkdir/rmdir seen correctly by the system xrdfs). 11/11 pass; redirector
cases auto-skip if :11160 is down. This is the gating drop-in proof: the native
tools are indistinguishable from the reference for the user-visible contract while
linking none of libXrdCl/libXrdSec*.

## Phase-37 final state (M0–M10, M8 excepted)

Build: `make -C client` clean, zero warnings under -Wall -Wextra -Werror=format-security;
client links only libssl/libcrypto/libz/libc (no libXrd*); `make -C shared/xrdproto check`
green (libxrdproto ngx-free). Harness-testable surface complete: anon/token/GSI/GSI+TLS
data path, in-protocol TLS, kXR_sigver (dormant at sec_level 0), redirect/wait following,
client-mediated remote→remote copy, pgread/pgwrite + per-page CRC32c, --cksum, the full
xrdfs subcommand set + REPL, and a native-vs-system conformance gate. Out of scope (no
harness support): M8 server-side TPC, sss/krb5. Test totals: native suite 55, conformance
11, redirector E2E 8 — all green. No `src/` module code changed this pass (the one harness
edit was a `start-dedicated cluster-redir` target in manage_test_servers.sh). Build
hardening: client/Makefile now emits -MMD -MP auto-deps so header edits recompile correctly
(the earlier "connect :0" was a stale mixed-ABI object from incremental make).

## M8 — parallel streams + server-side TPC

Wire facts (verified against the module + black-box):

| Fact | Module source (truth) | Client consumer |
|---|---|---|
| `ClientBindRequest` = streamid[2] reqid[2] sessid[16] dlen[4] (24B); reply = kXR_ok + **1 byte pathid** (1-253) | src/protocol/wire_write_extended_requests.h:162, src/session/bind.c:130-138 | conn.c `xrdc_bind` |
| A secondary stream **skips kXR_login**: handshake+kXR_protocol then kXR_bind{primary sessid}; identity inherited from the SHM session registry | src/session/bind.c:78-122 | conn.c `xrdc_bringup_ex(want_login=0)` |
| **Caveat:** kXR_read carries no pathid (wire_core_requests.h ClientReadRequest), and the server never reads it to fan reads — so server-side stream parallelism is cosmetic. The gate only requires binds + byte-exactness. | — | streams.c (bind N-1, copy on primary) |
| TPC source-first rendezvous: open SRC read `?tpc.key=K&tpc.dst=root://dest//dpath` (registers K), then open DST write `?tpc.src=root://src//spath&tpc.key=K`; opaque keys tpc.{src,dst,key,org,token_mode} | src/read/open_request.c:108-258, src/tpc/parse.c:310-356 | copy.c `copy_tpc` |
| Two `kXR_sync` on the dest handle: 1st arms (`kXR_ok "tpc-arm"`), 2nd triggers the pull, reply **deferred** until done | src/write/sync.c:56-66, src/tpc/launch.c | ops_file.c `xrdc_file_sync` (+ bumped timeout) |
| Server splits the open payload at `?` into path + opaque | src/read/open_overview.c open_extract_opaque | ops_file.c `xrdc_file_open_opaque` |

Implementation: `conn.c` split into `xrdc_bringup_ex(want_login)` + `xrdc_bind`;
new `lib/streams.c` (a best-effort N-1 bind set, torn down without endsess);
`ops_file.c` gained `xrdc_file_open_opaque` + `xrdc_file_sync`; `copy.c` gained
`copy_tpc` (source-first, two-sync, deferred) routed by `--tpc only|first|delegate`
(first → fall back to the existing client-mediated `copy_remote_to_remote`); xrdcp
got `-S/--streams N` and `--tpc`.

Validation: `xrdcp --streams 4` up+down byte-exact with BIND access-log entries
(test_xrdcp_client_options.py + native test_m8_streams_roundtrip_byte_exact);
`--tpc only` nginx↔nginx byte-exact (test_root_tpc.py 4/4 nginx cases + native
test_m8_tpc_only_nginx_to_nginx); `--tpc first` to a reference xrootd falls back to
client-mediated copy and completes.

**Scope boundary (documented):** the reference xrootd uses the async TPC model —
the TPC open returns `kXR_waitresp`(4006) and completes via a later `kXR_attn`
asynresp — whereas the nginx module uses the simpler open→sync(arm)→sync(trigger)
model the native client implements. So native `--tpc` drives **nginx-xrootd**
endpoints (the clean-room target) in both directions; real-XrdCl async-TPC interop
(test_root_tpc.py's 2 `--tpc only` *reference-xrootd* cases) is a distinct protocol
left out of this pass. `--tpc first` degrades gracefully to a client-mediated copy
against such peers.

## §14 — public libxrdc, Tier-1 tools, xrdgsiproxy

- **libxrdc** (`client/Makefile`): the client lib is now `libxrdc.a` + a versioned
  `libxrdc.so.0.1.0` (soname `libxrdc.so.0`, folding in the ngx-free libxrdproto via
  `--whole-archive`) + `libxrdc.pc` + an `install` target (header + self-contained
  protocol headers under `include/xrdc/`). `lib/xrdc.h` self-contains the two wire
  sizes it exposes (XRDC_FHANDLE_LEN/XRDC_SESSION_ID_LEN). A sample consumer
  (`examples/xrdc_stat_demo.c`) compiles against the INSTALLED lib via pkg-config and
  runs (shared + static), linking no libXrd* (test_libxrdc.py).
- **Tier-1 tools** (`client/apps/*.c`, thin front-ends; shared `xrdc_endpoint_parse`
  promoted to lib/url.c): `xrdcrc32c`/`xrdadler32` (local via xrdc_cksum_fd, remote
  via kXR_Qcksum), `xrdqstats` (kXR_query QStats/Qconfig/Qspace), `wait41`
  (connect-poll readiness), `xrdprep` (kXR_prepare; `xrdc_prepare` extended with
  optionX/prty — also fixed xrdfs `prepare -e` to mean evict). 13 tests.
- **xrdgsiproxy** (new `lib/proxy.c`, the one new crypto surface — pure OpenSSL
  X509): create an RFC-3820 proxy (proxyCertInfo OID 1.3.6.1.5.5.7.1.14,
  id-ppl-inheritAll, subject userDN+CN=<serial>, KeyUsage critical digitalSignature,
  SHA-256, chain proxycert+usercert+proxykey at 0400) mirroring utils/make_proxy.py;
  plus info/destroy. Clean-room provenance = RFC 3820 + OpenSSL public API. The
  proxyCertInfo DER is byte-identical to the reference proxy (test) and a proxy our
  tool builds authenticates GSI against the module at :11095 (cleartext) and :11096
  (TLS). 7 tests.

## §15 — client diagnostics

- New `lib/trace.c`: `xrdc_reqid_name`/`xrdc_status_name` (switch tables over
  opcodes.h), `xrdc_trace_frame` (one decoded line/frame, +hexdump at N≥2),
  `xrdc_timing_report`, `xrdc_mono_ns`. A zero-initialised `xrdc_diag` on `xrdc_conn`
  (off unless armed) carries the flags + per-opcode RTT table; set from opts in
  `xrdc_bringup` so it survives a redirect reconnect.
- `--wire-trace[=N]` (frame.c send/recv chokepoints + 2 conn.c handshake lines; →
  stderr so stdout stays clean), `--timing` (CLOCK_MONOTONIC brackets, per-opcode
  summary at xrdc_close), and `xrdfs explain <url>` (decode server_flags vs flags.h,
  sec_level, the &P= list + chosen auth + why others skipped via `xrdc_auth_explain`,
  TLS version/cipher via `xrdc_tls_info` + a gotoTLS-downgrade warning, sessid hex).
  6 tests; off-by-default verified.

## Phase-37 final state (M0–M10 + §14 + §15)

All numbered milestones M0–M10 are now complete (M8 done for nginx-xrootd endpoints).
Build: `make -C client` clean, zero warnings; `make -C shared/xrdproto check` green;
all 9 binaries (xrdfs xrdcp xrdcrc32c xrdadler32 xrdqstats wait41 xrdprep xrdgsiproxy
+ the libxrdc.{a,so}) link only libssl/libcrypto/libz/libc — no libXrd*. No `src/`
module changes this pass (one prior harness edit: `start-dedicated cluster-redir`).
Tests: 107 across the native-client suites (native 61, tools 13, xrdgsiproxy 7,
libxrdc 4, diagnostics 6, conformance 11, redirector 8) + the streams gate; root-TPC
4/6 (2 ref-xrootd async-TPC interop cases out of scope). Out of scope remaining:
sss/krb5 (no harness keytab/ccache) and real-XrdCl async TPC.

## Minimization pass 2 — shared checksum_core + open dedup (2026-06-14)

Following the "keep the client minimal / import from the module" directive: the
last compute the client duplicated from the module — the fd→checksum streaming —
was extracted to a pure `src/core/compat/checksum_core.{c,h}` and built-in-place into
BOTH the module (config NGX_ADDON_SRCS) and libxrdproto (shared/xrdproto Makefile
NAMES), exactly like crc32c/gsi_core. `xrootd_cksum_u32_fd`(adler32/crc32/crc32c)
and `xrootd_cksum_digest_fd`(md5/sha1/sha256) are ngx-free (kind codes match the
module's xrootd_checksum_alg_t ordinals). The module's `src/core/compat/checksum.c`
u32_fd/digest_fd now delegate to the core (keeping their ngx read-error logging via
errno); the client's `client/lib/checksum.c` does too — so client and server agree
on every checksum by construction, and the client reimplements none of it
(`grep adler32|EVP_DigestUpdate|crc32c_extend client/lib/checksum.c` = 0). Module
rebuilds clean under -Werror (objs/addon/compat/checksum_core.o linked); ngx-free
guard green (29 symbols); client checksum/cksum/tools tests pass against the live
server. Also collapsed ops_file.c's open_read/open_write into thin wrappers over
the existing xrdc_file_open_opaque (one open path). Client 5930→5853 LoC.

The audit confirms the client now single-sources every shareable algorithmic
kernel from the module via libxrdproto: crc32c, hex, crypto (SHA/HMAC),
error_mapping, gsi_core, checksum_core. The rest is irreducibly originator-side
(sockets/poll, TLS-connect, framing, handshake/login/auth-drive, response parsing,
copy engines, X.509 proxy build, diagnostics) — the inverse of the module's
ngx-event-loop responder role, with no shareable module counterpart.

## xrddiag + xrootdfs/preload + sss (2026-06-14)

Everything-testable remainder of §14/§15 + §6. No `src/` module changes — all
client + tests; the SSS server already exists in the module.

**Foundations** — `client/lib/http.c` `xrdc_http_get` (cleartext HTTP/1.0 GET over
`xrdc_tcp_connect`, read-to-EOF, close-delimited; the one HTTP touch, no
libcurl/TLS); `xrdc_kxr_to_errno` in status.c (kXR_*/XRDC_E* → -errno for the POSIX
layers); `xrdc_explain_conn` extracted from `xrdfs explain` into conn.c (shared
with `xrddiag check`).

**`xrddiag`** (apps/xrddiag.c) — check/bench/topology/status/compare, each a thin
compose of libxrdc. `check` probes auth-as-advertised, no-TLS-downgrade,
path-confinement (escape must be refused), dirlist dstat==stat, checksum-works
(query vs local), pgread CRC self-validation. Observability fact: the test fleet's
`/metrics` is cleartext on 9100 (reachable by `xrdc_http_get`); the dashboard
`/xrootd/` is TLS+password on 8443 — so `status` pulls /metrics; cluster/dashboard
JSON are optional `--cluster-url` with a graceful note. tests/test_xrddiag.py (10).

**`xrootdfs`** (apps/xrootdfs.c, libfuse3, fuse3-gated in the Makefile) — single
global `xrdc_conn` under a mutex, forced single-threaded (`-s`); `fuse_operations`
map onto libxrdc (getattr/readdir/open/create/read/write/release/fsync/mkdir/
unlink/rmdir/rename/chmod/truncate), errors via `xrdc_kxr_to_errno`. Validated:
ls/stat/cat/cp/mkdir/rm + write→readback→on-disk md5 all byte-exact.

**`libxrdposix_preload.so`** (preload/xrdposix_preload.c, LD_PRELOAD) — read-path
shim: `$XROOTD_VMP=/prefix=root://host:port/`; paths under the prefix route to a
shadow fd table (fds ≥ 0x40000000); everything else → dlsym(RTLD_NEXT) libc. Real
findings driving the symbol set: `cat` uses `open` (works); coreutils `md5sum` uses
stdio `fopen` (calls the openat **syscall inside libc**, bypassing the interposed
symbol — the documented fopen follow-up); `ls`/`stat` use **statx** and the LFS
**\*64** stat variants. So we interpose open/openat(+64), read/pread(+64),
lseek(+64), close, stat/lstat/fstat/fstatat(+64), **statx**, access. The
`REAL(name)` helper resolves each real symbol via `__typeof__(name) *` +
dlsym(RTLD_NEXT) so wrappers inherit libc's exact prototype. opendir/readdir is a
documented follow-up (opaque DIR* + readdir64/dirfd/fstatat interplay can't be
interposed safely). tests/test_xrootdfs.py (9; FUSE tests skip without /dev/fuse).

**SSS** (§6 + §14.3) — clean-room from `src/auth/sss/`:
- keytab = TEXT, line `0 N:<id> k:<hexkey> u:<user> g:<group> n:<name> [e:<exp>]`,
  mode **0600** (`(mode & (S_IRWXG|S_IRWXO))` must be 0), `O_NOFOLLOW`; first field
  "0"/"1"; required N:+k:. (config.c).
- kXR_auth blob = 16B header (magic `"sss\0"`, ver 1, spare 0, kn_size 0, enc
  `'0'`=BF32, **key-id 8-byte BE**) + BF32( 40B data-hdr [32 random ‖ gen_time be32
  = now−1222183880 ‖ 3 reserved ‖ opt 0x00 USEDATA] ‖ NAME TLV [0x01, 0, len,
  user+NUL; len incl NUL] ‖ **IEEE-CRC32 be32** ). cipher_len == plain_len
  (CFB64, no padding). (auth_proxy_credential.c).
- **CRC is IEEE (poly 0xedb88320, init/xorout 0xffffffff), NOT crc32c.** BF-CFB64 =
  EVP_bf_cfb64, padding OFF, `EVP_CIPHER_CTX_set_key_length`(variable ~32B), IV = 8
  zero bytes, OpenSSL-3 needs `OSSL_PROVIDER_load(NULL,"legacy")`.
  (auth_crypto_helpers.c).
- The module's crypto is ngx-coupled, so the tiny CRC32+BF32 are reimplemented in
  `client/lib/sss_keytab.c` (per plan; no `src/` change). `sec_sss.c` builds the
  blob byte-for-byte like the server encoder; registered in auth.c order
  gsi>ztn>**sss**>unix. `xrdsssadmin` add/list/del/install (RAND_bytes key, id=max+1,
  0600, self-validate by re-read).
- Gate: tests/test_native_sss.py (6) — a SELF-CONTAINED nginx (`xrootd_auth sss`)
  on a free port + temp keytab (no fleet/manage_test_servers.sh edits, matching
  test_dashboard_config_anon.py), `xrdfs --auth sss` stat/ls/explain + xrdcp md5
  pass; negatives: no keytab + wrong-key (same id, different key → server CRC
  reject). This e2e IS the byte-exact validation (the server's xrootd_sss_verify_blob
  is ngx-coupled, so no offline ngx cross-check).

Env note: a concurrent module rebuild during this pass briefly left objs/nginx with
0 xrootd symbols (mid-link) and took the shared fleet down; xrddiag/xrootdfs tests
now skip cleanly when :11094 is down (matching the xrootdfs pattern) rather than
hard-fail. All three suites verified green when the fleet was up; SSS is fleet-
independent. New binaries/.so: `ldd` shows no libXrd*. Client build clean -Wall
-Wextra; ngx-free guard green.

## probe-robustness + krb5 + xrdmapc + credinfo + capture/replay + netdiag + mpxstats (2026-06-14)

The final testable §14/§15 remainder. No `src/` module changes (all client + tests);
clean-room verified. Order = value×testability, ABI-growth workstreams last.

**WS-A — `xrddiag probe-robustness <url>`** (§15.8): app-side raw-frame auditor in
apps/xrddiag.c (libxrdc stays a *validating* client). Probes path-escape (refused +
conn survives), unknown opcode, oversized dlen (1 GiB claim, no body), OOB read on a
bogus fhandle, truncated/slowloris header; final "server-survives" reconnect. Built
on `xrdc_send`/`xrdc_write_full` + `xrdc_recv(.,0xffff,.)`. **Safety gate (real
control):** resolve host ONCE, classify the resolved sockaddr (127/8 + ::1), connect
the probe to that SAME numeric IP — defeats DNS-rebind/localhost.attacker.com;
non-loopback refused without `--i-am-authorized`. test_xrddiag_probe.py (5).

**WS-B — krb5 client (`sec_krb5.c`, `#ifdef XROOTD_HAVE_KRB5`)**: payload = 4 bytes
`"krb5"` + raw AP-REQ (from src/auth/krb5/auth.c: `cur_dlen>4` + `ngx_strncmp(payload,
"krb5",4)` then `krb5_rd_req` on bytes past offset 4). `first()`: krb5_cc_default →
krb5_get_credentials for the service principal (from the advertised `&P=krb5,<princ>`
parms, else xrootd/<host>) → krb5_mk_req_extended. Registered auth.c gsi>ztn>**krb5**>
sss>unix (arrays [4]→[5]); Makefile pkg-config krb5 gate (mirrors fuse3). **ENV: the
MIT KDC server tools (kdb5_util/kadmin.local/krb5kdc) are NOT installed — only
kinit/kdestroy** — so the e2e gate (test_native_krb5.py, self-contained nginx +
kdc_helpers.up()) skips cleanly; a standalone check (links libkrb5, no libXrd, --auth
help) passes. Needs `sudo dnf install krb5-server` to run the 6 e2e cases.

**WS-C — `xrdmapc`** (§14.5/§15.4): standalone apps/xrdmapc.c over the public API
only. `xrdc_locate` → parse `S<r|w><host>:<port>` holders (registry.c format,
IPv6-bracket-aware) + `xrdc_query(kXR_Qspace)` free/total. **`--verify`** = the single
home for the ghost-replica detector: per holder fresh connect+stat → PASS / GHOST
(advertised, NotFound) / UNREACHABLE; only probes the advertised set. test_xrdmapc.py
(4 + cluster-skip).

**WS-D — credential introspection (`credinfo.c`) + `xrdgsitest`** (§15.2/§14.3):
`xrdc_token_explain` (base64url-decode JWT payload, scalar-scan iss/sub/aud/scope/exp
+ EXPIRED, no sig-verify, no jansson), `xrdc_gsi_cert_explain` (reuse proxy.c X509 +
VOMS AC OID 1.3.6.1.4.1.8005.100.100.5 scan + notBefore skew), wired into
`xrdc_explain_conn` as an always-shown "Credentials (in environment)" block. De-static
`discover_token` → `xrdc_token_discover` (shared, no dup). `xrdgsitest` = force gsi +
connect + explain. Token-claim tests run against a SELF-CONTAINED anon server (no
fleet); GSI e2e PROXY_STD-gated. (added to test_native_client_diagnostics.py).

**WS-E — capture/replay (`capture.c`, §15.1)** — grows `xrdc_diag` (`+cap`) + `xrdc_opts`
(`+capture`): `.xrdcap` = magic `XRDCAP1\n` + records `'M' meta(klen,key,vlen,val)` /
`'F' frame(dir,isreq,sid:2BE,code:2BE,wirelen:4BE, wirebytes)` where wirebytes = the
exact header+body (so playback can re-issue verbatim). Hooks beside the wire-trace
hooks in frame.c (full request hdr+payload / response hdr+body); opened ONCE in
`xrdc_connect` (survives reconnect), caps-meta after bringup, closed idempotently in
`xrdc_close`. `--capture` on xrdcp/xrdfs; `xrddiag replay <f>` offline-decodes (reuses
trace.c name decoders), `--playback <url>` re-issues only real request ops (skips
protocol/login/auth/bind/endsess/sigver). test_xrddiag_capture.py (4).

**WS-F — `xrddiag bench` netdiag (`netdiag.c`, §15.3)** — grows `xrdc_diag`
(`+phase_ns[4]`, stamped in bringup: start/tcp/tls/login-auth): prints the connect-
phase breakdown, the connected address family (getpeername — happy-eyeballs winner),
IPv6 flow label (getsockname sin6_flowinfo — SciTags/phase-34), and TCP_INFO
(rtt/rttvar/retrans via getsockopt). **PII-free by construction** (families/µs/counts
only, no IP/path/cred); test asserts presence/format + non-negative rtt + a PII grep,
never numeric thresholds (WSL2). Both WS-E/WS-F land with one `make clean` rebuild.
(added to test_xrddiag.py).

**WS-G — `mpxstats`** (§14.5): parse-only apps/mpxstats.c — `xrdc_http_get` /metrics
(or stdin blob), fold Prometheus samples by base metric name → series count + sum.
No protocol core. test_native_tools.py (+2, self-contained stdin). **`xrdcrc64`** was
implemented concurrently by the maintainer (crc64.c/crc64.h + checksum_core u64;
CRC-64/XZ + CRC-64/NVME) — left untouched. **xrdreplay declined** (true duplicate of
`--playback`).

All 28 new self-contained tests pass; clean build (`-Wall -Wextra`, zero warnings),
every new binary/.so `ldd`-free of libXrd*, ngx-free guard green (33 symbols). The
shared fleet churned down mid-pass (maintainer's concurrent xrootdfs-pool + crc64
work) so fleet-dependent pre-existing tests fail on connect — env, not these changes;
every new test self-hosts its nginx or skips cleanly.

## cross-protocol oracle + doctor/diag enrichments — roadmap tail (2026-06-15)

The final HIGH/feasible §15 testable items (user "everything testable"). App + tests
only, no `src/` changes; clean-room. After this, leftovers are deferred (S3 SigV4 +
HTTPS-WebDAV cross-protocol — new subsystems; VO-ACL doctor — 2nd-credential harness)
or out-of-scope/env-blocked (real-XrdCl async TPC, krb5-server e2e; §14.1 public API is
functionally complete).

**http.c binary-safe** (prereq): `xrdc_http_get` now memcpy's the body (was `snprintf
"%s"` → truncated binary at the first NUL) and takes `size_t *outlen` (NULL-ok). The 3
text callers (status/topology/mpxstats) pass NULL; the davs oracle uses the length to
checksum exact bytes.

**WS-H — `xrddiag compare --davs <host[:port]>` (§15.6 cross-protocol oracle)**: read
the same object via root:// and cleartext WebDAV GET (`xrdc_http_get`, binary-safe) and
assert HTTP-200 + size + MD5 match — the capability no upstream client has (the fleet's
HTTP_WEBDAV_PORT serves the same DATA_DIR as root://). S3(SigV4)/HTTPS-davs(TLS+chunked)
print a one-line deferred note. test_xrddiag_compare_davs.py (3: match/mismatch/404; two
WebDAV roots — same dir = match, different dir = md5 FAIL, missing = 404).

**WS-I — `xrddiag check` doctor expansion (§15.5)**: (8) POSC-atomicity — open a 2nd
conn, `xrdc_file_open_write(posc=1)` + partial write, ABANDON (raw close the fd, no
kXR_close), then stat on the main conn → must be NotFound (server discards a
non-finalized POSC upload); (9) handle-limits — open files in a loop until the server
caps (16) with a graceful kXR_error, then a fresh stat proves the conn survived; (10)
cred-validity — surface env token/proxy expiry via credinfo (EXPIRED flagged). Tests in
test_xrddiag.py (writable self-contained server).

**WS-J — `--redirect-trace` per-hop trace (§15.4)**: grows `xrdc_opts.redir_trace` +
`xrdc_diag` mirror (armed in conn.c bringup like wire_trace); `frame.c xrdc_roundtrip`
emits `redirect[N] -> host:port` per hop + LOOP/budget-exhausted lines on stderr (inert
when off). `--redirect-trace` on xrdfs/xrdcp/xrddiag (rides any op, no new subcommand).
One `make clean` rebuild (struct growth). test: no-op (single server) runnable; the
real hop assertion is cluster-gated (skips when :11160 down).

**WS-K — `xrddiag bench --sweep` (§15.3)**: loop read sizes [64K,256K,1M,4M,16M] via
`xrdc_file_read` into a discard buffer, print a `size  MB/s` table to expose the
throughput knee. Test asserts ≥3 ascending-size rows + a MB/s column — structure only,
never throughput numbers (WSL2 untrustworthy).

14 new self-contained tests pass; clean build (-Wall -Wextra, zero warnings); every
binary/.so ldd-free of libXrd*; ngx-free guard green (33 syms). Fleet-gated pre-existing
tests skip when the shared fleet is down (maintainer co-developing — xrootdfs
connection-pool + crc64, both landed). **Phase-37 native-client roadmap is now complete
to the limit of this environment.**

**§15.8 — `xrddiag remote-doctor <url> [url2 …]` (network transfer-problem
diagnostician)**: a single command that interrogates one endpoint, or every hop of a
transfer path (client→redirector→DS, or a TPC src+dst pair), and root-causes a slow or
failing transfer. Pure composition of the public libxrdc surface — **no new wire, no
libcurl, no direct OpenSSL**. Per endpoint (`doctor_one`): one `xrdc_connect` reused for
everything; connect-phase / family / TCP_INFO (rtt/retrans) / flow-label via the new
`xrdc_netdiag_facts(const xrdc_conn*, xrdc_netfacts*)` accessor (factored out of
`xrdc_netdiag_report`, which now prints *through* it); TLS posture via `xrdc_tls_info` +
`kXR_gotoTLS`; chosen auth via `c.diag.chosen_auth`; a TTFB+MB/s throughput probe
(`xrdc_file_open_read`/`read`/`close` + `xrdc_mono_ns`, target chosen by `resolve_target`);
holder count via `xrdc_locate`; server load via `xrdc_http_get` /metrics (kXR_wait/budget
shed detect; `--metrics-port 0` skips). Each endpoint is scored GREEN/YELLOW/RED with an
`issues[]`. The cross-endpoint diff engine (`doctor_cross`) walks the path and fires
TLS-downgrade, auth-fallback, and v4/v6-asymmetry detectors per hop; client-side
credential validity (`xrdc_token_discover`/`xrdc_token_explain`/`xrdc_gsi_cert_explain`)
is surfaced once (the same creds reach every hop). `--json` emits a single-line
`{remote_doctor:{endpoints:[…],cross_endpoint_analysis:{hops}}}` (sprintf, no jansson).
**Every probe is bounded by `--probe-timeout` (`c.io.timeout_ms`)** so a wedged/unreachable
hop can never hang the tool; a dead hop is RED and the process exits nonzero. **PII-free**:
facts/JSON carry families / microseconds / counts / hex caps only — never a resolved IP,
path, or credential (the cwnd/low-throughput detector is gated on ≥4 MiB actually moved so
a tiny file never false-positives).

Structural edges: `main()`'s positional collector widened `pos[2]`→`pos[8]` (the transfer
path is N URLs; `compare`'s two-positional form preserved); new `--json` / `--dashboard-port`
opts. A genuine client URL-parser gap was fixed in `client/lib/url.c` (`parse_authority`):
bracketed IPv6 literals (`root://[::1]:port//path`) were passed to `getaddrinfo` with the
`[ ]` still attached → "Name or service not known"; now stripped (host between brackets,
optional `:port` after `]`). This is client-only code, benefits every native tool, and is
what makes the v4/v6-asymmetry detector demonstrable. `xrdc_netfacts` is a standalone
out-struct (no growth of `xrdc_conn`/`xrdc_diag`) → no mixed-ABI rebuild hazard.

tests/test_xrddiag_remote_doctor.py (7, all self-hosting anon nginx on free ports;
v4+v6 ::1 bound so the asymmetry detector runs): single-endpoint green + populated facts,
single + multi-endpoint `--json` parse, v4-vs-v6 asymmetry fires, reachable+unreachable →
dead hop RED + bounded (no hang) + exit nonzero, unparseable URL clean, and PII-free
(no path/token/cert leak in facts or JSON). Clean build (-Wall -Wextra, zero warnings);
xrddiag still ldd-free of libXrd*; the 35 pre-existing native-client tests stay green.
(One real bug caught in self-review: `doctor_emit_json` closed the cross + remote_doctor
objects but not the outer wrapper — `}}` vs `}}}` — invisible to eyeballing, caught only
by `json.loads` in the test.)

**remote-doctor → ACTIVE differential diagnosis (2026-06-15)**: expanded remote-doctor from a
fact-gatherer into an engine that *actively exercises a remote server's subsystems, observes
the exact (probe, kXR/errno) symptom, classifies it to a root cause, and prints a remediation*.
Still pure libxrdc composition (no new wire). Design = a table-driven differential: a static
`dx_rule[]` maps `(probe, kXR-code)` → `{verdict, cause, remedy}` (keyed on BOTH because the
same code means different things per subsystem — kXR_NotAuthorized on read = ACL, on write =
read-only/scope); `dx_record_status` scans it with a graceful generic fallback so we only assert
guidance we're sure of. Read-only probes ALWAYS run (auth posture, namespace stat+dirlist,
read open+1-block, adler32 checksum-vs-recompute, locate holder-count, /metrics load); the
reachability errno→cause classification fires on connect failure. `--allow-write` adds a gated
write probe (mkdir temp → write → read-back-verify → rm/rmdir, classifies kXR_fsReadOnly /
kXR_NotAuthorized-scope / overQuota / NoSpace) and, if a file is offline, a stage (kXR_prepare)
probe. Mutating probes require `--allow-write` AND (loopback-literal host OR `--i-am-authorized`).
Findings render as a human `diagnosis:` block (verdict + cause + → remedy) and a JSON `diagnosis[]`
array (new `fjson_str` escaper — issues/causes are wire-influenced). All kXR codes verified real
in `src/protocol/opcodes.h`; the server's write-gate genuinely returns kXR_fsReadOnly
(handshake/ + query/prepare.c). Also fixed a real client gap surfaced en route: nothing — the
IPv6 url.c fix was the prior pass.

Built with a 4-agent **understand** workflow (probe/failure-mode/pattern/errno-map) then a
5-dimension **adversarial review** workflow (classification-vs-server / write-safety / PII /
C-correctness / standards) with per-finding skeptic verification — 21 confirmed findings, of
which the genuine ones were fixed: **PII** — `st->msg` (server wire text, may carry a path) was
embedded in the generic-fallback cause and the connect-fail issue → both now use the PII-free
classification only; **safety** — the loopback gate's `strncmp("127.",4)` matched
`127.attacker.com` → exact-literal match only; **JSON** — `fjson_str` now escapes high bytes
(0x80-0xFF) so output is valid JSON on non-ASCII server text; **correctness** — the read probe
recorded DX_OK even when its `malloc` failed → switched to a stack buffer (no malloc path);
**write probe** — pid+`xrdc_mono_ns()` temp namespace (collision-proof), close-failure now
demotes the verdict (durability unconfirmed), and an un-removable residue is reported (no silent
leftover); **classification** — added a `locate`+kXR_NotFound rule; **polish** — `doctor_cross`
no longer prints a path-analysis header when <2 hops connected. (Rejected over-flagged findings:
getaddrinfo-based loopback resolve — more permissive than exact-match; doc-block retrofits on
pre-existing one-line helpers — file convention is mixed; checksum "silent on download fail" —
no false-OK, best-effort, read probe is authoritative.)

tests/test_xrddiag_remote_doctor.py grew to 13 (self-hosting rw/empty fixtures): read-only
probes present+green by default with no write probe; write path healthy + self-cleaning on a
writable export; **read-only export's write probe classifies the root cause + remedy → RED +
nonzero**; empty export → namespace WARN (counts non-dot entries, since the server keeps its own
`.`-lock in the root); dead hop → reachability finding with cause/remedy; diagnosis block PII-free.
Clean build (-Wall -Wextra, zero warnings), ldd no libXrd*; 32 pre-existing native-client tests
stay green.

**remote-doctor `--auth-suite` — AUTH/PERMISSIONS test-suite (2026-06-15)**: a *differential
authorization* suite that catches a server build whose authN/authZ is broken (accepts credentials
it must reject, or grants access it must deny — the real-world "broken release" incident class). It
drives the same operations under different credential states and asserts the server's allow/deny
decisions; a denied-expected op that *succeeds*, or a bad credential that is *accepted*, is the
smoking gun (DX_FAIL/CRITICAL). Probes (all PII-free, verdict + kXR code only):
- **authz-anon** — opens a `force_anon` session (login, NO credential) and, on an auth-required
  server, asserts unauthenticated stat/read is DENIED → catches **auth bypass / silent-anon
  fallback**. Self-contained: it learns the advertised `&P=` from its own session, so it runs even
  when the operator holds no valid credential and the *primary* connection failed.
- **authz-forgesig / authz-algnone** — present a garbage-signature token and an `alg:none` token;
  a correct server rejects them at `kXR_auth` → catches **broken signature verification** (the
  headline regression). The forged token carries no `kid` so the server reaches signature
  verification (a wrong `kid` would short-circuit at key selection).
- **authz-expired** — the operator's real but expired token must be rejected → **expiry enforced**.
- **authz-scope** (gated `--allow-write` + loopback/`--i-am-authorized`) — a read-only token's
  `mkdir` (a write op) must be DENIED → catches **scope-not-enforced / privilege escalation**;
  decided on the exact code (`kXR_NotAuthorized`=enforced, `kXR_fsReadOnly`=read-only-export so
  inconclusive→WARN, success→FAIL).

Mechanism (verified vs the server oracle in src/auth/token, src/handshake/policy.c): credentials are
read at connect time, so injection is `setenv(BEARER_TOKEN)`/restore around scoped connects; one
small client-only lib addition, `xrdc_opts.force_anon` (honored by an early `return 0` in
`client/lib/auth.c` — log in, present nothing), plus a reusable `xrdc_token_meta_get` factored out
of credinfo (exp/expired/read/write-scope) so the suite predicts the server's correct decision.
JWTs synthesized in-client via a small base64url encoder (no signing). Built with an understand
workflow (server enforcement oracle + broken-auth taxonomy + client feasibility) then a
5-dimension adversarial review (false-negative-focused; for a security suite a probe reporting
"OK" on a broken server is the cardinal sin). Review fixes applied: (1) the **false-negative** where
a forged/expired probe reported "rejected" on any connect failure — now requires an *auth*
rejection (`kXR_NotAuthorized`/`AuthFailed`/`XRDC_EAUTH`), else WARN; (2) **authz-scope** could
report "scope enforced" on a read-only export or via a discarded-mkdir-status — rewritten to test
`mkdir` directly and key the verdict on the exact denial code; (3) `setenv(NULL)` UB when
`strdup` fails (`had = (saved != NULL)`); (4) dropped the forged token's `kid` to reach signature
verification on multi-key servers; (5) broadened `has_write` scope detection (under-detection
would run the scope test on a write-capable token → false FAIL); (6) bounds-checked the base64url
encoder. tests/test_xrddiag_remote_doctor.py +7 (self-hosting an SSS server via xrdsssadmin for the
anon case, and a token server via utils.make_token RSA JWKS for forged/expired/scope) — 20 total,
all green; the connect-failure path now distinguishes auth-failure from transport by error code.
Clean build zero-warn, ldd no libXrd*; ngx-free guard green; native-client regression green
(4 unrelated failures are a shared-fleet data dependency: the fleet export lacks /test.txt).

**remote-doctor MULTI-PROTOCOL deep-dive (2026-06-15)**: remote-doctor now checks every
stage of a transfer across ALL five protocols the module serves, routed by URL scheme
(doctor_dispatch): root[s]:// (full libxrdc battery, unchanged), http:// / https:// / davs://
(WebDAV) / s3:// / cms://. Keystone = a clean-room TLS-capable HTTP/1.1 client (no libcurl):
lib/tls.c gained `xrdc_tls_client` (standalone TLS handshake on a connected socket, factored
from xrdc_tls_upgrade) + `xrdc_tls_read_some` (stream read up-to-n — xrdc_tls_read fills
EXACTLY n for root:// framing and returns -1 on clean close, wrong for HTTP read-to-EOF, the
bug that first broke https); lib/http.c gained `xrdc_http_req` (cleartext|TLS, any method +
headers + body, reads to EOF on Connection:close, de-chunks Transfer-Encoding:chunked) +
`xrdc_http_resp`/`xrdc_http_header`/`xrdc_http_resp_free`. Batteries in apps/xrddiag.c:
doctor_http (http/https/davs — TCP, TLS cert/cipher, HTTP status class, Accept-Ranges, RFC-3230
Digest checksum, Content-Length; davs adds OPTIONS→DAV class + PROPFIND 207 listing + COPY/TPC
capability); doctor_s3 (anon-auth posture 403/404/200 + clean-room SigV4 signer from libxrdproto
HMAC-SHA256/SHA-256 + SigV4-signed GET acceptance); doctor_cms (manager connect → xrdc_locate →
redirect-to-data-server resolution, reusing the libxrdc locate+reconnect). New `dx_url_parse`
(scheme→proto+tls+host:port+path, IPv6 brackets), `proto` field on doctor_ep + report/JSON,
`--no-verify-tls` for self-signed test endpoints. Verified live against self-hosted root +
WebDAV(http+https) + S3 servers and the live fleet cms redirector: SigV4 signature ACCEPTED by
the real S3 server, davs class-2+PROPFIND, https TLSv1.3 cert verify (self-signed correctly
REJECTED without --no-verify-tls → RED). 11 tests tests/test_xrddiag_multiproto.py (self-host
via http{} location blocks + openssl self-signed cert; cms fleet-gated). NO goto (httpx split
into httpx_exchange/httpx_parse so cleanup stays linear).

Adversarial review (5-dim, false-negative-focused; 11 confirmed) → fixes APPLIED: 8 MiB body
ceiling now ERRORS on truncation instead of silently truncating (one extra read distinguishes
EOF from more-data); SigV4 URI now percent-encoded (RFC-3986 unreserved+'/'), so keys with
spaces/specials sign correctly against any S3 server; SigV4 secret-key length bounded (kdate no
silent truncation→wrong-sig); PII — the root battery's "unparseable URL" no longer echoes st.msg;
S3 SignatureDoesNotMatch read from the XML `<Code>` element (not a body-wide substring); Digest
header requires '=' (RFC-3230) to count as a checksum. REJECTED with reasons: the stale
src/core/compat/hex.c "uppercase" comment (out-of-scope src/, and the impl is correctly lowercase);
restoring blocking mode after the TLS handshake (would DEFEAT the TLS read timeout — the
non-blocking socket + wait_io poll IS the never-hang mechanism); dynamic SignedHeaders + header
trimming (the 3 fixed headers never carry extraneous space); the header-line-boundary "fix" (the
scanner already advances strictly line-by-line). Clean build zero-warn, ldd no libXrd*; 30
remote-doctor/multiproto tests + native-client regression green.

**Client protocol-coverage audit (2026-06-15)**: full root://-family parity (transport TCP/v4/v6/
TLS, all opcodes, pgrw, bind streams, native TPC, sigver, all 5 auth methods, FUSE, preload);
HTTP/HTTPS/WebDAV/S3/CMS are DIAGNOSTIC-grade only (remote-doctor probes, not production transfer
clients — xrdcp moves data over root:// only); genuine gaps = kXR_readv/writev (server-side,
client never issues them), async-TPC (waitresp/asynresp), FRM Tape-REST recall, SRR; correctly
absent = cmsd server↔server protocol, SciTags UDP, mirroring (server-internal, not client-spoken).

**Client gap-closures (§16, 2026-06-15)** — five of the audited gaps closed + tested:
- **kXR_readv / kXR_writev** (lib/ops_file.c): `xrdc_file_readv` builds the readahead_list
  payload (fhandle[4]+rlen[4 BE]+offset[8 BE]), accumulates kXR_oksofar frames, demuxes the
  per-segment [16B hdr][data] reply into each caller buf (bounds-checked, clamped to seg.len,
  256 MiB cap); `xrdc_file_writev` sends the descriptor block + concatenated data (server
  recovers N from n*16+sum(wlen)==dlen) with kXR_wv_doSync. Exposed as `xrdfs readv <path>
  <off len>...` and `xrdfs writev <path> <off hexdata>...`. Verified: readv returns the exact
  requested segments (ABCDE+KLMNOP), writev byte-exact (aa\0\0ZZ at offsets 0/4).
- **recursive copy** (lib/copy.c + xrdcp -r): `copy_tree_download`/`copy_tree_upload` hold one
  connection per tree, walk via xrdc_dirlist (remote) / opendir (local), mkdir the dest tree,
  copy each file (copy_one_r2l/l2r); skips `.`/`..`. Verified: a 3-file/2-level tree
  round-trips (upload→download) md5-exact.
- **SRR** (xrddiag srr): GET the WLCG storage-resource-reporting doc over the HTTP client +
  scalar-JSON summarize (implementation, share count, total/used capacity). Verified live.
- **FRM Tape-REST** (xrddiag tape): POST /api/v1/stage {"files":[{"path"}]} then poll
  GET /api/v1/stage/{id}, report request-id + state + onDisk — over the HTTP client.
JSON parsed with new scalar scanners (js_str/js_sum/js_count, no jansson). NO goto; clean
build zero-warn; ldd no libXrd*; 5 new tests (tests/test_client_gaps.py) + 51 regression green.
REMAINING (largest two, not closed this pass): (1) **davs:// / s3:// production transfer** in
xrdcp — needs a STREAMING HTTP GET/PUT (the diagnostic xrdc_http_req is 8 MiB-capped + errors
on truncation) + SigV4 lifted into the lib; (2) **async-TPC** (kXR_waitresp→kXR_attn/asynresp)
— native SHM TPC already works root→root; the async variant is interop with a server that
defers, which our server does not do, so it cannot be validated in-tree without a ref-XRootD
async peer. Both are clean, scoped next steps.

**Both remaining gaps CLOSED + tested (§16, 2026-06-15)** — the client is now production
(not diagnostic) over web schemes, and understands the deferred-reply flow:

- **davs:// / http(s):// / s3:// production transfer in `xrdcp`** (gap A). New streaming HTTP
  transfer in `lib/http.c` (`xrdc_http_download`/`xrdc_http_upload` — body never fully buffered;
  handles Content-Length, chunked, and connection-close framing via a unified `body_src`; a
  shared `httpx_connect` factored out of `xrdc_http_req`). AWS SigV4 lifted into a new
  `lib/s3.c` (`xrdc_s3_sign_v4` + `xrdc_s3_sha256_hex`); `xrddiag`'s private signer is now a thin
  wrapper over it (DRY). Web-URL parser in `lib/url.c` (`xrdc_is_web_url`/`xrdc_weburl_parse` for
  http/https/dav/davs/s3/s3s). `lib/copy.c` gains a `copy_web` dispatch ahead of the root://
  path: download = web→local/stdout, upload = local→web; auth = WebDAV `Authorization: Bearer`
  or S3 SigV4. Keys/token from new `xrdcp` flags (`-T/--token`, `--s3-access/--s3-secret/
  --s3-region`) or the env (`BEARER_TOKEN` / `AWS_*`). KEY FINDING: the server's SigV4 canonical
  request hard-codes `UNSIGNED-PAYLOAD` (auth_sigv4_verify.c) and signs the `Host` header
  verbatim incl. `:port` — so the client signs `UNSIGNED-PAYLOAD` for every method and `host:port`
  as the canonical host. `lib/s3.c` added to Makefile `LIB_SRCS`. Verified: WebDAV PUT/GET
  round-trip md5-exact (1 MiB+ file), GET→stdout, S3 SigV4 PUT/GET round-trip (flags AND `AWS_*`
  env), and a security-negative unsigned-PUT-rejected (403). tests/test_client_web_transfer.py.

- **async-TPC / deferred replies** (gap B). `lib/frame.c` now handles `kXR_waitresp` transparently
  in `xrdc_recv`: on a waitresp it waits for the unsolicited `kXR_attn(asynresp)` envelope
  (`actnum=kXR_asynresp[4] reserved[4] inner ServerResponseHdr[8] data[]`), extends the read
  window to the server's advertised delay (capped 10 min, restored on every return path),
  matches the inner streamid, and surfaces the inner status+data exactly as a synchronous reply.
  A re-armed waitresp simply keeps waiting. Every caller (open/stat/sync/rm/…) gets this for free.
  nginx-xrootd answers synchronously so this can't be hit against it — validated instead with a
  minimal mock deferring XRootD server (handshake+login then waitresp→asynresp) in
  tests/test_client_async_tpc.py: 3 tests (asynresp ok, embedded error surfaced, double-waitresp
  re-arm). NO goto; clean build zero-warn; ldd no libXrd*. Full client regression 66 pass + 2 skip.

ALL SEVEN audited client gaps are now closed. Correctly-absent (server-internal, never
client-spoken): cmsd S2S, SciTags firefly UDP, traffic mirroring/proxy. Next: the
"swiss-army-knife" expansion — additive feature clusters per persona (researcher / sysadmin /
student), keeping official-client flag/semantics for compatibility.

**Gap A/B hardening (adversarial review, 2026-06-15)** — 8 confirmed findings fixed in the new
wire/transfer code: (HIGH) heap over-read on a non-NUL-terminated inner error message in the
asynresp + synchronous kXR_error paths → bounded with %.*s (frame.c); (HIGH) unvalidated/negative
Content-Length → silent truncation → reject via strtoll endptr+errno+sign (http.c); (HIGH) web
download clobbering a pre-existing dest on failure → download-to-temp + atomic rename, refuse
overwrite without -f (copy.c); (HIGH) weburl path truncation → reject-on-overflow (url.c);
(MED) waitresp backoff signed-overflow → clamp-before-multiply (frame.c); (MED) xrddiag SigV4
host mismatch → sign host:port (xrddiag.c); (MED) web upload non-regular source → require
S_ISREG (copy.c); (LOW) S3 query string mis-signed → reject '?' (copy.c). The async-TPC error
test now sends a NON-terminated message as a regression guard for the over-read fix.

**Swiss-army-knife cluster 1 — xrdfs power tools (2026-06-15).** Recursive filesystem ergonomics
on a shared depth-first walker (walk_dir + xrdfs_visit callback, XRDFS_MAXDEPTH=64 bound):
`du [-h] <path>...` (recursive bytes + file/dir counts, human sizes), `tree [-d] [-L N] [path]`
(visual tree + summary), `find <path> [-name GLOB] [-type f|d] [-size +N|-N]` (predicate search;
-name via fnmatch, -size is GNU-find semantics = all types), and `ls -R` (sectioned recursive
listing). All additive; existing ls/stat/… unchanged. NO goto; clean build zero-warn. 7 tests
(tests/test_client_xrdfs_tools.py). Full client regression: 73 pass + 2 skip.
Next clusters (user opted into all four): 2=bulk/resumable transfers (xrdcp), 3=ops/monitoring
(xrddiag), 4=friendly UX + unified `xrd` front-end + ~/.xrdrc aliases.

**Swiss-army-knife cluster 2 slice 1 — xrdcp bulk/batch (2026-06-15).** xrdcp goes from
strict `SRC DST` to `SRC... DST`: multiple sources, client-side glob expansion, and a
`--from <manifest>` list all copy into a destination DIRECTORY, with `--retry N`
(capped exponential backoff). Classic single `xrdcp SRC DST` is byte-for-byte preserved
(single-copy path taken when exactly one source and no --from). New `lib/glob.c`
(`xrdc_glob`/`xrdc_has_glob`/`xrdc_glob_free`, added to LIB_SRCS): single-level root://
wildcard expansion (split dir/last-component, one dirlist, fnmatch FNM_PERIOD, rebuild
full URLs). xrdcp.c rewritten with str_append/str_free dynamic source list, read_manifest
(# comments, stdin), expand_source (root glob / local glob(3) / literal), dest_is_dir
(local stat / remote kXR_isDir; web batch unsupported), per-file retry + summary
("N copied, M failed", nonzero exit on any failure). NO goto; clean build zero-warn; ldd
no libXrd*. 7 tests (tests/test_client_xrdcp_bulk.py): single back-compat, multi-source
download, glob download, manifest, multi-source upload into remote dir, batch-requires-dir,
retry-then-fail-no-hang. Full client regression: 80 pass + 2 skip.
Cluster 2 remaining slices: parallel queue (-j), byte progress+ETA, resumable (range-GET +
checkpoint), rsync-like dir sync, recursive web copy, auto integrity-verify. Then the
capability engine (Phase 0) folds underneath per docs/refactor/phase-37-swiss-army-plan.md.

**Cluster 2 slice 1 hardening (adversarial review, 2026-06-15)** — 6 confirmed fixes:
glob.c — (MED) reject over-long last-component pattern instead of silent truncation;
(MED) check the rebuilt-URL snprintf return and skip a match that would truncate;
(LOW) re-bracket an IPv6 host literal in the rebuilt URL; (LOW) reject dirlist entry
names containing '/' or '.'/'..' + fnmatch FNM_PATHNAME (no traversal-shaped URLs).
xrdcp.c — (LOW) path_basename now strips trailing slashes (buffer-copy form);
(LOW) expand_source distinguishes "not a glob" (XRDC_EUSAGE → literal) from a hard
connect/dirlist failure (surface the error, don't copy a literal '*'). ALSO removed a
goto I had introduced in glob.c (no-goto hard block) → flag+break cleanup. Clean build
zero-warn; grep confirms no goto in glob.c/xrdcp.c; 7 bulk tests + 20 remote-doctor +
full client suite green (a 6-error combined-run blip was env contention, 20/20 in isolation).

**Cluster 2 slice 2 — parallel transfer queue (2026-06-15).** xrdcp `-j/--jobs N` copies up
to N batch items concurrently via a pthread worker pool (batch_ctx: shared next-index + ok/fail
counters + one mutex; each xrdc_copy is fully independent — own connection/fds). Refactored
the per-item copy into batch_copy_one() shared by the serial and parallel paths; jobs clamped
to the item count; falls back to inline drain if no thread starts. Serial (jobs<=1) behaviour
and classic single copy unchanged. NO goto; clean build zero-warn. test_client_xrdcp_bulk.py
grows test_parallel_jobs_download (12 files, -j 4, all md5-exact) → 8 bulk tests; full client
suite green. Cluster 2 remaining: byte progress+ETA, resumable (range-GET + checkpoint),
rsync-like --sync, recursive web copy, auto integrity-verify.

**Cluster 2 slice 3 — rsync-like --sync (2026-06-15).** xrdcp `--sync` skips a transfer
when the destination already exists with the SAME size as the source (entry_size() stats
both ends: local stat / remote kXR_stat; web → always copy, no cheap stat). Files that
differ (or are missing) are copied, overwriting (sync implies force). transfer_one()
wraps the size check + copy and returns copied/skipped/failed; threaded through the single,
serial-batch, and parallel-worker paths; summary now "N copied, M skipped, K failed".
Clean build zero-warn; test_client_xrdcp_bulk.py grows test_sync_skips_up_to_date (same-size
skipped + wrong-size recopied) → 9 bulk tests; 28 core client tests green.
Cluster 2 done so far: batch/glob/manifest/retry (slice 1, +6 review fixes), parallel -j
(slice 2), --sync (slice 3). Remaining: byte progress+ETA, resumable (range-GET + checkpoint),
recursive web copy, auto integrity-verify. NB: the maintainer is concurrently refactoring the
client lib (copy.c download_stream_body extraction, ops_meta/ops_file/http edits) — keep
re-reading those before any lib edit; the xrdcp.c/glob.c cluster-2 work is independent of them.

**Swiss-army-knife — ~/.xrdrc endpoint aliases (2026-06-15).** New lib/xrdrc.c
(xrdc_alias_resolve): an optional ini file at $XRDRC (else ~/.xrdrc) with
`[alias NAME]` / `url = <base-url>` blocks. `name:suffix` resolves to base-url joined
to suffix (one '/'); anything not a known alias (or a `scheme://...`) passes through
verbatim → zero behaviour change when no rc file or no match. Parsed once, cached.
Wired at the single choke points: xrdcp (every source via expand_source + the dst) and
xrdfs (endpoint_to_url). So `xrdfs lab:/ ls` and `xrdcp lab:/data/f.bin .` "just work".
Added lib/xrdrc.c to LIB_SRCS. NO goto; clean build zero-warn. 5 tests
(tests/test_client_xrdrc_alias.py: xrdfs/xrdcp up+down via alias, unknown-alias
passthrough, missing-rc harmless); 28-test cross-suite regression green. This is the
foundation of the "just works" UX engine — next: a unified git-style `xrd` front-end and
per-endpoint auth hints in the alias blocks. (Lib refactor by the maintainer still in
flight in copy.c/http.c/ops_*; this slice stayed in new files + xrdcp/xrdfs choke points.)

**Cluster 2 slice 4 — recursive WebDAV download (2026-06-15).** `xrdcp -r davs://h/dir/ out/`
now copies an entire WebDAV/HTTP collection, preserving the tree. New lib/weblist.c
(xrdc_webdav_list): one PROPFIND Depth:infinity over the existing HTTP client, scans the
multistatus body for each <D:response> (href + whether it carries <D:collection/>),
percent-decodes hrefs, returns the file paths (subdirs excluded; bounded at 200k). xrdcp.c
gains recursive_web_download() (mkdir -p per relpath + public xrdc_copy per file, with a
non-recursive opts copy so the per-file copy doesn't hit the no-recursive-web guard) and a
main() interception (web -r only; root/local -r still handled inside xrdc_copy). Reuses the
public copy engine → NO copy.c changes (kept clear of the maintainer's in-flight copy.c
refactor). s3:// recursive returns a clean "not supported yet" (needs SigV4 query-canonical
listing — follow-up). Added lib/weblist.c to LIB_SRCS. NO goto; clean build zero-warn.
test_client_web_transfer.py grows test_webdav_recursive_download (top.txt + sub/deep.bin
round-trip with structure) → 6 web tests; 34-test client regression green.
Cluster 2 done: batch/glob/manifest/retry, parallel -j, --sync, recursive WebDAV download.
Remaining (need copy.c/http.c — held while maintainer refactors): byte progress+ETA,
resumable range-GET, auto integrity-verify, recursive S3 + recursive web UPLOAD.

**Recursive-web security hardening (2026-06-15).** recursive_web_download rejects any
server-supplied path that is absolute or contains a ".." component (path-traversal guard) so a
hostile WebDAV server cannot write outside the destination dir. test_webdav_recursive_rejects_
traversal drives a mock PROPFIND server returning /rtree/../../escape.txt and asserts xrdcp
refuses it ("unsafe path", nonzero exit, nothing escapes). 7 web tests green.

**Just-works auth — per-endpoint credentials in ~/.xrdrc (2026-06-15).** Alias blocks now
carry optional auth: `token` (inline bearer) / `token_file` (read a bearer from a file),
`s3_access` / `s3_secret` / `s3_region`, and `proxy` (X.509). New additive lib API
xrdc_alias_lookup(name, xrdc_alias_info*) (xrdc_alias_resolve left UNCHANGED — no call-site
churn, low collision with the maintainer's concurrent xrdcp/xrdfs edits). xrdcp merges a
matched alias's creds into opts via merge_alias_auth() for the dst + every source, with
CLI flag / earlier-alias / env all winning over it (first-wins, scheme-specific: bearer for
dav, s3_* for s3, proxy via setenv X509_USER_PROXY without clobber). So `xrdcp s3lab:/obj .`
authenticates with NO --s3-* flags and NO AWS_* env. PII: creds never logged. NO goto; clean
build zero-warn. test_client_web_transfer.py::test_s3_creds_from_xrdrc (S3 up+down with keys
only from the rc file, AWS_* stripped) + 13 web/alias tests; 36-test client regression green.
NB: the maintainer is concurrently building the SAME auth/UX area (Phase-40 xrdc_cred_hint_
for_status remediation in xrdfs.c, client lib refactor) — kept this slice additive + in
lib/xrdrc.c + xrdcp.c only; did NOT touch xrdfs.c. Coordinate before the unified cred_discover
engine to avoid duplicating their work.

**Swiss-army-knife — unified `xrd` front-end (2026-06-15).** New apps/xrd.c (added to BINS):
one git-style command that dispatches to the existing tools (which already resolve ~/.xrdrc
aliases). `xrd cp` / `xrd get <url> [dst=.]` / `xrd put <local> <url>` -> xrdcp; `xrd diag …`
-> xrddiag; filesystem verbs (ls/stat/du/tree/find/mkdir/rm/rmdir/mv/chmod/truncate/cat/tail/
locate/query/statvfs/prepare/explain) -> `xrdfs <endpoint> <verb> …`. Because xrdfs separates
the connect endpoint from the path, xrd splits a full root:// URL (or an alias that resolves to
one) into endpoint + path so `xrd stat root://h//d/f` and `xrd stat lab:/d/f` "just work"; a bare
host:port passes through. The target binary is found next to argv[0] (in-tree ./xrd finds
./xrdfs) via readlink(/proc/self/exe)+dirname, else $PATH; exec-only (execv, no shell → no
injection). It's the natural home for future `xrd doctor` / `xrd login`. NO goto; clean build
zero-warn; ldd no libXrd*. 6 tests (tests/test_client_xrd_frontend.py: ls/stat dispatch, get/
put/cp, version, unknown-cmd, missing-endpoint); 42-test client regression green.

**Auth/xrd hardening (adversarial review, 2026-06-15)** — 4 confirmed fixes:
(HIGH) inline ~/.xrdrc `token =` silently truncated at 2047B (xrdrc_load line buffer < the
8 KB token field; WLCG JWTs exceed 2 KB) → line buffer bumped to 8 KB (xrdrc.c); (HIGH) the
`xrd` fs-verb split only rewrote the FIRST URL, so `xrd mv root://h//a root://h//b` mangled
the 2nd into /root:/h/b → map_fs_arg() now splits EVERY path-position arg to its path and
rejects a cross-endpoint operation (xrd.c); (MED) merge_alias_auth folded s3_access/s3_secret
independently → could assemble a mismatched key pair from two aliases → now folded as a unit
(both-or-neither, only from an alias that has both); (LOW) a missing/empty alias token_file
failed silently → xrdc_alias_info gains token_file/token_file_failed and merge_alias_auth emits
"alias %s: token_file %s missing or empty" (path only, never contents). NO goto; clean build
zero-warn. New regression tests: xrd mv two-URLs + cross-endpoint-rejected, token_file-missing
warns. Full client regression 54 pass.

**Cluster 2 slices 5+6 — byte progress+ETA and --verify (2026-06-15, on the settled lib).**
- **`xrdcp --progress`**: a progress callback (xrdc_progress_cb) added to xrdc_copy_opts; the
  root download (download_stream_body) and upload (upload_stream_body) loops report
  bytes-so-far + total (upload total from fstat; -1 for stdin). xrdcp renders a throttled
  (~5 Hz) `\r` bar with %/MiB/rate/ETA + a final newline, shown when --progress is given or
  stderr is a TTY (and not -s, and not a '-' stdout transfer). Single-copy only (batch keeps
  its [k/N] lines). Web progress = follow-up (needs the callback threaded through
  xrdc_http_download/upload). 
- **`xrdcp --verify`**: post-transfer integrity check — sets cksum to "adler32:source" (an
  explicit --cksum still wins), reusing the existing cksum_verify (queries the server's
  Qcksum and compares the moved bytes). root:// today; web verify = follow-up.
NO goto (the maintainer's copy.c refactor already removed the old ladders); clean build
zero-warn. 4 new tests in test_client_xrdcp_bulk.py (progress rendered, progress-off-on-pipe,
verify-matches-server) → 12 bulk tests; full client regression 57 pass.
Cluster 2 now: batch/glob/manifest/retry, parallel -j, --sync, recursive WebDAV download,
byte progress+ETA, --verify. Remaining: resumable range-GET, recursive S3 (needs SigV4 query
signing), recursive web UPLOAD, and web-side progress/verify.

**Cluster 2 — recursive S3 download + S3 credential-noise gate (2026-06-15).** Closes the
last literal stub (`weblist.c:69 "s3:// listing not supported yet"`); `xrdcp -r s3://h:port/
bucket/prefix out/` now lists and downloads the whole prefix tree, structure-preserving.
- **SigV4 query signing** (`lib/s3.c`): `xrdc_s3_sign_v4_q()` adds the CanonicalQueryString
  line to the canonical request (the old `xrdc_s3_sign_v4` is now a thin wrapper passing ""),
  so GETs that carry a query (ListObjectsV2) sign correctly. The canon string is built with
  the SAME shared `xrootd_http_urlencode` kernel the server verifies with → client-signs ==
  server-verifies. Hardening: the `canon` snprintf return is now checked — a would-be
  truncation (pathological long prefix + continuation token) fails cleanly ("can't sign")
  instead of silently signing a different string than the server checks (→ a confusing 403).
- **`xrdc_s3_list()`** (`lib/weblist.c`): paginated `GET /bucket?list-type=2&prefix=…`
  (continuation-token<list-type<prefix, RFC-3986 sorted+encoded via `s3_canon_qs` helper —
  every append length-checked, NO goto), SigV4-signed with UNSIGNED-PAYLOAD, parses `<Key>`
  + `<IsTruncated>`/`<NextContinuationToken>` (shared `xml_tag` extractor). Bounded:
  XRDC_WEBLIST_MAX keys, 100000 pages; frees on every error path.
- **`recursive_s3_download()`** (`apps/xrdcp.c`): maps each key→`key − prefix` (basename
  fallback), `rel_is_unsafe` traversal guard rejects server-supplied `..`/absolute keys,
  `mkdirs_for` recreates the tree, each object a plain `copy_one_with_retry`. One guarded
  `memcpy` for the bucket split (no `-Wformat-truncation`). `keys` freed; 0/1 return.
- **S3 cred-noise gate** (`apps/xrdcp.c`): an s3:// endpoint authenticates with AWS SigV4
  keys, NOT a GSI proxy or bearer token, so the start-up `xrdc_cred_diagnose` pre-flight was
  wrongly printing "GSI proxy has EXPIRED" on pure-S3 transfers. New `is_s3_url`/
  `uses_cred_auth` predicates gate the pre-flight (and `--refresh` autorefresh) to the
  GSI/token family only (root:// + non-s3 web). "just works with tokens, x509 and other auth."
NO goto; clean build zero-warn; ldd no libXrd*. Tests: `test_s3_recursive_download` (upload 2
objects under a prefix via the client, then `-r` download → tree round-trips md5-exact) in
test_client_web_transfer.py; `test_s3_destination_skips_token_gsi_preflight` (expired token +
s3 dst → NO GSI/token hint) in test_client_cred_preflight.py. Full client regression 67 pass.

**Cluster 2 — recursive web UPLOAD (local tree → davs/http/s3) + adversarial fixes
(2026-06-15).** Symmetric to recursive download: `xrdcp -r ./dir davs://h/coll/` (or
`s3://h/bucket/prefix/`) walks the local tree and uploads its CONTENTS into the collection.
- **`xrdc_webdav_mkcol()`** (`lib/weblist.c` + decl `xrdc.h`): MKCOL a WebDAV collection;
  idempotent (201/200/405/301 = success). Needed because the server's PUT returns 409 on a
  missing parent collection (RFC 4918 §9.7.1).
- **`recursive_web_upload` / `web_upload_walk` / `web_join` / `is_local_dir`** (`apps/xrdcp.c`):
  parse dst weburl once, trim trailing '/' from the base path, walk the local dir with
  `lstat` (symlinks + special files skipped — only real dirs+regular files), MKCOL each
  collection TOP-DOWN before descending (so child PUTs never 409; S3 keys are flat → no
  MKCOL), PUT each file via the existing non-recursive `copy_one_with_retry`. Every snprintf
  truncation-checked. Wired into main's recursive branch: web SOURCE → download (existing);
  else web DST + local dir → upload. `copy_web` still hard-rejects recursive (the intercept
  is upstream), so no collision with the maintainer's root://↔local `copy_recursive`.
- **Adversarial review fixes** (sub-agent review of the new s3/upload code):
  - (HIGH) `xrdc_s3_list` `token[1024]` was too small for the server's NextContinuationToken
    (b64url of the last key, keys up to S3_MAX_KEY=4096 → ~5.5 KB) → silent pagination
    corruption. Fixed: `token[8192]` + `xml_tag` now RETURNS -1 on truncation (was: silently
    truncate + return 1); an over-long key or continuation token is now a hard error
    (XRDC_EPROTO) instead of a wrong download URL / corrupted page.
  - (MED) unchecked `scope`/`sts`/`hdrs` snprintf in `xrdc_s3_sign_v4_q` — a long
    user-controlled `--s3-region` could truncate the scope → silently wrong signature → 403.
    Fixed: all three return-checked (fail-clean), same contract as the canon guard.
  - (MED) IPv6 SigV4 host mismatch: the signed host was `"%s:%d"` (unbracketed) but the wire
    Host header brackets IPv6 (`[::1]:9000`). Fixed in BOTH `xrdc_s3_list` (`weblist.c`) and
    the per-object sign (`copy.c`) via `xrootd_format_host_port` → signed host == wire Host.
  Review confirmed CLEAN: no goto, no token/secret/key/signature logging, leak-free error
  paths, traversal guard on server-supplied keys, correct MKCOL/cred-gate semantics.
NO goto; clean build zero-warn; ldd no libXrd*. Tests: `test_webdav_recursive_upload` +
`test_s3_recursive_upload` (build a nested local tree, `-r` upload, recursively download it
back, assert md5-exact + structure) in test_client_web_transfer.py. Full client regression
68 pass. Recursive copy now works both directions over root/davs/http/s3.

**Batch: web->web copy + xrddiag watch + xrd doctor/login (2026-06-15, ultracode).** A design
workflow (8 grounded design agents + synthesis) ranked the missing-feature backlog by
value×self-containment×collision-risk; this batch is the 3 highest self-contained picks (all
clear of the maintainer-active copy.c/http.c). Then a 3-reviewer→verify adversarial workflow
audited the new code; confirmed findings fixed.
- **web->web copy** (`apps/xrdcp.c`): `xrdcp davs://a/f s3://b/k` (any web↔web combo) now works —
  `relay_web_to_web` stages through a private mkstemp temp in $TMPDIR (download leg → upload leg),
  intercepted at `copy_one_with_retry` so single + batch + per-file recursive all relay; each leg
  is web↔local so it never re-enters the relay. Recursive web->web came almost free: both
  recursive download funcs now place files via a shared `recursive_place` (local dir → mkdir+copy;
  web collection → `mkcol_parents` + relay), and `ensure_web_dst_base` MKCOLs the dst collection
  once. Review fix (MED): the download leg's temp+rename lands 0644, so we `chmod 0600` the staged
  file before the upload leg (was world-readable in /tmp during the upload window); comment
  corrected to stop over-promising prompt SIGINT cancel for web legs. 4 tests (davs→davs,
  s3→davs cross-protocol, recursive davs→s3 round-trip, missing-source temp-cleanup).
- **`xrddiag watch`** (`apps/xrddiag.c`): bounded continuous health/SLA probe (connect + tiny-read
  TTFB + locate) over N endpoints; output as human / Prometheus textfile (`--prometheus[=PATH]`,
  atomic write+rename) / NDJSON (`--json`); `--interval`/`--count`; SIGINT/SIGTERM stop cleanly
  (async-signal-safe flag + interruptible sleep). PII-free: labels are host:port only — review fix
  (MED): the parse-failure path used to leave the raw URL (path/query) in the label → now a
  "(unparseable)" placeholder; prom label-escape drops control bytes; interval clamped (no
  seconds*5 overflow). 4 tests (prometheus up, down-endpoint bounded, json multi-endpoint,
  atomic file).
- **`xrd doctor` / `xrd login`** (`apps/xrd.c`): `xrd doctor [endpoint]` = local cred summary
  (`xrdc_token_explain`/`xrdc_gsi_cert_explain`/`xrdc_cred_diagnose`) + optional connect+TLS-posture
  check (`xrdc_connect`/`xrdc_explain_conn`/`xrdc_tls_info`); `xrd login` = best-effort
  acquire/refresh via `xrdc_cred_autorefresh`. Pure composition of fail-soft libxrdc helpers (no
  new lib code, no Makefile/config.h change — xrd already links libxrdc). Exit nonzero on a fatal
  local cred problem or a failed connect. PII-free (claims only, never the raw token). 4 tests
  (token explained + not echoed, endpoint connect OK, dead endpoint nonzero, login no-creds no-op).
All three: NO goto; clean build zero-warn; `ldd` no libXrd* on xrdcp/xrddiag/xrd. Full client
regression 80 + 44 existing xrddiag pass; 12 new tests. Deferred (need maintainer-active
http.c/copy.c, or next batch): web-side progress/--verify, resumable --continue, web globbing,
`--dry-run`, shell completion + `xrdcp --json`/-h.

**`xrd mount` / `xrd unmount` (2026-06-15).** Front-end verbs for the FUSE3 mount lifecycle.
- `xrd mount [--legacy|--driver aio|legacy] [driver-opts] <endpoint> <mountpoint> [fuse-opts]`
  exec's the FUSE driver (default `xrootdfs_aio` resilient; `--legacy`→`xrootdfs`), forwarding
  args in the driver's native order and resolving a ~/.xrdrc alias for the endpoint (the driver
  doesn't expand aliases). Found via exec_tool's sibling-then-PATH search; the driver backgrounds
  itself unless a fuse -f/-d is given.
- `xrd unmount [-z] <mountpoint>` (alias `umount`) runs `fusermount3 -u` → `fusermount -u` →
  `umount` (lazy -z maps to each tool's flag) via a fork+execvp `run_cmd` (NO shell → no
  injection); a 126 "couldn't exec" sentinel drives the fallback chain.
NO goto; clean build zero-warn; xrd still links no libXrd*. 8 hermetic tests
(tests/test_client_xrd_mount.py: no-args/bad-driver, aio forwarding, --legacy selection, alias
resolution, unmount no-args, fusermount3-preferred, umount-fallback) — fake sibling drivers + a
fake fusermount on $PATH assert the forwarded argv without a real mount. Real-mount smoke on this
host CONFIRMED `xrd mount` mounts (rc=0) and FUSE readdir/stat work (probe.txt at correct size),
and the unmount fallback chain runs. NOTE/finding: the xrootdfs_aio **read** path stalls
(uninterruptible) on this WSL2 host even with thread_pool configured — a pre-existing DRIVER issue
(maintainer-active client lib + FUSE async I/O), independent of the xrd dispatch layer; flagged for
follow-up.
