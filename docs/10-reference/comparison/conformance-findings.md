# Wire-Protocol Conformance — Findings & Fixes

> Reference-grounded conformance testing of this module against the XRootD C++
> **source** and the **stock xrootd server/tools** (v5.9.5), built because the
> `kXR_sigver`-ack bug survived for so long: prior tests checked our server
> against our *own* client (a consistent-but-non-standard pair). The suites below
> check against the **spec and the reference implementation**, so divergences
> surface. **Working assumption: a divergence is a bug in this module unless
> there is positive evidence otherwise.**
>
> Suites:
> - `tests/test_xrootd_conformance.py` — 20 raw-wire tests vs. the documented
>   protocol (self-provisioned anon server, no external deps).
> - `tests/test_official_interop.py` (+ `official_interop_lib.py`) — 53 differential
>   tests that run the **stock `xrdfs`/`xrdcp` against our server** (Q3), **our
>   client against the stock `xrootd` server** (Q2), stock↔stock as an oracle
>   (Q4), and compare outputs (DIFF). Skips without the stock toolchain.
> - `tests/test_gohep_interop.py` — the independent go-hep client (see
>   [`gohep-interop-findings.md`](gohep-interop-findings.md)).
> - `tests/test_gfal_interop.py` — the gfal2 WLCG client (FTS/Rucio layer: xrootd
>   plugin → `libXrdCl`, http plugin → `davix`; see
>   [`gfal-interop-findings.md`](gfal-interop-findings.md)).

Companion: [`xrootd-implementations.md`](xrootd-implementations.md).

---

## Divergences found and FIXED

All ten below were detected by the suites above and corrected (server and, where
the client mirrored the non-standard format, client). Each has a guarding test.

| # | Area | Was | Now (matches reference) | Found by |
|---|---|---|---|---|
| 1 | `kXR_sigver` | server ACKed it; client read the ack | no response on success (it's a request *prefix*) | go-hep |
| 2 | `stat`/`dirlist` redirect | only `open`/`locate` used the static `manager_map` | all consult it | go-hep (mesh) |
| 3 | root `/` prefix match | matched only `/`, not `/child` | trailing-`/` prefix is boundary-aligned | go-hep (mesh) |
| 4 | unknown opcode | `kXR_Unsupported` (3013) | `kXR_InvalidRequest` (3006) | conformance |
| 5 | `kXR_statx` | 4 bytes/path text line; `'\0'`-separated request | **1 flag byte/path**; **newline-separated** request | conformance |
| 6 | `kXR_query` Qconfig | `key=value` | bare `value\n` / echo-key for unknown / `bind_max` | conformance |
| 7 | `kXR_open` | always 12-byte body | **4-byte fhandle** unless retstat/compress | conformance |
| 8 | `statvfs` | 4-field stat line (stock client: "Invalid response") | **6-field** `nRW freeRW utilRW nStg freeStg utilStg` via `statvfs(2)` | stock `xrdfs` |
| 9 | dirlist namespace | leaked `/.nginx-xrootd-ckp-recovery.lock` | internal `.nginx-xrootd*` artifacts hidden | stock `xrdfs` (DIFF) |
| 10 | WebDAV `PROPFIND` quota | emitted RFC 4331 `quota-used-bytes` on **files** → `davix` mapped it to `st_size` | quota gated to **collections** (`S_ISDIR`); files carry only `getcontentlength` | gfal2 (davs:// `gfal-stat`) |

Each fix was verified **client-safe**: e.g. our client doesn't use `statx`, parses
query config via `strstr`, and reads the open fhandle from the first 4 bytes; the
sigver fix was a coordinated server+client change. Several (#5–#8) were
sigver-style "agrees-with-our-own-client" traps — caught only by an independent
client/server.

### Second differential batch — 256 tests, 6 more divergences FIXED

A larger differential sweep (`tests/test_conf_*.py`, 256 parametrized cases run by
the stock `xrdfs`/`xrdcp` against both servers on a rich edge-case tree) surfaced
six more divergences, all corrected and pinned by a guarding test:

| # | Area | Was | Now (matches reference) | Found by |
|---|---|---|---|---|
| 10 | `kXR_stat` flags | only `kXR_readable`(+`kXR_isDir`) | full `StatGen`: `kXR_writable`/`kXR_xset` from perms vs server euid/egid | stock `xrdfs stat` |
| 11 | `mkdir` of an existing path (no `-p`) | silent success | `kXR_ItExists` "file exists" (mkpath stays idempotent) | stock `xrdfs mkdir` |
| 12 | `query config pio_max` | echoed the key (unknown) | bare integer (`maxPio+1`=5) | stock `xrdfs query` |
| 13 | create-open to a missing parent dir | `kXR_NotFound` | parent chain auto-created (XrdOss makes the path even without `kXR_mkpath`) | stock `xrdcp` upload |
| 14 | `kXR_mv` into a missing parent dir | `kXR_NotFound` | dest parent chain auto-created; source-missing wording aligned | stock `xrdfs mv` |
| 15 | interior `..` segment (e.g. `/sub/../f`) | silently normalized by RESOLVE_BENEATH | rejected for the extract-based ops (stat/open/dirlist/locate), as the reference does not normalize `..` | stock `xrdfs`/`xrdcp` |

Notes:
- #10 mirrors `XrdXrootdProtocol::StatGen` exactly (shared encoder
  `xrootd_stat_flags_from_stat`, owner/group/other checked against the server's
  effective uid/gid — whom the confined export is accessed as).
- #13/#14 were confirmed empirically (stock `xrdcp` leaves `MakePath` *off* by
  default yet the file still lands in a missing parent — the **server** makes the
  path on create-open / rename).
- #15: the op-table ops (rm/mkdir/mv/chmod/…) already rejected `..` with traversal
  logging in `xrootd_path_resolve_beneath`; only the kernel-RESOLVE_BENEATH ops
  bypassed it. The new `xrootd_reject_dotdot_path` closes that gap with the same
  warning + access-log line. Escaping `..` was always confined; this is a
  protocol-conformance guard, not a new security boundary.

### Third differential batch — 908 tests, 7 more divergences FIXED

A 10-file deep sweep (`tests/test_conf_{cksum,readv,openflags,truncate_sync,dirlist,
statx,errors,xrdfs,xrdcp,pathedge}.py`, ~908 parametrized cases, stock `xrdfs`/
`xrdcp` + raw-wire against both servers) found seven more divergences, all fixed:

| # | Area | Was | Now (matches reference) | Found by |
|---|---|---|---|---|
| 16 | `query checksum ?cks.type=<algo>` as LAST CGI field | wire NUL folded into the algo name → "unknown algorithm" (broke every non-adler32 + `xrdcp --cksum`) | trailing NUL/CR/LF trimmed | stock `xrdfs`/`xrdcp` |
| 17 | `kXR_statx` of a missing path | `kXR_ok` + `kXR_offline` byte | `kXR_error`/`kXR_NotFound` (offline is only for a stat that succeeds with mode==-1) | stock raw-wire |
| 18 | `kXR_rm` of a **directory** | recursively deleted the whole subtree (**data loss**) | unlink file / non-recursive rmdir (empty→ok, non-empty→ENOTEMPTY) | stock raw-wire + xrdfs |
| 19 | `mkdir /d/` (trailing slash) | `kXR_ArgInvalid` | normalized (stripped) like the reference's Squash → created | stock `xrdfs mkdir` |
| 20 | `open(kXR_new)` on an existing file | `kXR_FileLocked`(3003) | `kXR_ItExists`(3018) (EEXIST mapping) | stock raw-wire |
| 21 | create-open parent auto-create | (1st pass) unconditional, then mkpath-only | `kXR_mkpath` **OR** `kXR_async` — the exact reference condition (Xeq:1544); xrdcp sends `kXR_async`, so uploads work while raw `open(new)` without either correctly fails NotFound | stock raw-wire + xrdcp |
| 22 | client `xrdfs chmod rwxr-xr-x` | only octal parsed → symbolic form silently became mode 000 | accepts the stock 9-char symbolic form AND octal | stock vs our client (Q2) |

Notes:
- #18 is the most serious: a plain `rm <dir>` recursively erased non-empty trees.
  The reference `osFS->rem` (XrdOssSys::Unlink) does unlink-or-rmdir, never recurse.
- #21 was a two-step correction: the 200-batch's "auto-create unconditionally"
  (#13) over-generalized; raw-wire differential proved stock gates path creation on
  `kXR_mkpath | kXR_async` (XProtocol bit 0x40), which is exactly what xrdcp sets.
- The suite also hardened the harness (`official_interop_lib`): `stop_pair` now kills
  the whole process group and `start_pair` converts any setup failure to a skip, so
  all 10 files run in one process without leftover servers exhausting the box.

The POSC-disconnect case is left as a documented xfail (ours removes the un-closed
partial immediately, which is the correct Persist-On-Successful-Close intent; stock
keeps it pending a reconnect window — a defensible semantic difference, not a bug).

Two stock behaviours were judged **non-bugs** (evidence against "our bug"): stock
returns `mkdir` idempotently rc=0 for a directory *it itself* created earlier
(an oss namespace-cache quirk that does not apply to a pre-existing on-disk dir,
where it correctly returns 3018), and maps `mkdir`-under-a-file to `ENOTDIR`/3005
where our confined-resolve abstraction reports the coarser `NotFound`/3011 — both
valid rejections (no directory is created). The two probes pin the stable contract.

### Regression the broader sweep exposed — write-through cache flush

Running the wider suite against the full topology fleet surfaced a **latent
self-consistency regression** introduced by fix #7 (4-byte open response): the
write-through cache's hand-rolled origin client (`src/fs/cache/origin_protocol.c`)
required the open reply to be `>= sizeof(ServerOpenBody)` (12 bytes), but a
conformant non-`retstat` open now returns a bare **4-byte** fhandle. The cache
rejected the valid reply, aborted the flush after opening the origin file, and
the close failed with `[3007] write-through flush to origin failed` (the origin
logged the half-written file's close as "connection lost"). Fixed to require only
`XRD_FHANDLE_LEN` and read the fhandle alone (the cache never uses cpsize/cptype).
This is exactly the class of bug differential conformance work introduces — a wire
change that satisfies the spec but desyncs an *internal* peer that over-specified
the old framing; the regression net (`test_cache_write_through`, `test_integrity_
matrix` write-through topologies) now guards it.

### Fourth differential batch — ~1,160 tests via the libXrdCl/gfal API contract, 9 more divergences FIXED

This batch drives the **real `libXrdCl` bindings** (out-of-process via the
`_xrdcl_proxy` worker — `from XRootD import client`) and the **gfal2 CLI** (the
FTS/Rucio layer) differentially against both servers, in addition to raw-wire and
stock-tool probes. It is grounded in the **XrdCl public API as the behaviour
contract** — the exact `StatInfo`/`LocationInfo`/`Status`/`DirectoryList` parse
rules gfal depends on (`XrdClXRootDResponses.cc`, `XrdClFileSystem.hh`). Six new
files (`tests/test_conf_xrdcl_{stat,fileops,fs,locate}.py`,
`tests/test_conf_{gfal_ops,fattr}.py`) contribute ~1,160 cases. Nine divergences
were found and fixed (each pinned by a now-passing guard):

| # | Area | Was | Now (matches reference) | Found by |
|---|---|---|---|---|
| 23 | `kXR_stat` **id** (chunks[0], `StatInfo::GetId`) | bare inode | `(st_ino<<32)\|(uint32_t)st_dev` — the reference `StatGen` union layout (`XrdXrootdProtocol.cc:766`) | XrdCl `FileSystem::Stat` |
| 24 | `ENOTEMPTY`/`EEXIST` → kXR | `kXR_FSError`(3005) | `kXR_ItExists`(3018) — reference `mapError` (`XProtocol.hh:1422`) | XrdCl rm/rmdir of non-empty dir |
| 25 | NS `NO_SPACE` → kXR | `kXR_NoMemory` | `kXR_NoSpace`(3017) (ENOSPC) | mapping audit alongside #24 |
| 26 | `kXR_truncate` of a missing path | `kXR_IOError`(3007) | errno-mapped → `kXR_NotFound`(3011) (handler hard-coded IOError; now `xrootd_kxr_from_errno`) | XrdCl/stock truncate |
| 27 | `query config role` | echoed `role` (unknown-key) | `server` (or `manager` in manager mode) — `do_Qconf` `XRDROLE` | XrdCl `Query(Config)` |
| 28 | `query config fattr` | echoed `fattr` | `248 65536` (usxParms: Linux user.* name/value caps) | XrdCl `Query(Config)` |
| 29 | `query config` empty payload | `kXR_ok` empty | `kXR_ArgMissing` "query config argument not specified." (`do_Qconf`) | raw-wire |
| 30 | `query prepare` (Qprep) unknown reqid | `kXR_ok` empty | `kXR_ArgInvalid` "Prepare requestid owned by an unknown server" (`do_Prepare(isQuery)`); FRM-tracked/inline-path queries unaffected | raw-wire + XrdCl |
| 31 | `query space` empty/relative path | `kXR_ok` | `kXR_NotAuthorized`(3010) (reference `rpCheck`/`rpEmsg`) | XrdCl `Query(Space)` |
| 32 | `kXR_fattrList` name | leaked internal `U.<name>` (stripped 5 of 7 bytes) | bare verbatim name — strips the full `user.U.` prefix (reference keeps `FATTR_NAMESPACE='U'` internal); also fixes list→get round-trips | XrdCl `list_xattr` + stock `xrdfs xattr list` + gfal |

Plus a session fix surfaced by the regression sweep: a **second `kXR_login` on a
live connection** now returns the reference code `kXR_InvalidRequest` "duplicate
login; already logged in" (`do_Login`, Xeq:1095) instead of `kXR_ArgInvalid`
(the test pins the rejection *category*, since the exact code is version-dependent
— installed stock v5.9.5 surfaces `kXR_ArgMissing`).

Two findings were judged **non-bugs / deferred** (evidence otherwise):
- **pgwrite CSE-retransmit** — on a corrupt page stock replies `kXR_ok` + a
  `ServerResponseBody_pgWrCSE` retransmit list; ours **safely hard-fails** the
  page with `kXR_ChkSumErr`. Both detect the corruption (no silent acceptance);
  only the recovery shape differs. CSE-retransmit needs coordinated client+server
  state and is tracked as a feature (documented `xfail`), not a data-safety gap.
- **gfal-sum / `xroot.cksum` xattr** vs the *bare* stock data server return
  "Operation not supported" because the harness's stock server is launched without
  a checksum plugin, while ours computes digests in-tree (independently verified
  against `xrdcrc32c`/`xrdadler32`/`hashlib`). Not a divergence in our favour to
  "fix"; pinned as `xfail` with the reason.

All nine fixes live in `src/path/stat_body.c`, `src/core/compat/error_mapping.c`,
`src/write/truncate.c`, `src/query/{config,space,prepare}.c`,
`src/fattr/list.c` (+ `ngx_xrootd_fattr.h`), and `src/session/login.c`, each
verified client-safe and regression-clean against the full `test_conf_*` suite.

---

## What the suites confirm conformant (no divergence)

streamid echo; `kXR_ping` empty-ok; pre-login rejection; negative/oversized dlen;
error-body framing (`errnum`+NUL, `kXR_NotFound` for ENOENT); handshake reply
(protover `0x520`, DataServer); `kXR_protocol` flags; 16-byte login sessid;
`kXR_stat` `id size flags mtime` (size/`isDir`/`readable`); `kXR_read` raw data;
`kXR_readv` per-segment `readahead_list` framing; **stock `xrdfs` ls/-l/stat/
statvfs/locate/query{config,checksum}/mkdir/rmdir/rm/mv/truncate/chmod/cat/ls-R/
tail against our server**; **stock `xrdcp` up/download/stdout/1-MiB/`--cksum`
against our server**; **our client ls/stat/statvfs/locate/cat/cp/mkdir/rm against
the stock server**; `ls` and `stat`-field parity and identical bytes/checksum
between our server and the stock server.

---

## Running

```bash
# raw-wire protocol conformance (no external deps)
PYTHONPATH=tests pytest tests/test_xrootd_conformance.py -v        # 20 pass

# differential against the stock xrootd server/tools (needs xrootd/xrdfs/xrdcp)
PYTHONPATH=tests pytest tests/test_official_interop.py -v          # 53 pass

# all conformance + interop + GSI/TPC regression
PYTHONPATH=tests pytest tests/test_official_interop.py \
  tests/test_xrootd_conformance.py tests/test_gohep_interop.py \
  tests/test_gsi_interop_guards.py tests/test_tpc_gsi_outbound.py -q
# -> 87 passed, 5 skipped
```

The `test_official_interop` harness launches both servers on the same tree, so
adding a probe for any new operation is a few lines; treat any new failure as a
bug in this module first.
