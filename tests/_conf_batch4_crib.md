# Conformance batch 4 — author crib (libXrdCl / gfal angle + remaining gaps)

Goal: ~1000 NEW differential conformance tests, grounded in the **XrdCl public API
contract** (what gfal/FTS/Rucio rely on) and the **stock xrootd v5.9.5 server**.
Working assumption: a divergence from stock is a **bug in this module** unless
there is positive evidence otherwise.

## Infrastructure you MUST reuse (do not reinvent)

`tests/official_interop_lib.py` (import as `L`):
- `L.start_pair(base, our_port=N, off_port=N+1)` → `(procs, ctx)`. Launches OUR
  nginx-xrootd server AND the stock `xrootd` server on identical rich trees.
  `ctx['our']`, `ctx['off']` are `root://127.0.0.1:PORT` URLs; `ctx['our_data']`,
  `ctx['off_data']` are the on-disk roots (identical bytes). Raises RuntimeError
  on setup failure → wrap fixture so it `pytest.skip`s.
- `L.stop_pair(procs)` in fixture teardown (kills whole process group).
- `L.run(argv, timeout=)` → `(rc, stdout, stderr)`.
- `L.OFF_XRDFS`, `L.OFF_XRDCP`, `L.OFF_XROOTD` — stock tool paths.
- `L.OUR_XRDFS`, `L.OUR_XRDCP` — our native client binaries.
- `L.have_official()` — gate the module: `pytestmark = pytest.mark.skipif(not L.have_official(), ...)`.
- Tree contents (make_rich_tree): `hello.txt`(12), `data.bin`(4096), `empty.txt`(0),
  `sub/nested.txt`, `deep/a/b/c/leaf.txt`, `empty_dir/`, `many/f00..f11.txt`,
  `sz_{1,255,4095,4096,4097,8192,65536}.bin`, `big1m.bin`(1MiB), `with space.txt`,
  `cksum.bin`(10000).

**Real libXrdCl (the NEW angle)** — out-of-process bindings, safe in pytest:
```python
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags, MkDirFlags, DirListFlags, QueryCode, AccessMode, PrepareFlags
fs = client.FileSystem(ctx['our'])
status, statinfo = fs.stat('/hello.txt')   # status.ok/.code/.errno/.message ; statinfo.size/.flags/.id/.modtime
status, listing  = fs.dirlist('/', DirListFlags.STAT)
status, loc      = fs.locate('/hello.txt', OpenFlags.REFRESH)
f = client.File(); status,_ = f.open(ctx['our']+'//hello.txt', OpenFlags.READ)
status, data = f.read(0, 12)
```
Drive the SAME op against `ctx['our']` and `ctx['off']` and assert the parsed
result objects agree (size, flags, status.code/errno, listing names/flags,
location type+access chars). This is exactly gfal's code path.

**gfal** (`gfal-stat/ls/mkdir/rm/copy/xattr/sum/rename`): use `env` with
`LD_LIBRARY_PATH` removed so gfal uses the SYSTEM libXrdCl (see
tests/test_gfal_interop.py `_clean_env`). Run against both `ctx['our']`/`ctx['off']`.

## The behavior contract (XrdCl public API — cite these)

- OpenFlags: `/tmp/xrootd-src/src/XrdCl/XrdClFileSystem.hh:74` (New=kXR_new, Delete=kXR_delete,
  MakePath=kXR_mkpath, Update=kXR_open_updt, Write=kXR_open_wrto, Read=kXR_open_read,
  POSC=kXR_posc, Refresh, Force, NoWait, Replica, SeqIO, PrefName...).
- Access::Mode (chmod bits): UR/UW/UX/GR/GW/GX/OR/OW/OX.
- MkDirFlags: None=0, MakePath=1. DirListFlags: Stat=1,Locate=2,Recursive=4,Merge=8,Chunked=16,Zip=32,Cksm=64.
- PrepareFlags: Colocate/Fresh/Stage/WriteMode/Cancel/Evict.
- QueryCode: Config,ChecksumCancel,Checksum,Opaque,OpaqueFile,OpaqueQ,Prepare,Space,Stats,Visa,XAttr,FInfo,QFinfo,QFSinfo.
- **StatInfo wire parse** (`XrdClXRootDResponses.cc:140`): response is space-split into
  chunks; `chunks[0]=id` (string), `chunks[1]=size` (strtoll base 0, MUST be a clean
  integer or parse FAILS), `chunks[2]=flags` (strtol), `chunks[3]=modtime`. If
  `chunks.size()>=9`: chunks[4]=ctime, [5]=atime, [6]=mode-string(>=4 chars, e.g.
  "0644"), [7]=owner, [8]=group (extended stat). **A malformed integer anywhere makes
  XrdCl reject the whole stat** — so trailing junk / wrong field count is a real bug.
- StatInfo flags enum (`XrdClXRootDResponses.hh:420`): XBitSet=kXR_xset, IsDir=kXR_isDir,
  Other=kXR_other, Offline=kXR_offline, POSCPending=kXR_poscpend, IsReadable=kXR_readable,
  IsWritable=kXR_writable, BackUpExists=kXR_bkpexist.
- LocationInfo parse (`XrdClXRootDResponses.cc:38`): space-split; each token
  `[0]`=type char `M`/`m`/`S`/`s` (Manager/Server Online/Pending), `[1]`=access char
  `r`(Read)/`w`(ReadWrite), rest = `host:port`. A bad type/access char makes XrdCl
  reject the WHOLE locate response. Token length must be >=5.
- StatInfoVFS parse (`:452`): chunks `nrw frw urw nstg fstg ustg` (6 fields).
- Wire enums/error codes: `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` (kXR_* opcodes,
  XErrorCode kXR_* error numbers, kXR_char flag bits).

## Known candidate divergence to investigate (seed)
- StatInfo `id` (chunks[0]): ours emits a small number (inode only?), stock emits a
  large composite (e.g. `(dev<<...)|ino`). Check `XrdXrootdProtocol::StatGen` in
  `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeq.cc` for the exact id formula. gfal mostly
  ignores id, but XrdCl exposes it; align if cheap & evidence says so.

## Rules
- NO new server/client behavior assumptions — cite stock source or stock-tool output.
- Each test file: module-scoped fixture starting ONE pair on YOUR assigned port range.
- Parametrize heavily (per-path, per-flag, per-size) to reach the count target.
- **Do NOT edit any `src/` or `client/` files.** If you find a divergence, record it
  in a `# DIVERGENCE:` comment AND in your final report (area / our output / stock
  output / XrdCl-contract citation / suspected source file). The orchestrator fixes
  serially to avoid concurrent edits. If a test pins a CURRENT divergence you cannot
  fix, mark it `@pytest.mark.xfail(reason=...)` with the citation so the suite stays green.
- Skip cleanly (never ERROR) if tools/bindings missing.
