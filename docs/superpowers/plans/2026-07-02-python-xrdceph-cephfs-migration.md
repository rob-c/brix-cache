# Python3 XrdCeph ↔ CephFS Migration Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pure-Python3 re-implementation of the two XrdCeph (libradosstriper) ↔ CephFS migration tools with zero-move redirect migration, full C++ parity plus `--json`/progress/state/filter improvements, tested against the Docker Ceph demo cluster.

**Architecture:** Two executable scripts in `tests/ceph/` share a `pymigrate/` package: `radosbridge.py` (ctypes access to librados's C API + the four C++-only manifest ops, with a compiled-shim fallback), `cephfs_meta.py` (pure-Python port of the `cephfs_denc`/`cephfs_layout` decoders + RADOS namespace walker), and `common.py` (CLI plumbing: worklist, state manifest, JSON/progress/log, thread runner). Spec: `docs/superpowers/specs/2026-07-02-python-xrdceph-cephfs-migration-design.md`.

**Tech Stack:** Python 3.9 stdlib (ctypes, zlib, json, fnmatch, concurrent.futures) + distro `python3-rados` / `python3-cephfs`. No pip. Docker demo cluster via existing `tests/ceph_harness.sh` (`xrd-ceph-demo` + `xrd-ceph-work`, pool `xrdtest`, fs pools `cephfs_metadata`/`cephfs_data`).

## Global Constraints

- Distro modules only: `python3-rados`, `python3-cephfs`, stdlib. No pip installs.
- C++ originals (`xrdceph_striper_migrate.cpp`, `xrdceph_cephfs_to_striper.cpp`) and their runner stay untouched.
- CLI grammar of each Python tool is a superset of its C++ original (spec §5/§6); guard semantics identical (`--delete-source`×redirect refused; `--assume-quiesced` mandatory for tool 2; exit 0/1/2).
- Redirect stubs are created **without a reference** (`set_redirect(..., ver, 0)`); rollback always detaches (`unset_manifest`) **before** unlink/remove.
- `zlib.adler32(data, 1)` — seed 1, rendered `"%08x"`, compared case-insensitively to `user.XrdCks.adler32`.
- Decoders refuse cleanly (exception → classified skip), never guess; caps: 256 frags, 64 xattrs, flagged truncated.
- Verified ABI facts (reef 18.2, container `xrd-ceph-work`): manifest ops are C++-only; exact mangled symbols in Task 5; base `ObjectOperation` ctor/dtor exported; `librados::IoCtx` is a single-pointer pimpl over `rados_ioctx_t`; el9 `librados-devel` lacks `librados.hpp` (it's in `libradospp-devel`) — shim build must handle absence.
- Spike `/tmp/bridge_spike.py` (2026-07-02) proved the full ctypes redirect round-trip on the live cluster: keep its mechanics verbatim (StdString CXX11 SSO struct, 16-byte OpBuf, fabricated IoCtx).

## File Structure

```
tests/ceph/
  pymigrate/__init__.py             # empty marker
  pymigrate/cephfs_meta.py          # Task 1-3: denc cursor, typed decoders, walker
  pymigrate/common.py               # Task 4: shared CLI plumbing
  pymigrate/radosbridge.py          # Task 5-6: ctypes bridge + shim fallback + striper read
  pymigrate/shim/rados_manifest_shim.cpp  # Task 6
  test_cephfs_meta.py               # Tasks 1-4 unit tests (pytest, no cluster)
  xrdceph_striper_migrate.py        # Task 7: tool 1 (striper → CephFS)
  xrdceph_cephfs_to_striper.py      # Task 8: tool 2 (CephFS → striper)
  run_py_migrate.sh                 # Task 9: Docker e2e runner
```

---

### Task 1: denc layer — `Denc` cursor + frame (`pymigrate/cephfs_meta.py`)

**Files:**
- Create: `tests/ceph/pymigrate/__init__.py` (empty)
- Create: `tests/ceph/pymigrate/cephfs_meta.py`
- Test: `tests/ceph/test_cephfs_meta.py`

**Interfaces (Produces):**
```python
class DecodeError(Exception): ...
class Denc:                       # bounded LE cursor; raises DecodeError on overrun
    def __init__(self, buf: bytes, pos: int = 0, end: int | None = None)
    def u8/u16/u32/u64/s64(self) -> int
    def bytes(self, n) -> bytes
    def skip(self, n) -> None
    def str(self) -> bytes        # u32 len + payload (string/bufferlist/bufferptr)
    def start(self) -> Frame      # ENCODE_START: struct_v u8, compat u8, len u32
    def finish(self, f: Frame)    # jump to f.payload_end
    def remaining(self) -> int
Frame = namedtuple("Frame", "struct_v struct_compat payload_end")
```
Unlike the C sticky-error cursor, Python raises `DecodeError` immediately (idiomatic; callers wrap in try/except). `start()` errors if declared length exceeds the buffer.

- [ ] **Step 1: Write failing tests** — in `tests/ceph/test_cephfs_meta.py`:

```python
import struct, pytest, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pymigrate.cephfs_meta import Denc, DecodeError

def test_denc_ints():
    d = Denc(struct.pack("<BHIQq", 7, 0x1234, 0xdeadbeef, 2**60, -5))
    assert (d.u8(), d.u16(), d.u32(), d.u64(), d.s64()) == (7, 0x1234, 0xdeadbeef, 2**60, -5)
    assert d.remaining() == 0

def test_denc_overrun_raises():
    d = Denc(b"\x01")
    with pytest.raises(DecodeError):
        d.u32()

def test_denc_str_and_frame():
    payload = struct.pack("<I", 3) + b"abc"
    frame = bytes([9, 1]) + struct.pack("<I", len(payload) + 4) + payload + struct.pack("<I", 0xffffffff)
    d = Denc(frame)
    f = d.start()
    assert f.struct_v == 9
    assert d.str() == b"abc"
    d.finish(f)                      # skips the trailing u32 inside the frame
    assert d.remaining() == 0

def test_denc_frame_length_overrun():
    with pytest.raises(DecodeError):
        Denc(bytes([1, 1]) + struct.pack("<I", 999)).start()
```

- [ ] **Step 2: Run to verify failure** — `cd tests/ceph && python3 -m pytest test_cephfs_meta.py -v` → ImportError/ModuleNotFoundError.

- [ ] **Step 3: Implement** `Denc`/`Frame`/`DecodeError` per the interface (mirror `cephfs_denc.c` semantics; `str()` returns bytes copy; `start()` validates `len` against `end`).

- [ ] **Step 4: Run tests** → 4 PASS.

- [ ] **Step 5: Commit** — `git add tests/ceph/pymigrate tests/ceph/test_cephfs_meta.py && git commit -m "feat(pymigrate): Ceph encoding cursor (denc layer)"`

---

### Task 2: typed decoders (`cephfs_meta.py` continued)

**Files:** Modify `tests/ceph/pymigrate/cephfs_meta.py`, extend `tests/ceph/test_cephfs_meta.py`.

**Interfaces (Produces):** faithful port of `src/fs/backend/rados/cephfs_layout.c`:
```python
MAX_FRAGS = 256; MAX_XATTRS = 64
S_IFMT=0o170000; S_IFDIR=0o040000; S_IFREG=0o100000; S_IFLNK=0o120000
def mode_is_dir(m)/mode_is_reg(m)/mode_is_link(m) -> bool
@dataclass Layout: stripe_unit, stripe_count, object_size, pool_id
@dataclass Inode: ino, mode, uid, gid, nlink, size, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec, layout, struct_v
@dataclass Dentry: kind ("primary"|"remote"), remote_ino, remote_d_type,
                   inode, symlink: bytes|None, frags: list[int], frags_truncated,
                   xattrs: dict[bytes, bytes], xattrs_truncated
def decode_file_layout(d: Denc) -> Layout        # framed; pool_ns frame-skipped
def decode_inode(d: Denc) -> Inode               # guards: v>=4 dir_layout(8B), v>=5 truncate_pending(u32); frame-skip after mtime
def decode_fragtree(d: Denc) -> (list[int], bool)  # unframed compact_map; leaves via explicit stack; empty map -> [0]
def decode_xattrs(d: Denc) -> (dict[bytes,bytes], bool)
def decode_dentry(buf: bytes) -> Dentry          # u64 snapid, u8 type: 'L'/'l' remote; 'i' wrapped (v>=2 alt_name) ; 'I' bare
```
Field order/version guards copied verbatim from `cephfs_layout.c` (inode: ino u64, rdev u32, ctime 2×u32, mode/uid/gid/nlink u32, anchored u8, [v≥4 dir_layout 8B], framed layout, size u64, truncate_seq u32, truncate_size u64, truncate_from u64, [v≥5 u32], mtime 2×u32, frame-skip rest). Fragtree child: `enc=(bits<<24)|value`, child `= ((bits+n)<<24)|(((value<<n)|i)&0xffffff)`, fan-out capped at 8 bits, >MAX_FRAGS splits → DecodeError.

- [ ] **Step 1: Write failing tests** — port the C unittest's synthetic encoder + assertions AND the real-fixture assertions:

```python
FIXDIR = os.path.join(os.path.dirname(__file__), "fixtures", "reef-18.2.4")

def enc_frame(v, compat, payload):
    return bytes([v, compat]) + struct.pack("<I", len(payload)) + payload
def enc_layout(su=0x400000, sc=1, osz=0x400000, pool=7):
    return enc_frame(2, 2, struct.pack("<IIIq", su, sc, osz, pool) + struct.pack("<I", 0))
def enc_inode(v, ino=0x1234, mode=0o100644, size=4096, mtime=555):
    b = struct.pack("<QIII", ino, 0, 100, 0) + struct.pack("<IIII", mode, 0, 0, 1) + b"\0"
    if v >= 4: b += b"\0" * 8
    b += enc_layout()
    b += struct.pack("<QIQQ", size, 1, 0xffffffffffffffff, 0)
    if v >= 5: b += struct.pack("<I", 0)
    b += struct.pack("<II", mtime, 0) + b"\0" * 16      # trailing fields to frame-skip
    return enc_frame(v, 6, b)

@pytest.mark.parametrize("v", [2, 3, 4, 5, 11, 14, 19])
def test_inode_versions(v):
    ino = decode_inode(Denc(enc_inode(v)))
    assert (ino.struct_v, ino.ino, ino.size, ino.mtime_sec) == (v, 0x1234, 4096, 555)
    assert mode_is_reg(ino.mode) and ino.layout.object_size == 0x400000 and ino.layout.pool_id == 7

def test_fragtree_empty_and_split():
    leaves, tr = decode_fragtree(Denc(struct.pack("<I", 0)))
    assert leaves == [0] and not tr
    leaves, tr = decode_fragtree(Denc(struct.pack("<III", 1, 0, 1)))
    assert sorted(leaves) == [0x01000000, 0x01000001] and not tr

def test_xattr_map():
    def s(x): return struct.pack("<I", len(x)) + x
    xs, tr = decode_xattrs(Denc(struct.pack("<I", 2) + s(b"user.a") + s(b"1") + s(b"user.bb") + s(b"22")))
    assert xs == {b"user.a": b"1", b"user.bb": b"22"} and not tr

def _fx(name): return open(os.path.join(FIXDIR, name), "rb").read()

def test_fixture_file():
    dn = decode_dentry(_fx("fx_dir1_hello.bin"))
    assert dn.kind == "primary" and dn.inode.ino == 0x100000001f7 and dn.inode.size == 27
    assert mode_is_reg(dn.inode.mode) and dn.inode.layout.object_size == 0x400000

def test_fixture_dirs_and_top():
    assert decode_dentry(_fx("fx_root_dir1.bin")).inode.ino == 0x10000000000
    assert mode_is_dir(decode_dentry(_fx("fx_dir1_sub.bin")).inode.mode)
    assert decode_dentry(_fx("fx_root_top.bin")).inode.size == 15

def test_fixture_symlink():
    dn = decode_dentry(_fx("fx_link_symlink.bin"))
    assert mode_is_link(dn.inode.mode) and dn.symlink == b"hello.txt" and dn.inode.ino == 0x10000000003

def test_fixture_xattrs():
    dn = decode_dentry(_fx("fx_hello_xattr.bin"))
    assert dn.xattrs == {b"user.color": b"blue", b"user.shape": b"round"} and dn.inode.size == 27

def test_dentry_garbage_refused():
    with pytest.raises(DecodeError):
        decode_dentry(b"\0" * 8 + b"Z" + b"\0" * 32)
    with pytest.raises(DecodeError):
        decode_dentry(b"\x01")
```

- [ ] **Step 2: Run → FAIL** (names undefined).
- [ ] **Step 3: Implement** the five decoders per the interface block (dentry `'i'`: outer frame, `if wrap.struct_v >= 2: d.str()` alt_name, inner InodeStore frame, primary body = inode + (symlink if link) + fragtree + xattrs, then finish both frames; unknown type byte → DecodeError).
- [ ] **Step 4: Run → all PASS.**
- [ ] **Step 5: Commit** — `feat(pymigrate): CephFS typed decoders (dentry/inode/fragtree/layout/xattrs)`

---

### Task 3: namespace walker + snaptable probe (`cephfs_meta.py` continued)

**Files:** Modify `tests/ceph/pymigrate/cephfs_meta.py`, extend tests.

**Interfaces (Produces):**
```python
ROOT_INO = 1
@dataclass WalkEntry:
    path: str; kind: str   # "file"|"dir"|"symlink"|"remote"|"special"
    dentry: Dentry
    undecodable: bool = False
def frag_oid(ino: int, frag: int) -> str          # "%x.%08x"
def walk_namespace(omap_reader, root_ino=ROOT_INO):
    """Yields WalkEntry depth-first. omap_reader(oid, start_after) ->
    (list[(key: bytes, val: bytes)], more: bool)  — abstraction over rados omap paging.
    Counts snap dentries via the returned entries: non-'_head' keys whose last
    '_'-segment is hex. Yields dirs before descending. Undecodable dentry ->
    WalkEntry(kind='file', undecodable=True) for the caller to count+skip."""
def snap_dentry(key: bytes) -> bool
def snaptable_last_snap(buf: bytes) -> int        # u64 version, frame, u64 last_snap; 0 on any DecodeError
```
`walk_namespace` also carries per-entry `snap_dentries` count: expose as generator attribute via a `WalkStats` object passed in: `walk_namespace(omap_reader, stats: WalkStats)` where `@dataclass WalkStats: snap_dentries:int=0; undecodable:int=0`.

- [ ] **Step 1: Write failing tests** — fake omap_reader over an in-memory dict built with the Task-2 synthetic encoder (root dir containing: a file, a subdir with a file, a symlink, a remote dentry, a snap dentry key, one garbage value):

```python
def enc_primary_dentry(v_inode, mode, ino, size=0, symlink=None, nxattrs=0):
    body = enc_inode(v_inode, ino=ino, mode=mode, size=size)
    if (mode & 0o170000) == 0o120000:
        body += struct.pack("<I", len(symlink)) + symlink
    body += struct.pack("<I", 0)                       # empty fragtree
    body += struct.pack("<I", 0)                       # empty xattr map
    return struct.pack("<Q", 2) + b"I" + body          # snapid, 'I' bare InodeStore

def enc_remote_dentry(ino, d_type=8):
    return struct.pack("<Q", 2) + b"L" + struct.pack("<QB", ino, d_type)

def test_walk_namespace():
    from pymigrate.cephfs_meta import walk_namespace, WalkStats, frag_oid
    omaps = {
        frag_oid(1, 0): [
            (b"f1_head", enc_primary_dentry(19, 0o100644, 0x100, size=7)),
            (b"sub_head", enc_primary_dentry(19, 0o040755, 0x200)),
            (b"old_1a_1f", b"whatever"),               # snap dentry: skipped+counted
            (b"bad_head", b"\0\0"),                    # undecodable
        ],
        frag_oid(0x200, 0): [
            (b"f2_head", enc_primary_dentry(19, 0o100644, 0x300, size=9)),
            (b"ln_head", enc_primary_dentry(19, 0o120777, 0x400, symlink=b"f2")),
            (b"hl_head", enc_remote_dentry(0x300)),
        ],
    }
    def rd(oid, start):
        return ([e for e in omaps.get(oid, []) if e[0] > start], False)
    st = WalkStats()
    got = {e.path: e.kind for e in walk_namespace(rd, stats=st) if not e.undecodable}
    assert got == {"/f1": "file", "/sub": "dir", "/sub/f2": "file",
                   "/sub/ln": "symlink", "/sub/hl": "remote"}
    assert st.snap_dentries == 1 and st.undecodable == 1

def test_snaptable_last_snap():
    from pymigrate.cephfs_meta import snaptable_last_snap
    payload = struct.pack("<Q", 5) + b"\1\1" + struct.pack("<I", 8) + struct.pack("<Q", 3)
    assert snaptable_last_snap(payload) == 3
    assert snaptable_last_snap(b"junk") == 0
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** walker (explicit stack of `(ino, frags, path)`, omap paging loop keyed on last key, `_head` suffix filter, kind classification via mode; dirs recurse using the dentry's decoded `frags`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(pymigrate): RADOS namespace walker + snaptable probe`

---

### Task 4: shared CLI plumbing (`pymigrate/common.py`)

**Files:** Create `tests/ceph/pymigrate/common.py`; extend `tests/ceph/test_cephfs_meta.py`.

**Interfaces (Produces):**
```python
def adler32_hex(chunks: Iterable[bytes]) -> str          # zlib.adler32 seed 1, "%08x"
def filter_worklist(items: list[str], list_file: str|None, prefix: str|None, match: str|None) -> list[str]
class StateManifest:                                     # JSONL append-only
    def __init__(self, path: str|None)                   # None -> disabled (all no-ops)
    def done_ok(self, soid, action, mode) -> bool        # latest record ok?
    def record(self, soid, action, mode, result, **extra)  # thread-safe append+flush
class Reporter:
    def __init__(self, json_mode: bool, progress: bool, total: int)
    def item(self, soid, action, result, bytes=0, objects=0, dest=None, error=None)
        # human line ("OK   soid -> dest (n bytes...)") to stdout, or stderr in
        # json mode with JSONL record to stdout; updates counters + progress
    def warn(self, msg)                                  # budget-capped (400) warning
    def summary(self) -> int                             # prints totals; returns exit code 0/1
    counters: ok/skip/fail/bytes  (thread-safe)
def run_parallel(items, fn, threads)                     # ThreadPoolExecutor; fn(item) must not raise
    # fn exceptions are caught -> reporter is the only failure channel; re-raise KeyboardInterrupt
```
Result strings: `"ok" | "skip" | "fail"`. Manifest record: `{"ts", "soid", "action", "mode", "result", ...extra}`. Progress: stderr line every 5 s when enabled (`done/total files, MiB, MiB/s, ETA`), final line always.

- [ ] **Step 1: Write failing tests:**

```python
def test_adler32_hex_seed1():
    from pymigrate.common import adler32_hex
    import zlib
    assert adler32_hex([b"hello ", b"world"]) == "%08x" % zlib.adler32(b"hello world", 1)

def test_filter_worklist(tmp_path):
    from pymigrate.common import filter_worklist
    items = ["rm/a", "rm/b", "cp/x"]
    lf = tmp_path / "l"; lf.write_text("rm/a\r\ncp/x \n\n")
    assert filter_worklist(items, str(lf), None, None) == ["rm/a", "cp/x"]
    assert filter_worklist(items, None, "rm/", None) == ["rm/a", "rm/b"]
    assert filter_worklist(items, None, None, "*/b") == ["rm/b"]
    assert filter_worklist(items, str(lf), "rm/", None) == ["rm/a"]

def test_state_manifest_roundtrip(tmp_path):
    from pymigrate.common import StateManifest
    p = str(tmp_path / "state.jsonl")
    m = StateManifest(p)
    m.record("a", "migrate", "redirect", "fail")
    m.record("a", "migrate", "redirect", "ok")
    m.record("b", "migrate", "redirect", "fail")
    m2 = StateManifest(p)                                # reload
    assert m2.done_ok("a", "migrate", "redirect")
    assert not m2.done_ok("b", "migrate", "redirect")
    assert not m2.done_ok("a", "rollback", "redirect")   # keyed on action too
    assert not StateManifest(None).done_ok("a", "migrate", "redirect")

def test_reporter_json(capsys):
    from pymigrate.common import Reporter
    r = Reporter(json_mode=True, progress=False, total=2)
    r.item("s1", "migrate", "ok", bytes=10, objects=2, dest="/d/s1")
    r.item("s2", "migrate", "fail", error="boom")
    rc = r.summary()
    out = [json.loads(l) for l in capsys.readouterr().out.strip().splitlines()]
    assert out[0]["result"] == "ok" and out[1]["error"] == "boom"
    assert out[-1]["summary"]["ok"] == 1 and out[-1]["summary"]["fail"] == 1
    assert rc == 1
```

- [ ] **Step 2: Run → FAIL.  Step 3: Implement.  Step 4: Run → PASS (all tasks' tests green).**
- [ ] **Step 5: Commit** — `feat(pymigrate): shared CLI plumbing (worklist/state/json/progress/threads)`

---

### Task 5: ctypes bridge (`pymigrate/radosbridge.py`)

**Files:** Create `tests/ceph/pymigrate/radosbridge.py`. Container-verified by script (no host-runnable unit test — needs the cluster; e2e coverage in Task 9).

**Interfaces (Produces):**
```python
class BridgeError(RuntimeError): ...
class ManifestBridge:                                   # context manager
    def __init__(self, conf_path="/etc/ceph/ceph.conf", client="admin",
                 force_shim=None)                       # None -> $PYMIGRATE_FORCE_SHIM
    def close(self)
    def create_stub(self, pool, oid)                    # C API write_op create(idempotent)
    def set_redirect(self, dst_pool, dst_oid, src_pool, src_oid, src_version)
    def copy_from(self, dst_pool, dst_oid, src_pool, src_oid, src_version)
    def tier_promote(self, pool, oid)
    def unset_manifest(self, pool, oid)                 # returns rc; negative tolerated by callers
    def stat(self, pool, oid) -> (size, version)        # rados_stat + get_last_version
    def remove(self, pool, oid)
    def rmxattr(self, pool, oid, name)                  # tolerant
    def self_test(self, scratch_pool)                   # spike round-trip; raises BridgeError
    def striper_read(self, pool, soid, size) -> bytes   # libradosstriper C API
    backend: str                                        # "ctypes" | "shim"
```
Mechanics (verbatim from the proven spike): mangled symbols
```
ctor  _ZN8librados7v14_2_015ObjectOperationC1Ev
dtor  _ZN8librados7v14_2_015ObjectOperationD1Ev
set_redirect  _ZN8librados7v14_2_020ObjectWriteOperation12set_redirectERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS0_5IoCtxEmi
copy_from     _ZN8librados7v14_2_020ObjectWriteOperation9copy_fromERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS0_5IoCtxEmj
tier_promote  _ZN8librados7v14_2_020ObjectWriteOperation12tier_promoteEv
unset_manifest _ZN8librados7v14_2_020ObjectWriteOperation14unset_manifestEv
operate       _ZN8librados7v14_2_05IoCtx7operateERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS0_20ObjectWriteOperationE
```
tried under inline-namespace list `["v14_2_0"]` (single extension point `_ABI_NAMESPACES`); all-or-nothing probe, miss → shim fallback (Task 6) → `BridgeError` naming every symbol tried. Helper structs: `StdString` (CXX11 `{ptr,size,buf[16]}`, SSO self-pointer for <16, kept `create_string_buffer` otherwise), `CxxIoCtx{impl}` fabricated from `rados_ioctx_t`, `OpBuf{vptr,impl}` initialized by the exported base ctor, destroyed by the base dtor. Ioctxs cached per pool; one `Lock` around C++ op build+operate (ops are cheap; contention is on the OSD anyway). `self_test`: write 4 KiB source → stub → redirect → read-through compare → unset_manifest → remove both; any mismatch raises. striper: dlopen `libradosstriper.so.1`, `rados_striper_create/read/destroy` (read loop until size).

- [ ] **Step 1: Write the container check script inline** (bottom of `radosbridge.py`):

```python
if __name__ == "__main__":     # python3 -m pymigrate.radosbridge [scratch_pool]
    import sys
    with ManifestBridge() as b:
        b.self_test(sys.argv[1] if len(sys.argv) > 1 else "xrdtest")
        print(f"radosbridge self-test OK (backend={b.backend})")
```

- [ ] **Step 2: Implement the module** per the interface.
- [ ] **Step 3: Verify in container:**
```bash
docker cp tests/ceph/pymigrate xrd-ceph-work:/work/pymigrate
docker exec -w /work xrd-ceph-work python3 -m pymigrate.radosbridge xrdtest
```
Expected: `radosbridge self-test OK (backend=ctypes)`.
- [ ] **Step 4: Commit** — `feat(pymigrate): ctypes manifest-op bridge + striper read`

---

### Task 6: shim fallback (`pymigrate/shim/rados_manifest_shim.cpp` + loader)

**Files:** Create `tests/ceph/pymigrate/shim/rados_manifest_shim.cpp`; modify `radosbridge.py`.

**Interfaces:** C ABI, all taking `rados_ioctx_t` (the C handle) so Python passes the same pointers either path:
```c
extern "C" {
int shim_set_redirect(rados_ioctx_t dst, const char *dst_oid,
                      rados_ioctx_t src, const char *src_oid, uint64_t ver);
int shim_copy_from(rados_ioctx_t dst, const char *dst_oid,
                   rados_ioctx_t src, const char *src_oid, uint64_t ver);
int shim_tier_promote(rados_ioctx_t io, const char *oid);
int shim_unset_manifest(rados_ioctx_t io, const char *oid);
}
```
Implementation: `librados::IoCtx::from_rados_ioctx_t(h, ioctx)` (public API) + `ObjectWriteOperation` + `operate`. Loader order in `ManifestBridge.__init__` when ctypes probe fails or `force_shim`: (1) `$PYMIGRATE_SHIM` path, (2) `rados_manifest_shim.so` next to the module, (3) compile `g++ -shared -fPIC -std=c++17 rados_manifest_shim.cpp -lrados` into a temp dir **iff** g++ and `<rados/librados.hpp>` exist (el9: package `libradospp-devel`), (4) `BridgeError` listing all remedies. Shim note: `IoCtx::from_rados_ioctx_t` copies share the impl — never let the C++ IoCtx destructor run on them (use pointer/new or `standalone=false` semantics; simplest: heap-allocate and leak per call is unacceptable — instead construct in function scope from the raw impl the same fabricated way, or use the documented static and `ioctx.close()` suppression; implementer: verify with the self-test).

- [ ] **Step 1: Write the shim + loader.**
- [ ] **Step 2: Verify both paths in container:**
```bash
docker exec -w /work xrd-ceph-work bash -c 'dnf -y -q install libradospp-devel 2>/dev/null; PYMIGRATE_FORCE_SHIM=1 python3 -m pymigrate.radosbridge xrdtest'
```
Expected: `radosbridge self-test OK (backend=shim)` (or a clean skip notice if libradospp-devel cannot install — then loader error text is the assertion).
- [ ] **Step 3: Commit** — `feat(pymigrate): compiled C-ABI shim fallback for manifest ops`

---

### Task 7: tool 1 — `xrdceph_striper_migrate.py` (striper → CephFS)

**Files:** Create `tests/ceph/xrdceph_striper_migrate.py` (executable).

**Interfaces (Consumes):** `ManifestBridge`, `common.*`. Uses `rados.Rados`/`Ioctx` (enumeration, xattrs) and `cephfs.LibCephFS` (namespace).

**CLI (superset of C++, spec §5):**
```
xrdceph_striper_migrate.py <striper_pool> <cephfs_data_pool> <dest_prefix>
  [--mode redirect|copy] [--rollback] [--finalize] [--list FILE] [--strip PFX]
  [--threads N=4] [--verify] [--delete-source] [--force] [--dry-run] [--conf PATH]
  [--json] [--state FILE] [--prefix PFX] [--match GLOB] [--progress]
```
Guards: `--delete-source` with redirect mode or `--rollback` → exit 2. Flow:
1. Connect python-rados + LibCephFS(mount "/") + ManifestBridge (skip bridge in pure-dry-run); warn on source pool RADOS snapshots (`Ioctx.list_snaps()` — if binding lacks it, `rados lssnap` is NOT available in-process: use `ioctx.snap_list()`... implementer: python-rados exposes `list_snaps()`; tolerate absence with try/except and skip the warning).
2. **Single indexing pass** over the source pool (`ioctx.list_objects()`): regex `^(?P<soid>.+)\.(?P<idx>[0-9a-f]{16})$` → `index: dict[soid, list[int]]` (sorted). Worklist = index keys (or `--list`), then `filter_worklist`.
3. Per-soid worker `migrate_one/rollback_one/finalize_one` mirroring the C++ functions exactly (geometry from `striper.layout.*`+`striper.size` xattrs of `<soid>.0000000000000000`; layout stamped via `ceph.file.layout.*` fsetxattr before data; redirect stubs `"%x.%08x" % (ino, idx)`; rollback = unset_manifest all stubs then `ceph_unlink`; finalize = tier_promote + unset_manifest + rm striper xattrs; verify = libcephfs read loop → `adler32_hex` vs carried checksum, else size check; carry all `user.*` xattrs; truncate to total; idempotent SKIP on statx size match unless `--force`; state-manifest fast path first).
4. `run_parallel` + `Reporter` + `StateManifest`; exit = `reporter.summary()` (2 for usage).

- [ ] **Step 1: Implement the tool.**
- [ ] **Step 2: Smoke in container** (manual, pre-runner): seed one striper file with existing `/tmp/striper_seed`-style seed (build `striper_seed.c` once), run `--dry-run`, then redirect+verify, confirm `OK`+source objects intact:
```bash
docker exec -w /work/repo xrd-ceph-work bash -c '
  gcc -D_FILE_OFFSET_BITS=64 tests/ceph/striper_seed.c -lradosstriper -lrados -o /tmp/striper_seed
  /tmp/striper_seed xrdtest pysmk/one 6291456 4194304 4194304 1
  python3 tests/ceph/xrdceph_striper_migrate.py xrdtest cephfs_data /pysmk --list <(echo pysmk/one) --verify'
```
Expected: `OK pysmk/one -> /pysmk/pysmk/one (6291456 bytes, 2 redirect, verified)`-style line, exit 0.
- [ ] **Step 3: Commit** — `feat(pymigrate): xrdceph_striper_migrate.py (striper->CephFS, parity+improvements)`

---

### Task 8: tool 2 — `xrdceph_cephfs_to_striper.py` (CephFS → striper)

**Files:** Create `tests/ceph/xrdceph_cephfs_to_striper.py` (executable).

**Interfaces (Consumes):** `ManifestBridge` (incl. `striper_read`), `cephfs_meta.walk_namespace/WalkStats/snaptable_last_snap/frag_oid`, `common.*`. python-rados for omap paging + data-pool index + snaptable read.

**CLI (superset of C++, spec §6):**
```
xrdceph_cephfs_to_striper.py <meta_pool> <cephfs_data_pool> <striper_pool>
  --assume-quiesced [--finalize] [--rollback] [--strip PFX] [--threads N=4]
  [--verify] [--delete-source] [--dry-run] [--report-only] [--conf PATH]
  [--json] [--state FILE] [--prefix PFX] [--match GLOB] [--list FILE] [--progress]
```
Guards: no `--assume-quiesced` → exit 2 with the C++ tool's message; `--delete-source` without `--finalize` → exit 2. Flow:
1. omap_reader adapter over python-rados: `ReadOpCtx` + `get_omap_vals(op, start_after, "", 1024)` + `operate_read_op(op, oid)`.
2. Pass 1 index data pool `<ino_hex>.<objno_hex8>` → `ino -> sorted [objno]`; pass 2 `walk_namespace` collecting `FileEnt(soid, ino, layout, size, cksum)` for regular files in the target pool, classification counters for everything else (hardlink primaries nlink>1 UNVERIFIED warn; aliases/symlinks/specials/other-pool skipped+warned via `Reporter.warn`), snaptable probe, pool-snapshot warning; print the C++-format classification block; `--report-only` stops here (exit 0).
3. Per-file `process()` verbatim from C++: redirect = per objno stub `"%s.%016x" % (soid, objno)` create + set_redirect at `"%x.%08x" % (ino, objno)`, then stamp `striper.layout.{object_size,stripe_unit,stripe_count}` + `striper.size` (+ carried `user.XrdCks.adler32`) on `<soid>.0000000000000000` via python-rados `set_xattr`; idempotency = existing `striper.size` xattr matches (redirect mode only); rollback = unset_manifest+remove per stub; finalize = tier_promote+unset_manifest per stub, `--delete-source` then removes the CephFS data objects; verify = `bridge.striper_read` + `adler32_hex`.
4. Same Reporter/State/parallel/exit contract as tool 1.

- [ ] **Step 1: Implement the tool.**
- [ ] **Step 2: Smoke in container:** seed CephFS via existing seeds + `ceph tell mds.demo flush journal`, then `--assume-quiesced --report-only` (classification sane) and a one-file redirect+verify.
- [ ] **Step 3: Commit** — `feat(pymigrate): xrdceph_cephfs_to_striper.py (CephFS->striper, parity+improvements)`

---

### Task 9: e2e runner — `tests/ceph/run_py_migrate.sh`

**Files:** Create `tests/ceph/run_py_migrate.sh` (host-side, executable), modeled on `run_striper_migrate.sh` (docker cp sources → `docker exec` script with `set -e`).

Coverage checklist (each line an explicit assertion in the script):
- [ ] forward: seed 3 striper files → redirect `--verify` → `OK`×3 AND source objects still present (`rados ls | grep -c`)
- [ ] forward durability: `flush journal` + `cache drop` → `--force --verify` re-OK
- [ ] forward idempotency: rerun → `SKIP`×3
- [ ] forward rollback: overlay gone (`ceph_statx` fails / cephfs ls), sources intact; re-migrate → `OK`
- [ ] forward copy mode + `--delete-source`: source objects 0 after
- [ ] forward guard: redirect + `--delete-source` → exit 2
- [ ] forward `--json`: `python3 -c 'json.loads'` every line; summary totals match
- [ ] forward `--state`: run once with state file; delete one CephFS target; rerun with state → still SKIP (state fast-path); rerun `--force` → re-OK
- [ ] forward `--prefix`: only matching subset migrated
- [ ] forward `PYMIGRATE_FORCE_SHIM=1`: one redirect leg re-run (`--force`), asserts `backend=shim` in stderr banner (skip+notice if shim deps absent)
- [ ] reverse: seed CephFS tree (reuse `cephfs_seed` binaries incl. symlink+hardlink from seed2) + `flush journal` → `--assume-quiesced --report-only`: classification counts match seeded tree
- [ ] reverse redirect + `--verify` (striper_read serves bytes) → rollback (CephFS objects intact) → re-migrate → finalize + `--delete-source` (CephFS data objects gone, striper read still OK)
- [ ] reverse guard: missing `--assume-quiesced` → exit 2
- [ ] runner prints `run_py_migrate: ALL CHECKS PASSED` and exits 0

- [ ] **Step 1: Write the runner.  Step 2: Run `tests/ceph/run_py_migrate.sh` → ALL CHECKS PASSED.**
- [ ] **Step 3: Commit** — `test(pymigrate): Docker e2e runner for both Python migration tools`

---

### Task 10: docs + final sweep

**Files:** Modify `tests/ceph/README.md` (new "Python migration tools" subsection under Recovery & migration: usage of both tools, bridge/shim note incl. `PYMIGRATE_FORCE_SHIM`/`libradospp-devel`, the read-only-until-finalize warning, runner command). Modify `docs/10-reference/xrdceph-cephfs-bidirectional-migration.md` (short "Python implementations" note: identical semantics + extra flags + runner).

- [ ] **Step 1: Write both doc updates.**
- [ ] **Step 2: Final verification sweep:** `python3 -m pytest tests/ceph/test_cephfs_meta.py -v` (all green) AND `tests/ceph/run_py_migrate.sh` (ALL CHECKS PASSED) AND confirm C++ tool files untouched (`git status`).
- [ ] **Step 3: Commit** — `docs(pymigrate): README + reference notes for Python migration tools`

---

## Self-Review Notes

- Spec coverage: §2 layout→Tasks 1–9 files; §3 bridge→5–6 (self-test §3.2 in 5, shim §3.3 in 6, striper §3.4 in 5); §4 decoders→1–3; §5 tool 1→7; §6 tool 2→8; §7 improvements→4 (+7/8 wiring); §8 error handling→each task's guards + Reporter contract; §9 testing→1–4 unit + 9 e2e; §10 docs→10. No gaps.
- Type consistency: `Dentry.kind` strings, `Reporter.item` result strings, `ManifestBridge` method names used identically in Tasks 5–9.
- Known open detail flagged inline (Task 6): shim IoCtx lifetime with `from_rados_ioctx_t` — verified by self-test at implementation time, both fabrication fallbacks documented.
