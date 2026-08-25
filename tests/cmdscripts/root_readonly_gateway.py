"""Proof that a ``brix_read_only`` root:// gateway is read-only ACROSS THE WHOLE
protocol surface, not just at open.

The rig is the documented public-gateway deployment (see
docs/03-configuration/read-only-root-gateway.md): a stock XRootD server holding
the data, and a brix ``brix_root`` stream server in front of it with
``brix_auth none`` (anonymous) + ``brix_read_only on`` +
``brix_storage_backend root://<origin>``.  Five brix instances are started
(plus the origin):

  ro         the documented gateway — read_only on, backed by the XRootD
             origin.  The expansive families in the sibling ``_deep`` module all
             run against this one.
  override   read_only on TOGETHER WITH an explicit ``brix_allow_write on``.
             brix_shared_apply_read_only() must win (INVARIANT 3: allow_write is
             forced off at merge time, before token scope), so the refusal set
             must be identical to ``ro``.
  control    a plain writable local export.  The SAME probe frames run against
             it and must NOT be refused with kXR_fsReadOnly — otherwise a
             malformed frame, not the gate, would be producing the refusals
             above.
  substreams read_only on with ``brix_data_substreams off``.  brix_data_substreams
             merges to ON, so ``ro`` is the posture that ACCEPTS a kXR_bind
             secondary (and must still refuse the bound kXR_write); this is the
             opposite posture, where the bind itself is refused.
  public     ``brix_read_only_public on`` and NOTHING else — no explicit
             brix_read_only.  The stricter posture implies the weaker one in the
             config finaliser, so this instance proves the implication on the
             wire (the mutation battery must be refused exactly as on ``ro``)
             while additionally refusing the kXR_query infotypes that describe
             the server rather than a path.

             There is no manager instance: brix_manager_mode + brix_read_only is
             refused by nginx -t (brix_merge_srv_readonly_role_check), so that
             pair is checked at config time, not by starting a server.

Every mutating opcode the dispatcher knows is probed.  ``mutating_opcodes()``
reads the write-gated route table straight out of
``src/protocols/root/handshake/dispatch_write.c`` and the checks assert the
probe set covers every row, so a new mutating opcode added to the C table
without a probe here fails this test rather than silently widening the public
surface.  The four read-table opcodes that can still mutate (kXR_open in write
mode, kXR_fattr set/del, kXR_prepare with kXR_wmode, kXR_clone) are gated at
their own choke points and are probed explicitly.

That hand-considered probe table is the floor, not the ceiling.  The exhaustive
sweeps — the whole opcode space, the whole kXR_open option space, every
kXR_query infotype, path spellings, pre-login and pre-handshake frames, bound
secondary streams, signing envelopes, concurrency and SIGHUP — live in
cmdscripts/root_readonly_gateway_deep.py and are driven from run_checks() here.

The checks speak XRootD directly over sockets, so the only prerequisites are an
nginx binary with the brix module and (optionally) a stock ``xrootd``; without
xrootd the origin is a brix root:// export instead, which changes nothing about
the gate — every refusal happens at the protocol edge, before the VFS and
before any storage driver is consulted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

import _test_a_robustness_helpers as H

REPO = Path(__file__).resolve().parents[2]
DISPATCH_WRITE_C = REPO / "src/protocols/root/handshake/dispatch_write.c"

XROOTD_BIN = shutil.which("xrootd")

# --- opcodes (src/protocols/root/protocol/opcodes.h) ------------------------
kXR_query, kXR_chmod, kXR_close, kXR_dirlist = 3001, 3002, 3003, 3004
kXR_mkdir, kXR_mv, kXR_set = 3008, 3009, 3018
kXR_open, kXR_chkpoint, kXR_read, kXR_rm = 3010, 3012, 3013, 3014
kXR_rmdir, kXR_sync, kXR_stat, kXR_write = 3015, 3016, 3017, 3019
kXR_fattr, kXR_prepare, kXR_bind, kXR_pgwrite = 3020, 3021, 3024, 3026
kXR_truncate, kXR_sigver, kXR_writev, kXR_clone = 3028, 3029, 3031, 3032
kXR_readv = 3025
kXR_setattr, kXR_symlink, kXR_link = 3500, 3501, 3503

# kXR_open option bits + kXR_prepare options (protocol/flags.h).
kXR_delete, kXR_new, kXR_open_read, kXR_open_updt = 0x0002, 0x0008, 0x0010, 0x0020
kXR_mkpath, kXR_open_apnd, kXR_posc, kXR_open_wrto = 0x0100, 0x0200, 0x1000, 0x8000
kXR_stage, kXR_wmode = 0x08, 0x10

# fattr subcodes (opcodes.h).
kXR_fattrDel, kXR_fattrGet, kXR_fattrList, kXR_fattrSet = 0, 1, 2, 3

kXR_ok, kXR_error = 0, 4003
kXR_NotAuthorized, kXR_Unsupported, kXR_fsReadOnly = 3010, 3013, 3025
kXR_InvalidRequest = 3006


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def mutating_opcodes() -> set[str]:
    """Opcode names in the write-gated route table of dispatch_write.c.

    Every row there passes brix_dispatch_require_write() before its handler, so
    the table IS the enumeration of the mutating surface. Parsing it here keeps
    this test honest as the table grows.
    """
    text = DISPATCH_WRITE_C.read_text(encoding="utf-8")
    table = text.split("brix_wr_routes[] = {", 1)[1].split("\n};", 1)[0]
    return set(re.findall(r"\{\s*(kXR_[a-z]+)\s*,", table))


# --------------------------------------------------------------------------- #
# configs                                                                      #
# --------------------------------------------------------------------------- #

def write_xrootd_config(prefix: Path, port: int) -> tuple[Path, Path, Path]:
    """Stock-XRootD origin config. The admin/pid sockets live in a short /tmp
    directory because AF_UNIX sun_path caps at 108 bytes and a pytest tmp_path
    plus "/admin/.xrd.socket" overruns it."""
    data = prefix / "data"
    data.mkdir(parents=True, exist_ok=True)
    admin = Path(tempfile.mkdtemp(prefix="brix-rogw-adm."))
    conf = prefix / "xrootd.cfg"
    conf.write_text(
        f"xrd.port {port}\n"
        "all.export /\n"
        f"oss.localroot {data}\n"
        f"all.adminpath {admin}\n"
        f"all.pidpath {admin}\n"
        "xrootd.async off\n",
        encoding="utf-8",
    )
    return conf, data, admin


def write_brix_origin_config(prefix: Path, port: int) -> tuple[Path, Path]:
    """Fallback origin when no stock xrootd is installed: a writable brix
    root:// export. The gateway under test cannot tell the difference."""
    data = prefix / "data"
    logs = prefix / "logs"
    for path in (data, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {data};
    brix_auth none; brix_allow_write on; }} }}
""",
        encoding="utf-8",
    )
    return conf, data


def write_gateway_config(prefix: Path, port: int, knobs: str,
                         origin_port: int | None) -> Path:
    """The documented gateway. ``knobs`` carries the posture under test; the
    rest is verbatim what docs/03-configuration/read-only-root-gateway.md
    publishes."""
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    backend = (f"    brix_storage_backend root://{HOST}:{origin_port};\n"
               f"    brix_cache_store posix:{cache};\n") if origin_port else ""
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {export};
    brix_auth none;
{knobs}{backend}}} }}
""",
        encoding="utf-8",
    )
    return conf


# --------------------------------------------------------------------------- #
# wire helpers                                                                 #
# --------------------------------------------------------------------------- #

def _session(port: int) -> socket.socket:
    s = socket.create_connection((HOST, port), timeout=8)
    s.settimeout(8)
    if H._full_anon_login(s) != (0, 0, 0):
        s.close()
        raise RuntimeError(f"anonymous login to :{port} failed")
    return s


def _send(s: socket.socket, opcode: int, body: bytes, payload: bytes = b"",
          trailer: bytes = b"") -> tuple[int, bytes]:
    """kXR_writev frames ONLY its 16-byte segment descriptors in dlen; the
    segment data rides on the wire after the dlen-framed region — hence
    ``trailer``."""
    s.sendall(H.make_request(b"\x00\x07", opcode, body, payload) + trailer)
    return H._recv_response(s)


def _errnum(body: bytes) -> int | None:
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _errmsg(body: bytes) -> str:
    return body[4:].split(b"\x00")[0].decode("utf-8", "replace")


def _open_read(s: socket.socket, path: bytes) -> bytes:
    st, body = _send(s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), path)
    if st != kXR_ok:
        raise RuntimeError(f"read-open {path!r} failed: {st} {_errmsg(body)}")
    return body[:4]


# --------------------------------------------------------------------------- #
# the probe table                                                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Probe:
    name: str
    opcode: int
    body: bytes
    payload: bytes = b""
    trailer: bytes = b""
    #: seed tree this probe needs in the export/origin root before it runs
    seed_files: tuple[str, ...] = ()
    seed_dirs: tuple[str, ...] = ()
    #: substitute a real writable handle into body[0:4] when one is obtainable
    wants_write_handle: bool = False
    #: on a writable server this probe must return kXR_ok (not merely "not
    #: refused") — proves the frame is well-formed and really does mutate
    must_succeed_when_writable: bool = True


def _open_probe(name: str, options: int, path: str, *, mode: int = 0o644,
                seed_files: tuple[str, ...] = (),
                must_succeed: bool = True) -> Probe:
    return Probe(name, kXR_open, struct.pack(">HH12x", mode, options),
                 path.encode(), seed_files=seed_files,
                 must_succeed_when_writable=must_succeed)


def _fattr_body(subcode: int, numattr: int) -> bytes:
    """fattr body: fhandle[4] subcode[1] numattr[1] options[1] reserved[9]."""
    return b"\x00" * 4 + bytes([subcode, numattr, 0]) + b"\x00" * 9


def probes() -> list[Probe]:
    return [
        # -- kXR_open in every write mode (read/open_request.c mode guard) ----
        _open_probe("open create-new", kXR_open_updt | kXR_new, "/ro_new.dat"),
        _open_probe("open truncate", kXR_open_updt | kXR_delete, "/ro_trunc.dat",
                    seed_files=("/ro_trunc.dat",)),
        _open_probe("open update", kXR_open_updt, "/ro_updt.dat",
                    seed_files=("/ro_updt.dat",)),
        _open_probe("open append", kXR_open_apnd, "/ro_apnd.dat",
                    seed_files=("/ro_apnd.dat",)),
        _open_probe("open wrto", kXR_open_wrto, "/ro_wrto.dat",
                    seed_files=("/ro_wrto.dat",)),
        _open_probe("open mkpath+new", kXR_open_updt | kXR_new | kXR_mkpath,
                    "/ro_mk/deep/nest.dat"),
        _open_probe("open posc+new", kXR_open_updt | kXR_new | kXR_posc,
                    "/ro_posc.dat"),
        # A TPC destination open pulls bytes IN; on a writable server it fails
        # for want of a reachable source, so only the refusal code is asserted.
        _open_probe("open tpc-destination", kXR_open_updt | kXR_new,
                    "/ro_tpc.dat?tpc.src=root://127.0.0.1:1//x&tpc.key=k",  # net-literal-allow: unreachable TPC source (port 1); only the refusal is asserted
                    must_succeed=False),

        # -- namespace mutations (dispatch_write.c path handlers) ------------
        Probe("mkdir", kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/ro_mkdir"),
        Probe("rm", kXR_rm, b"\x00" * 16, b"/ro_rm.dat", seed_files=("/ro_rm.dat",)),
        Probe("rmdir", kXR_rmdir, b"\x00" * 16, b"/ro_rmdir",
              seed_dirs=("/ro_rmdir",)),
        Probe("mv", kXR_mv, b"\x00" * 14 + struct.pack(">h", len("/ro_mv_src.dat")),
              b"/ro_mv_src.dat /ro_mv_dst.dat", seed_files=("/ro_mv_src.dat",)),
        Probe("chmod", kXR_chmod, struct.pack(">14xH", 0o777), b"/ro_chmod.dat",
              seed_files=("/ro_chmod.dat",)),
        Probe("truncate (by path)", kXR_truncate, struct.pack(">4xq4x", 4),
              b"/ro_size.dat", seed_files=("/ro_size.dat",)),

        # -- handle data writes ----------------------------------------------
        # On a read-only server NO writable handle can exist, so these carry
        # handle 0; the gate must still answer kXR_fsReadOnly (a kXR_FileNotOpen
        # here would mean the handle check, not the gate, produced the refusal).
        Probe("write", kXR_write, b"\x00" * 4 + struct.pack(">q4x", 0), b"X" * 8,
              wants_write_handle=True),
        Probe("pgwrite", kXR_pgwrite, b"\x00" * 4 + struct.pack(">q4x", 0),
              b"X" * 8, wants_write_handle=True, must_succeed_when_writable=False),
        Probe("writev", kXR_writev, b"\x00" * 16,
              struct.pack(">4siq", b"\x00" * 4, 8, 0), trailer=b"X" * 8,
              wants_write_handle=True, must_succeed_when_writable=False),
        Probe("sync", kXR_sync, b"\x00" * 16, wants_write_handle=True),
        Probe("chkpoint", kXR_chkpoint, b"\x00" * 4 + struct.pack(">11xB", 0),
              wants_write_handle=True, must_succeed_when_writable=False),

        # -- extended attributes (fattr/dispatch.c allow_write gate) ---------
        Probe("fattr set", kXR_fattr, _fattr_body(kXR_fattrSet, 1),
              b"/ro_fattr.dat\x00user.brixprobe\x00" + struct.pack(">H", 4) + b"evil",
              seed_files=("/ro_fattr.dat",), must_succeed_when_writable=False),
        Probe("fattr del", kXR_fattr, _fattr_body(kXR_fattrDel, 1),
              b"/ro_fattr.dat\x00user.brixprobe\x00",
              seed_files=("/ro_fattr.dat",), must_succeed_when_writable=False),

        # -- vendor POSIX-completeness extensions (capability "xrdfs.ext") ---
        Probe("setattr", kXR_setattr, b"\x00" * 16,
              struct.pack(">iqqqqii", 0x01, 0, 0, 1_700_000_000, 0, -1, -1)
              + b"/ro_setattr.dat\x00", seed_files=("/ro_setattr.dat",)),
        Probe("symlink", kXR_symlink,
              b"\x00" * 14 + struct.pack(">h", len("/ro_link.dat")),
              b"/ro_link.dat /ro_symlink", seed_files=("/ro_link.dat",)),
        Probe("link", kXR_link,
              b"\x00" * 14 + struct.pack(">h", len("/ro_link.dat")),
              b"/ro_link.dat /ro_hardlink", seed_files=("/ro_link.dat",)),

        # -- prepare in write mode (query/prepare.c) -------------------------
        # prepare body: options[1] prty[1] port[2] reserved[12]
        # prepare carries a NEWLINE-SEPARATED path list, not a bare path.
        Probe("prepare wmode", kXR_prepare,
              struct.pack(">BBH12x", kXR_wmode, 0, 0), b"/ro_prep.dat\n",
              seed_files=("/ro_prep.dat",), must_succeed_when_writable=False),
    ]


#: served by every gateway; never a mutation target, so a successful read of it
#: after the whole probe run proves the export is still intact.
PUBLIC_FILE = "/public.txt"
PUBLIC_PAYLOAD = b"public payload for the read-only gateway probe\n"


def seed_tree(root: Path) -> None:
    """Materialise every path the probe table needs, plus the public read file."""
    root.mkdir(parents=True, exist_ok=True)
    (root / PUBLIC_FILE.lstrip("/")).write_bytes(PUBLIC_PAYLOAD)
    (root / "ro_clone.dat").write_bytes(PUBLIC_PAYLOAD)
    for probe in probes():
        for rel in probe.seed_files:
            target = root / rel.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(PUBLIC_PAYLOAD)
        for rel in probe.seed_dirs:
            (root / rel.lstrip("/")).mkdir(parents=True, exist_ok=True)


def tree_snapshot(root: Path) -> set[str]:
    """Relative paths under ``root``, for the untouched-origin assertion."""
    return {str(p.relative_to(root)) for p in root.rglob("*")}


# The runtime checks and orchestration live in a continuation so each source
# file remains small enough to review as one cohesive unit.
from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "root_readonly_gateway_part2.py")
