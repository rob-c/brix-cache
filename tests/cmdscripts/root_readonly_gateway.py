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
                    "/ro_tpc.dat?tpc.src=root://127.0.0.1:1//x&tpc.key=k",
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


# --------------------------------------------------------------------------- #
# checks                                                                       #
# --------------------------------------------------------------------------- #

def _check_table_is_covered(results: list[tuple[bool, str]]) -> None:
    """The probe set must cover every row of the C write-gated route table."""
    probed = {p.opcode for p in probes()} | {kXR_clone}
    names = {
        "kXR_write": kXR_write, "kXR_pgwrite": kXR_pgwrite, "kXR_sync": kXR_sync,
        "kXR_truncate": kXR_truncate, "kXR_mkdir": kXR_mkdir, "kXR_rm": kXR_rm,
        "kXR_writev": kXR_writev, "kXR_rmdir": kXR_rmdir, "kXR_mv": kXR_mv,
        "kXR_chmod": kXR_chmod, "kXR_chkpoint": kXR_chkpoint,
        "kXR_setattr": kXR_setattr, "kXR_symlink": kXR_symlink,
        "kXR_link": kXR_link,
    }
    try:
        table = mutating_opcodes()
    except (OSError, IndexError):
        results.append((False, "dispatch_write.c route table is parseable"))
        return
    results.append((bool(table), "dispatch_write.c route table is parseable"))
    unknown = sorted(table - set(names))
    results.append((not unknown,
                    f"every write-gated opcode has a numeric mapping here "
                    f"(unmapped: {unknown})"))
    missing = sorted(name for name in table & set(names)
                     if names[name] not in probed)
    results.append((not missing,
                    f"every write-gated opcode is probed (unprobed: {missing})"))


DOC_PAGE = REPO / "docs/03-configuration/read-only-root-gateway.md"


def _doc_nginx_blocks() -> list[str]:
    """Every ```nginx fenced block in the documentation page."""
    text = DOC_PAGE.read_text(encoding="utf-8")
    return re.findall(r"```nginx\n(.*?)```", text, re.S)


def _check_doc_configs_parse(base: Path, nginx_bin: str,
                             results: list[tuple[bool, str]]) -> None:
    """The published example configs must survive ``nginx -t``.

    The page is the deliverable; a directive that has been renamed or that never
    existed has to fail HERE rather than in an operator's terminal.  Paths and
    the listen port are rewritten to the scratch tree; a self-signed pair backs
    the TLS block.
    """
    blocks = _doc_nginx_blocks()
    results.append((len(blocks) >= 2,
                    f"documentation page publishes nginx config blocks "
                    f"(found {len(blocks)})"))
    work = base / "docparse"
    for name in ("export", "cache", "logs", "tls"):
        (work / name).mkdir(parents=True, exist_ok=True)
    crt, key = work / "tls/gw.crt", work / "tls/gw.key"
    have_tls = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(crt), "-days", "2", "-nodes", "-subj", "/CN=brix-doc"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    for index, block in enumerate(blocks):
        if "brix_root" not in block:
            continue                        # the XRootD origin config, not ours
        if "brix_certificate" in block and not have_tls:
            results.append((True, f"doc config block {index}: skipped "
                                  f"(openssl unavailable for the TLS block)"))
            continue
        conf = (block
                .replace("/var/lib/brix/export", str(work / "export"))
                .replace("/var/cache/brix", str(work / "cache"))
                .replace("/etc/brix/tls/gateway.crt", str(crt))
                .replace("/etc/brix/tls/gateway.key", str(key)))
        if "events" not in conf:
            conf = "events { worker_connections 64; }\n" + conf
        path = work / f"block{index}.conf"
        path.write_text(f"error_log {work / 'logs/e.log'} info;\n"
                        f"pid {work / 'nginx.pid'};\n" + conf, encoding="utf-8")
        result = run([nginx_bin, "-p", str(work), "-c", str(path), "-t"])
        # A doc block binds the privileged default port; only the bind is
        # expected to fail, never the parse.
        output = (result.stderr or "") + (result.stdout or "")
        parsed = "syntax is ok" in output
        results.append((parsed, f"doc config block {index} passes nginx -t "
                                f"({output.strip()[-300:]})"))


def _run_probes(port: int, writable: bool) -> list[tuple[Probe, int, bytes]]:
    """Fire the whole table at one server. Each probe gets a fresh session so a
    refusal (or a state change) never leaks into the next one."""
    out = []
    for probe in probes():
        s = _session(port)
        try:
            body16 = probe.body
            payload = probe.payload
            if probe.wants_write_handle and writable:
                st, resp = _send(s, kXR_open,
                                 struct.pack(">HH12x", 0o644,
                                             kXR_open_updt | kXR_new | kXR_delete),
                                 b"/ro_handle.dat")
                if st == kXR_ok:
                    fh = resp[:4]
                    body16 = fh + body16[4:]
                    if probe.opcode == kXR_writev:
                        payload = struct.pack(">4siq", fh, 8, 0)
            status, resp = _send(s, probe.opcode, body16, payload, probe.trailer)
            out.append((probe, status, resp))
        finally:
            s.close()
    return out


def _check_read_only_surface(port: int, label: str,
                             results: list[tuple[bool, str]]) -> None:
    refused = []
    for probe, status, body in _run_probes(port, writable=False):
        ok = status == kXR_error and _errnum(body) == kXR_fsReadOnly
        if ok:
            refused.append(probe.name)
        results.append((ok, f"{label}: {probe.name} -> kXR_fsReadOnly "
                            f"(got status={status} err={_errnum(body)} "
                            f"{_errmsg(body)!r})"))
    results.append((len(refused) == len(probes()),
                    f"{label}: all {len(probes())} mutating probes refused"))


def _check_clone_refused(port: int, label: str,
                         results: list[tuple[bool, str]]) -> None:
    """kXR_clone is gated by brix_validate_write_handle, not by the write gate:
    its refusal is DERIVED from the fact that no writable handle can be opened.
    Probe it with a genuine READ handle as the clone destination, otherwise a
    kXR_FileNotOpen on an unopened handle would prove nothing."""
    s = _session(port)
    try:
        fh = _open_read(s, PUBLIC_FILE.encode())
        status, body = _send(s, kXR_clone, fh + b"\x00" * 12,
                             struct.pack(">4s4xQQQ", fh, 0, 8, 0))
        results.append((status == kXR_error and _errnum(body) == kXR_NotAuthorized,
                        f"{label}: clone onto an open READ handle -> "
                        f"kXR_NotAuthorized ({_errmsg(body)!r})"))
    finally:
        s.close()


def _check_reads_work(port: int, label: str,
                      results: list[tuple[bool, str]]) -> None:
    """A read-only gateway must still be a fully functional read gateway."""
    s = _session(port)
    try:
        st, body = _send(s, kXR_open,
                         struct.pack(">HH12x", 0, kXR_open_read),
                         PUBLIC_FILE.encode())
        results.append((st == kXR_ok, f"{label}: read-open succeeds"))
        if st == kXR_ok:
            st, data = _send(s, kXR_read,
                             body[:4] + struct.pack(">qi", 0, len(PUBLIC_PAYLOAD)))
            results.append((st == kXR_ok and data == PUBLIC_PAYLOAD,
                            f"{label}: read returns the origin bytes"))
        # NB: the stat `flags` field is derived from POSIX mode bits against the
        # server's effective uid (brix_stat_flags_from_stat), NOT from
        # brix_read_only — a client must not infer the posture from it.
        st, body = _send(s, kXR_stat, b"\x00" * 16, PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok, f"{label}: stat succeeds"))
        st, _ = _send(s, kXR_dirlist, b"\x00" * 16, b"/\x00")
        results.append((st == kXR_ok, f"{label}: dirlist succeeds"))
        st, body = _send(s, kXR_fattr, _fattr_body(kXR_fattrList, 0),
                         PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok, f"{label}: fattr list (read side) succeeds"))
        # The read-only gate on kXR_prepare is scoped to kXR_wmode; a plain
        # stage hint must not draw it.  (Its path scan runs against the LOCAL
        # export, not the backend, so a backend-only path answers "file not
        # found" here — a pre-existing scoping quirk, not the read-only gate.)
        st, body = _send(s, kXR_prepare,
                         struct.pack(">BBH12x", kXR_stage, 0, 0),
                         PUBLIC_FILE.encode() + b"\n")
        results.append((_errnum(body) != kXR_fsReadOnly if st == kXR_error
                        else True,
                        f"{label}: prepare WITHOUT kXR_wmode is not refused as "
                        f"read-only (status={st} {_errmsg(body)!r})"))
    finally:
        s.close()


def _check_control_is_not_refusing(port: int,
                                   results: list[tuple[bool, str]]) -> None:
    """Security-negative control: the identical frames against a WRITABLE server
    must never draw kXR_fsReadOnly, and the core mutations must actually land —
    so the refusals above are the gate, not a malformed probe."""
    misrefused, failed = [], []
    for probe, status, body in _run_probes(port, writable=True):
        if status == kXR_error and _errnum(body) == kXR_fsReadOnly:
            misrefused.append(probe.name)
        if probe.must_succeed_when_writable and status != kXR_ok:
            failed.append(f"{probe.name}({status}/{_errnum(body)}"
                          f":{_errmsg(body)})")
    results.append((not misrefused,
                    f"control: no probe draws kXR_fsReadOnly on a writable "
                    f"server (drew: {misrefused})"))
    results.append((not failed,
                    f"control: every well-formed mutation succeeds when writes "
                    f"are allowed (failed: {failed})"))


def _check_origin_untouched(origin_root: Path, before: set[str],
                            results: list[tuple[bool, str]]) -> None:
    after = tree_snapshot(origin_root)
    added = sorted(after - before)
    removed = sorted(before - after)
    results.append((not added and not removed,
                    f"origin tree is byte-for-byte unchanged after the whole "
                    f"probe run (added={added} removed={removed})"))
    public = origin_root / PUBLIC_FILE.lstrip("/")
    results.append((public.read_bytes() == PUBLIC_PAYLOAD,
                    "origin public file content is unchanged"))


# --------------------------------------------------------------------------- #
# runner                                                                       #
# --------------------------------------------------------------------------- #

def _wait(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@dataclass
class _Rig:
    """Everything started by run_checks, so teardown is one call."""
    nginx_prefixes: list[Path] = field(default_factory=list)
    procs: list[subprocess.Popen] = field(default_factory=list)
    tmpdirs: list[Path] = field(default_factory=list)

    def close(self) -> None:
        for prefix in reversed(self.nginx_prefixes):
            stop_nginx(prefix)
        for proc in self.procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for path in self.tmpdirs:
            shutil.rmtree(path, ignore_errors=True)


def _start_origin(base: Path, port: int, rig: _Rig) -> tuple[Path, str]:
    """Prefer the stock XRootD server — that is the documented deployment. Fall
    back to a writable brix root:// export where xrootd is not installed."""
    prefix = base / "origin"
    if XROOTD_BIN:
        conf, data, admin = write_xrootd_config(prefix, port)
        rig.tmpdirs.append(admin)
        seed_tree(data)
        proc = subprocess.Popen(
            [XROOTD_BIN, "-c", str(conf), "-l", str(prefix / "xrootd.log")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        rig.procs.append(proc)
        if _wait(port):
            return data, "stock xrootd"
        rig.procs.remove(proc)
        proc.terminate()
    conf, data = write_brix_origin_config(prefix, port)
    seed_tree(data)
    result = run([NGINX_BIN, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        raise RuntimeError(f"brix origin start failed: "
                           f"{(result.stderr or result.stdout)[-2000:]}")
    rig.nginx_prefixes.append(prefix)
    if not _wait(port):
        raise RuntimeError("brix origin never accepted a connection")
    return data, "brix root:// export"


def _start_gateway(base: Path, name: str, port: int, knobs: str,
                   origin_port: int | None, nginx_bin: str,
                   rig: _Rig) -> tuple[Path, Path]:
    """Start one gateway posture. Returns (prefix, export) — the prefix carries
    nginx.pid, which the reload-persistence check needs."""
    prefix = base / name
    conf = write_gateway_config(prefix, port, knobs, origin_port)
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        raise RuntimeError(f"{name} gateway start failed: "
                           f"{(result.stderr or result.stdout)[-2000:]}")
    rig.nginx_prefixes.append(prefix)
    if not _wait(port):
        raise RuntimeError(f"{name} gateway never accepted a connection")
    return prefix, prefix / "export"


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    # The deep families import this module for its wire helpers and probe table,
    # so the import lives here rather than at module scope (plain cycle break).
    from cmdscripts.root_readonly_gateway_deep import (check_override_is_logged,
                                                       run_deep_checks)

    (origin_port, ro_port, ov_port, ctl_port,
     sub_port, pub_port) = cmdscript_ports("root_readonly_gateway", 6)
    rig = _Rig()
    results: list[tuple[bool, str]] = []
    try:
        origin_root, origin_kind = _start_origin(base, origin_port, rig)
        results.append((True, f"origin is {origin_kind} on :{origin_port}"))

        ro_prefix, ro_export = _start_gateway(
            base, "ro", ro_port, "    brix_read_only on;\n",
            origin_port, nginx_bin, rig)
        ov_prefix, _ = _start_gateway(
            base, "override", ov_port,
            "    brix_allow_write on;\n    brix_read_only on;\n",
            origin_port, nginx_bin, rig)
        _, control_export = _start_gateway(base, "control", ctl_port,
                                           "    brix_allow_write on;\n",
                                           None, nginx_bin, rig)
        seed_tree(control_export)
        # brix_data_substreams merges to ON, so the documented gateway above
        # already accepts a kXR_bind secondary — the one route by which a bare
        # kXR_write reaches the gate without an open on the same connection.
        # This instance is the opposite posture: substreams explicitly off, so
        # the narrower surface is asserted too.
        _start_gateway(base, "substreams", sub_port,
                       "    brix_read_only on;\n"
                       "    brix_data_substreams off;\n",
                       origin_port, nginx_bin, rig)
        # brix_read_only_public: the same read-only guarantee PLUS the
        # introspection restrictions.  A separate instance because the whole
        # point is that the two postures differ on the kXR_query surface and
        # NOWHERE else — the mutation battery must produce identical results.
        pub_prefix, pub_export = _start_gateway(
            base, "public", pub_port, "    brix_read_only_public on;\n",
            origin_port, nginx_bin, rig)

        before = tree_snapshot(origin_root)
        _check_doc_configs_parse(base, nginx_bin, results)
        _check_table_is_covered(results)
        for port, label in ((ro_port, "read_only"),
                            (ov_port, "read_only+allow_write"),
                            (pub_port, "read_only_public")):
            _check_read_only_surface(port, label, results)
            _check_clone_refused(port, label, results)
            _check_reads_work(port, label, results)
        _check_control_is_not_refusing(ctl_port, results)
        check_override_is_logged(nginx_bin, ov_prefix,
                                 ov_prefix / "nginx.conf", results, run)
        run_deep_checks(ro_port=ro_port, ro_prefix=ro_prefix, sub_port=sub_port,
                        pub_port=pub_port, pub_export=pub_export,
                        pub_prefix=pub_prefix, nginx_bin=nginx_bin,
                        base=base, origin_root=origin_root,
                        export_root=ro_export, results=results)
        _check_origin_untouched(origin_root, before, results)
        return results
    except Exception as exc:                          # rig failure -> one row
        results.append((False, f"rig failure: {exc}"))
        return results
    finally:
        rig.close()


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    with tempfile.TemporaryDirectory(prefix="root_readonly_gateway.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_root_readonly_gateway: ALL PASS")
        return 0
    print("run_root_readonly_gateway: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
