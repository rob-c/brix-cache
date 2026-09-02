"""Phase-107 C1 — the writer's reorder spill, live over both staged-only drivers.

The VFS writer used to refuse any staged write whose offset was not the staged
cursor (`EINVAL`, pre-W2 `vfs_writer.c`).  W2 replaced the refusal with a local
spill: out-of-order extents land in a private scratch file under the export's
registered spill root, and commit drains them into the staged session in
strictly sequential order.  These are the five contract rows from
docs/refactor/phase-107-vfs-mutation-surface-completion.md §4/C1:

  success   reverse-order kXR_write over `remote` and `http` fronts lands the
            object byte-exact (the scratch existed mid-flight, and was
            unlinked by the commit);
  success   in-order writes never create a spill file at all;
  error     `brix_vfs_spill_max 1m` + a 4 MiB reordered upload refuses
            `ENOSPC` -> kXR_NoSpace, and publishes NOTHING;
  sec-neg   a read-only front refuses the write open BEFORE any spill file is
            created — asserted by listing the spill root, not only the errno;
  sec-neg   `brix_vfs_spill_path` inside an export root (plus the relative
            path and the sub-1m cap) is refused at `nginx -t`.

The C object unit (tests/c/test_vfs_writer_spill.c, `vfs_writer_spill` in
cmdscripts/c_object_units.py) proves the state machine's edges hermetically;
this file proves the wire-to-origin composition.  Instance topology in
tests/configs/nginx_p107_spill.conf.
"""
import hashlib
import os
import pathlib
import subprocess
import tempfile

import pytest

from XRootD import client
from XRootD.client.flags import OpenFlags

from _xrdcl_proxy import real_bindings_available
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p107-spill"),
              pytest.mark.skipif(
                  not real_bindings_available(),
                  reason="real libXrdCl bindings unavailable")]

SPEC = "lc-p107-spill"
MIB = 1024 * 1024
S3_AK = "AKIDP107SPILLTEST1"
S3_SK = "cDEwNy1zcGlsbC13cml0ZXItcmVvcmRlci1zZWNyZXQ"


def _bytes(n: int, seed: int) -> bytes:
    """Deterministic, non-repeating payload: a chunk-wise constant pattern
    would let a drain that permutes whole chunks pass unnoticed."""
    return bytes(((i * 37) + (i >> 12) * 11 + seed) & 0xFF for i in range(n))


def _files_under(root) -> list:
    return sorted(str(p) for p in pathlib.Path(root).rglob("*") if p.is_file())


def _need_nginx() -> None:
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


@pytest.fixture(scope="module")
def spill_srv(tmp_path_factory):
    """One instance, four fronts + two origins (see nginx_p107_spill.conf)."""
    _need_nginx()
    base = tmp_path_factory.mktemp("p107-spill")
    dirs = {name: base / name for name in (
        "s3store", "http_origin", "exp_remote", "exp_http", "exp_capped",
        "exp_ro", "spill_remote", "spill_http", "spill_capped", "spill_ro")}
    for d in dirs.values():
        d.mkdir()
    (dirs["s3store"] / "testbucket").mkdir()
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_p107_spill.conf",
            protocol="root",
            data_root=str(dirs["http_origin"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "S3_DIR": str(dirs["s3store"]),
                "S3_ACCESS_KEY": S3_AK,
                "S3_SECRET_KEY": S3_SK,
                "HTTP_ORIGIN_ROOT": str(dirs["http_origin"]),
                "REMOTE_EXPORT": str(dirs["exp_remote"]),
                "HTTP_EXPORT": str(dirs["exp_http"]),
                "CAPPED_EXPORT": str(dirs["exp_capped"]),
                "RO_EXPORT": str(dirs["exp_ro"]),
                "SPILL_REMOTE": str(dirs["spill_remote"]),
                "SPILL_HTTP": str(dirs["spill_http"]),
                "SPILL_CAPPED": str(dirs["spill_capped"]),
                "SPILL_RO": str(dirs["spill_ro"]),
            },
            reason="phase-107 C1 reorder spill over http + s3 staged fronts"))
        yield {"port": ep.port, "extras": ep.extra_ports, "dirs": dirs}
    finally:
        harness.close()


def _url(port: int, path: str) -> str:
    return f"root://{HOST}:{port}/{path.lstrip('/')}"


def _reverse_upload(port: int, name: str, data: bytes, spill_dir,
                    chunk: int = MIB) -> None:
    """Write `data` in strictly reverse chunk order; assert the scratch file
    appears once out-of-order bytes exist and is gone after the commit."""
    f = client.File()
    status, _ = f.open(_url(port, name), OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    offsets = list(range(0, len(data), chunk))[::-1]
    for i, off in enumerate(offsets):
        status, _ = f.write(data[off:off + chunk], off)
        assert status.ok, (
            f"reordered write at {off} refused: {status.message}")
        if i == 1:
            # Two out-of-order extents are in flight: the spill scratch must
            # exist NOW (owned-temp named), or the bytes went somewhere else.
            names = _files_under(spill_dir)
            assert names and all(".xrd-tmp." in n for n in names), (
                f"no owned-temp spill scratch under {spill_dir}: {names}")
    status, _ = f.close()
    assert status.ok, f"commit close failed: {status.message}"
    assert _files_under(spill_dir) == [], (
        "spill scratch survived the commit — the drain must unlink it")


def _download(port: int, name: str) -> bytes:
    f = client.File()
    status, _ = f.open(_url(port, name), OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"
    try:
        chunks, off = [], 0
        while True:
            status, data = f.read(offset=off, size=8 * MIB)
            assert status.ok, f"read failed: {status.message}"
            if not data:
                break
            chunks.append(bytes(data))
            off += len(data)
        return b"".join(chunks)
    finally:
        f.close()


# --------------------------------------------------------------------------- #
# success                                                                      #
# --------------------------------------------------------------------------- #
def test_reverse_order_http_is_byte_exact(spill_srv):
    """8 MiB in reverse 1 MiB chunks over the http (sd_http) front."""
    data = _bytes(8 * MIB, 3)
    _reverse_upload(spill_srv["port"], "/rev8.bin", data,
                    spill_srv["dirs"]["spill_http"])
    got = _download(spill_srv["port"], "/rev8.bin")
    assert hashlib.md5(got).hexdigest() == hashlib.md5(data).hexdigest(), (
        "reverse-order upload over http is not byte-identical")
    # The staged commit PUT the whole object to the WebDAV posix origin.
    landed = spill_srv["dirs"]["http_origin"] / "rev8.bin"
    assert landed.read_bytes() == data


def test_reverse_order_remote_is_byte_exact(spill_srv):
    """The same contract over the remote (s3://, sd_remote) driver.  Byte-
    exactness is asserted at the S3 store itself: the brix_s3-over-posix
    origin stores objects FLAT under its root (nginx_root_s3_staged.conf
    precedent), and the commit is a single signed PUT of the drained bytes."""
    port = spill_srv["extras"]["REMOTE_PORT"]
    data = _bytes(4 * MIB, 11)
    _reverse_upload(port, "/rev4.bin", data,
                    spill_srv["dirs"]["spill_remote"])
    landed = spill_srv["dirs"]["s3store"] / "rev4.bin"
    assert landed.exists(), "the staged commit published nothing to the store"
    assert hashlib.md5(landed.read_bytes()).hexdigest() \
        == hashlib.md5(data).hexdigest(), (
        "reverse-order upload over remote/s3 is not byte-identical")


def test_in_order_writes_never_create_a_spill(spill_srv):
    """Sequential writes must stay in SEQUENTIAL mode: no scratch, ever."""
    data = _bytes(4 * MIB, 5)
    spill_dir = spill_srv["dirs"]["spill_http"]
    f = client.File()
    status, _ = f.open(_url(spill_srv["port"], "/seq4.bin"),
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    for off in range(0, len(data), MIB):
        status, _ = f.write(data[off:off + MIB], off)
        assert status.ok, f"in-order write at {off} failed: {status.message}"
        assert _files_under(spill_dir) == [], (
            "an in-order write created a spill scratch")
    status, _ = f.close()
    assert status.ok, f"close failed: {status.message}"
    landed = spill_srv["dirs"]["http_origin"] / "seq4.bin"
    assert landed.read_bytes() == data


# --------------------------------------------------------------------------- #
# error                                                                        #
# --------------------------------------------------------------------------- #
def test_spill_max_refuses_enospc_and_publishes_nothing(spill_srv):
    """brix_vfs_spill_max 1m + a 4 MiB reorder: ENOSPC -> kXR_NoSpace, the
    scratch is unlinked (T4) and NO object reaches the origin."""
    port = spill_srv["extras"]["CAPPED_PORT"]
    spill_dir = spill_srv["dirs"]["spill_capped"]
    f = client.File()
    status, _ = f.open(_url(port, "/cap4.bin"),
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    # First extent at 3 MiB: the spill would have to reserve a 4 MiB span,
    # four times the cap — refused at entry, before any staged byte exists.
    status, _ = f.write(_bytes(MIB, 9), 3 * MIB)
    assert not status.ok, "a reorder past brix_vfs_spill_max was accepted"
    assert "space" in status.message.lower(), (
        f"want the kXR_NoSpace/ENOSPC text, got: {status.message}")
    f.close()
    assert _files_under(spill_dir) == [], (
        "the refused spill left a scratch file behind")
    assert not (spill_srv["dirs"]["http_origin"] / "cap4.bin").exists(), (
        "a refused reordered upload still published an object")


# --------------------------------------------------------------------------- #
# security-negative                                                            #
# --------------------------------------------------------------------------- #
def test_read_only_front_reaches_no_spill(spill_srv):
    """The phase-105 gate refuses BEFORE the writer exists: the spill root
    must stay empty no matter what a client attempts."""
    port = spill_srv["extras"]["RO_PORT"]
    f = client.File()
    status, _ = f.open(_url(port, "/ro.bin"), OpenFlags.DELETE | OpenFlags.NEW)
    if status.ok:  # an open that slipped through must still refuse the write
        status, _ = f.write(_bytes(MIB, 13), MIB)
        f.close()
    assert not status.ok, "a write path opened on the read-only front"
    assert _files_under(spill_srv["dirs"]["spill_ro"]) == [], (
        "a read-only front created a spill scratch — the gate ran too late")


def _nginx_t(extra_stream: str) -> tuple:
    """Parse-only stream config: export {d}/exp, spill candidates beside and
    beneath it.  Placeholders: {EXP} {UNDER} {REL} {OUT}."""
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "exp", "exp/spill", "out"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        body = (extra_stream
                .replace("{EXP}", d + "/exp")
                .replace("{UNDER}", d + "/exp/spill")
                .replace("{OUT}", d + "/out")
                .replace("{REL}", "rel/spill"))
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            modules = [m for m in os.environ.get(
                "TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
            fh.write("".join(f"load_module {m};\n" for m in modules)
                     + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                     + "events {}\nstream {\n  server {\n"
                     + f"    listen {BIND_HOST}:{SHARED_PARSE_PLACEHOLDER_PORT};\n"
                     + "    brix_root on;\n    brix_auth none;\n"
                     + f"    brix_export {d}/exp;\n"
                     + f"    brix_storage_backend posix:{d}/exp;\n"
                     + "    brix_allow_write on;\n"
                     + f"    {body}\n"
                     + "  }\n}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


@pytest.mark.parametrize("directive,needle", [
    # Inside the export: service scratch reachable as export storage.
    ("brix_vfs_spill_path {UNDER};", "at or beneath export root"),
    # Relative: realpath() would resolve it against the master's cwd.
    ("brix_vfs_spill_path {REL};", "must be absolute"),
    # A cap below the directive minimum (0 stays legal = uncapped).
    ("brix_vfs_spill_path {OUT}; brix_vfs_spill_max 4096;",
     "must be 0 or at least 1m"),
])
def test_spill_config_negatives_refused_at_nginx_t(directive, needle):
    _need_nginx()
    rc, out = _nginx_t(directive)
    assert rc != 0, f"nginx -t accepted: {directive}"
    assert needle in out, f"want {needle!r} in:\n{out[-1500:]}"
