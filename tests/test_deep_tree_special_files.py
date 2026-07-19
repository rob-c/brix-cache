"""Regression guard: deep-nested + symlink data-plane access, and the
special-file (FIFO / socket) worker-wedge DoS.

Two server bugs are pinned here, both fixed 2026-06-26 (memory
``clientconf_suite`` item 5):

  1. WORKER-WEDGE DoS.  The confined open path opened files ``O_RDONLY`` WITHOUT
     ``O_NONBLOCK``, before the ``fstat()`` type check.  ``open()`` on a FIFO (or
     a device with a blocking open routine) parks the single-threaded nginx
     worker in the kernel ``wait_for_partner`` rendezvous FOREVER, freezing its
     event loop and every connection pinned to it — a remotely triggerable denial
     of service that a plain ``xrdcp -r`` over a tree containing a named pipe
     trips.  Fix: force ``O_NONBLOCK`` on real opens (``src/fs/path/beneath.c`` and
     ``src/protocols/root/read/open_resolved_file.c``) and reject non-regular files after fstat.

  2. ``O_PATH | O_NONBLOCK`` -> ``EINVAL``.  The first cut of fix #1 added
     ``O_NONBLOCK`` to EVERY ``openat2()``, including the ``O_PATH`` opens used
     for stat/lstat and the persistent root anchor.  ``openat2()`` rejects
     ``O_PATH|O_NONBLOCK`` with ``EINVAL``, which silently broke ALL path
     resolution ("Invalid argument" on every stat/open).  The deep-access tests
     here would have caught it: they assert stat/ls/open SUCCEED.

The server runs with a SINGLE worker (``official_interop_lib.start_our_server``):
if bug #1 regresses the worker wedges, and every call here has a bounded timeout
so the test FAILS with a clear wedge diagnosis instead of hanging the suite
forever.  Driven by our native client so the file runs without the stock
toolchain; one differential nest-parity test uses stock and self-skips when it
is absent.

Harness: official_interop_lib (PYTHONPATH=tests).  Self-provisioning on a
per-worker high port; skips cleanly when the nginx-xrootd binary or the native
client is not built.
"""

import os
import socket
import subprocess

import pytest

import official_interop_lib as L
from settings import NGINX_BIN

# A healthy op completes in well under a second; this ceiling exists only so a
# WEDGED worker blows past it and the test fails fast.  pytest-timeout is a
# second backstop in case a call somehow evades the per-op bound.
OP_TIMEOUT = 15

pytestmark = pytest.mark.timeout(240)


# --------------------------------------------------------------------------- #
# Tree builder + module fixture (our server only, single worker).             #
# --------------------------------------------------------------------------- #
def _build_tree(root):
    """Build the export tree and return the set of special-file basenames that
    were actually created (a unix socket can fail on an over-long bind path)."""
    j = os.path.join
    specials = set()

    # A 6-level-deep regular file.
    os.makedirs(j(root, "deep", "a", "b", "c"), exist_ok=True)
    with open(j(root, "deep", "a", "b", "c", "leaf.txt"), "w") as f:
        f.write("deep-leaf-payload\n")

    # A symlink target + a trailing symlink to it (followed on open) + a symlink
    # that IS a directory component + a dangling symlink.
    with open(j(root, "target.txt"), "w") as f:
        f.write("symlink-target-payload\n")
    os.symlink("target.txt", j(root, "link_to_file.txt"))   # -> regular file
    os.symlink("deep", j(root, "linkdir"))                  # -> directory
    os.symlink("nope_missing", j(root, "link_broken"))      # -> nonexistent

    # The DoS trigger: a named pipe (and, if possible, a unix socket) directly
    # in the export.
    os.mkfifo(j(root, "fifo0"), 0o644)
    specials.add("fifo0")
    try:
        s = socket.socket(socket.AF_UNIX)
        s.bind(j(root, "sock0"))
        s.close()
        specials.add("sock0")
    except OSError:
        pass

    # A clean subtree (regular files + an in-export symlink, NO special files):
    # recursive copy of this is deterministic and must nest + match byte-for-byte.
    os.makedirs(j(root, "clean", "sub"), exist_ok=True)
    with open(j(root, "clean", "one.txt"), "w") as f:
        f.write("clean-one\n")
    with open(j(root, "clean", "sub", "two.txt"), "w") as f:
        f.write("clean-two\n")
    os.symlink("two.txt", j(root, "clean", "sub", "lnk.txt"))   # -> regular file

    # A subtree that CONTAINS a fifo: recursive copy of it must not wedge the
    # worker (the file set is order-dependent on the abort, so only no-hang +
    # responsiveness are asserted, not the exact contents).
    os.makedirs(j(root, "withspecial"), exist_ok=True)
    with open(j(root, "withspecial", "a.txt"), "w") as f:
        f.write("ws-a\n")
    os.mkfifo(j(root, "withspecial", "pipe.fifo"), 0o644)

    return specials


@pytest.fixture(scope="module")
def our(tmp_path_factory):
    if not (NGINX_BIN and os.path.exists(NGINX_BIN)):
        pytest.skip("nginx-xrootd binary not built")
    base = str(tmp_path_factory.mktemp("deeptree"))
    data = os.path.join(base, "data")
    os.makedirs(data, exist_ok=True)
    specials = _build_tree(data)
    port = L.worker_port(14060)
    proc = L.start_our_server(base, data, port=port)
    if not proc:
        pytest.skip("our nginx-xrootd server did not start")
    yield {"url": L.our_url(port), "data": data, "specials": specials}
    L.stop_pair([proc])


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _require_native():
    if not (os.path.exists(L.OUR_XRDCP) and os.path.exists(L.OUR_XRDFS)):
        pytest.skip("native xrdcp/xrdfs not built")


def _bounded(argv, what, timeout=OP_TIMEOUT):
    """Run argv; FAIL with a wedge diagnosis if it does not return in time.

    A timeout here is the signature of the worker-wedge regression: on a
    single-worker server, a blocking open(2) on a special file freezes the only
    worker and every subsequent request hangs."""
    try:
        return L.run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        pytest.fail(
            "%s did not return within %ss — the single worker is WEDGED. This is "
            "the FIFO/special-file open-DoS regression: open() on a non-regular "
            "file without O_NONBLOCK parks the worker in the kernel "
            "'wait_for_partner' state forever. argv=%r" % (what, timeout, argv))


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _alive(url, what):
    """A normal, cheap request must succeed quickly — the wedge detector."""
    rc, out, err = _bounded([L.OUR_XRDFS, url, "stat", "/target.txt"],
                            "responsiveness check after %s" % what)
    assert rc == 0 and "Size:" in out, (
        "server is UNRESPONSIVE after %s — worker likely wedged: %s%s"
        % (what, out, err))


# --------------------------------------------------------------------------- #
# Deep-nested + symlink data-plane access (also the O_PATH|O_NONBLOCK guard).  #
# --------------------------------------------------------------------------- #
def test_deep_nested_upload_download_access(our, tmp_path):
    _require_native()
    url = our["url"]
    deep = "/up/lvl1/lvl2/lvl3/lvl4/lvl5"

    rc, o, e = _bounded([L.OUR_XRDFS, url, "mkdir", "-p", deep], "mkdir -p deep")
    assert rc == 0, "mkdir -p deep failed: %s%s" % (o, e)

    src = tmp_path / "src.txt"
    src.write_bytes(b"deep-upload-payload\n")
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s", str(src),
                         "%s/%s/u.txt" % (url, deep)], "upload deep")
    assert rc == 0, "upload into deep dir failed: %s%s" % (o, e)
    on_disk = os.path.join(our["data"], deep.lstrip("/"), "u.txt")
    assert _read(on_disk) == b"deep-upload-payload\n", "uploaded bytes wrong on disk"

    back = tmp_path / "back.txt"
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s", "%s/%s/u.txt" % (url, deep),
                         str(back)], "download deep")
    assert rc == 0 and back.read_bytes() == b"deep-upload-payload\n", (
        "deep download mismatch: %s%s" % (o, e))

    # stat + ls must reach the depth (these are the O_PATH|O_NONBLOCK EINVAL
    # guard: that regression made every stat/ls fail with "Invalid argument").
    rc, o, e = _bounded([L.OUR_XRDFS, url, "stat", "%s/u.txt" % deep], "stat deep")
    assert rc == 0 and "Size:" in o, "stat of deep file failed: %s%s" % (o, e)
    rc, o, e = _bounded([L.OUR_XRDFS, url, "ls", "/deep/a/b/c"], "ls deep")
    assert rc == 0 and "leaf.txt" in o, "ls of deep dir failed: %s%s" % (o, e)


def test_trailing_symlink_to_file_is_followed(our, tmp_path):
    _require_native()
    dst = tmp_path / "via_link"
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s",
                         "%s//link_to_file.txt" % our["url"], str(dst)],
                        "download symlink->file")
    assert rc == 0, "download of symlink-to-file failed: %s%s" % (o, e)
    assert dst.read_bytes() == _read(os.path.join(our["data"], "target.txt")), (
        "symlink-to-file did not return the target's bytes")


def test_file_through_symlinked_directory_component(our, tmp_path):
    _require_native()
    # /linkdir -> deep, so /linkdir/a/b/c/leaf.txt resolves to the deep leaf.
    dst = tmp_path / "via_linkdir"
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s",
                         "%s//linkdir/a/b/c/leaf.txt" % our["url"], str(dst)],
                        "download via symlinked dir component")
    assert rc == 0, "access through symlinked dir component failed: %s%s" % (o, e)
    assert dst.read_bytes() == _read(
        os.path.join(our["data"], "deep", "a", "b", "c", "leaf.txt")), (
        "symlinked-dir access returned wrong bytes")


def test_stat_types_resolve_without_einval(our):
    """A pointed guard for the O_PATH|O_NONBLOCK->EINVAL regression: stat of a
    regular file, a directory, and a symlink must all SUCCEED (that bug made
    every O_PATH open — i.e. every stat — fail with kXR_ArgInvalid)."""
    _require_native()
    for path in ("/target.txt", "/deep", "/link_to_file.txt", "/deep/a/b/c"):
        rc, o, e = _bounded([L.OUR_XRDFS, our["url"], "stat", path],
                            "stat %s" % path)
        assert rc == 0 and "Size:" in o and "Invalid argument" not in (o + e), (
            "stat %s failed (O_PATH EINVAL regression?): %s%s" % (path, o, e))


# --------------------------------------------------------------------------- #
# The worker-wedge DoS guard: opening a special file must fast-FAIL, and the    #
# server must stay responsive afterwards.                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("special", ["fifo0", "sock0"])
def test_special_file_open_does_not_wedge_worker(our, tmp_path, special):
    _require_native()
    if special not in our["specials"]:
        pytest.skip("%s could not be created in this environment" % special)
    url = our["url"]

    # Opening the special file must return an error PROMPTLY (never block).  If
    # the worker wedges, _bounded() fails with the wedge diagnosis.
    dst = tmp_path / ("got_" + special)
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s", "%s//%s" % (url, special),
                         str(dst)], "open special file %s" % special)
    assert rc != 0, "expected opening %s to FAIL, got success: %s%s" % (
        special, o, e)

    # And the worker must still be alive for the next client.
    _alive(url, "opening %s" % special)


def test_broken_symlink_errors_fast(our, tmp_path):
    _require_native()
    dst = tmp_path / "got_broken"
    rc, o, e = _bounded([L.OUR_XRDCP, "-f", "-s",
                         "%s//link_broken" % our["url"], str(dst)],
                        "open dangling symlink")
    assert rc != 0, "expected dangling symlink to FAIL: %s%s" % (o, e)
    _alive(our["url"], "opening a dangling symlink")


# --------------------------------------------------------------------------- #
# Recursive copy: a clean subtree nests deterministically; a subtree with a     #
# fifo must complete without wedging the worker.                                #
# --------------------------------------------------------------------------- #
def test_recursive_clean_subtree_nests_and_matches(our, tmp_path):
    _require_native()
    out = tmp_path / "rec_clean"
    out.mkdir()
    rc, o, e = _bounded([L.OUR_XRDCP, "-s", "-r", "%s//clean" % our["url"],
                         str(out)], "recursive clean subtree", timeout=30)
    assert rc == 0, "recursive copy of clean subtree failed: %s%s" % (o, e)

    # Nested under the source basename "clean", every regular file (incl. the
    # in-export symlink, followed on open) present and byte-exact.
    base = out / "clean"
    want = {
        "one.txt": _read(os.path.join(our["data"], "clean", "one.txt")),
        os.path.join("sub", "two.txt"):
            _read(os.path.join(our["data"], "clean", "sub", "two.txt")),
        os.path.join("sub", "lnk.txt"):       # symlink -> two.txt (followed)
            _read(os.path.join(our["data"], "clean", "sub", "two.txt")),
    }
    for rel, data in want.items():
        p = base / rel
        assert p.is_file(), "recursive clean copy missing %s (no nest?)" % rel
        assert p.read_bytes() == data, "recursive clean copy: %s bytes wrong" % rel


def test_recursive_over_fifo_subtree_does_not_hang(our, tmp_path):
    _require_native()
    out = tmp_path / "rec_special"
    out.mkdir()
    # The copy may exit non-zero (a fifo cannot be copied, exactly as stock); the
    # invariant under test is that it COMPLETES without wedging the worker (the
    # _bounded timeout is the wedge detector) and the server stays responsive
    # (_alive below). Whether the regular file beside the fifo lands is
    # ORDER-DEPENDENT and NOT asserted: copy_tree_download (client/lib/xfer/
    # copy_recursive.c) walks the server's dirlist in unsorted readdir order and
    # aborts the whole recursion on the first un-copyable entry — the fifo —
    # exactly like stock `xrdcp -r` without --continue. So a.txt is delivered only
    # when it happens to sort before the fifo in the remote listing. Assert
    # byte-correctness IF it landed; never require its presence.
    _bounded([L.OUR_XRDCP, "-s", "-r", "%s//withspecial" % our["url"], str(out)],
             "recursive copy over a tree containing a fifo", timeout=30)
    landed = out / "withspecial" / "a.txt"
    if landed.is_file():
        assert landed.read_bytes() == b"ws-a\n", (
            "the regular file beside the fifo landed but with the wrong bytes")
    _alive(our["url"], "a recursive copy over a fifo-bearing tree")


# --------------------------------------------------------------------------- #
# Differential: our recursive nest layout must match the stock toolchain.       #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    if not L.have_official():
        pytest.skip("stock xrootd toolchain not installed")
    base = str(tmp_path_factory.mktemp("deeptree_pair"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14062),
                                  off_port=L.worker_port(14063))
    except Exception as exc:                       # noqa: BLE001 -> skip cleanly
        pytest.skip("server pair did not start: %s" % exc)
    yield ctx
    L.stop_pair(procs)


def _rel_files(root):
    return sorted(str(p.relative_to(root))
                  for p in root.rglob("*") if p.is_file())


def test_recursive_nest_layout_matches_stock(pair, tmp_path):
    """`xrdcp -r //deep <dst>` must nest under the source basename identically on
    our stack and the stock stack (guards the 'ours flattens' client regression
    against the stock oracle)."""
    _require_native()
    our_out = tmp_path / "ours"
    our_out.mkdir()
    rc, o, e = _bounded([L.OUR_XRDCP, "-s", "-r", "%s//deep" % pair["our"],
                         str(our_out)], "native -r vs our server", timeout=30)
    assert rc == 0, "native recursive download failed: %s%s" % (o, e)

    stock_out = tmp_path / "stock"
    stock_out.mkdir()
    rc, o, e = _bounded([L.OFF_XRDCP, "-s", "-r", "%s//deep" % pair["off"],
                         str(stock_out)], "stock -r vs stock server", timeout=30)
    assert rc == 0, "stock recursive download failed: %s%s" % (o, e)

    assert _rel_files(our_out) == _rel_files(stock_out), (
        "recursive nest layout diverges from stock: ours=%s stock=%s"
        % (_rel_files(our_out), _rel_files(stock_out)))
