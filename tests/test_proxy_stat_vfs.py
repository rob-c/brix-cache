# test_proxy_stat_vfs.py — regression for the kXR_stat wire-layout fix in the
# transparent tap proxy (src/net/proxy/forward_request.c).
#
# BUG: brix_proxy_forward_stat shared the kXR_stat / kXR_truncate / kXR_fattr
# path and read the fhandle at byte 4. That is correct for truncate/fattr but for
# ClientStatRequest byte 4 is the `options` field (fhandle is at byte 16). A plain
# stat (options=0) fell through to the path branch and worked by luck, but statvfs
# sets options=kXR_vfs(1): the nonzero options byte was mistaken for a live file
# handle, translation failed, and the proxy rejected the op with kXR_InvalidRequest
# ("invalid file handle"). FIX: brix_proxy_forward_statx handles kXR_stat on its
# own, translating the fhandle at byte 16 only when present (open-handle stat) and
# forwarding path/vfs stats verbatim.
#
# 3 tests per change:
#   success       — statvfs (kXR_vfs) forwards and returns kXR_ok (was rejected)
#   error/normal  — plain path stat still works; a bad path is a backend error,
#                   NOT an invalid-file-handle reject
#   security-neg  — a stat carrying a never-opened fhandle@byte16 is still rejected
#                   (the guard survives, just at the correct offset)
import struct

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_proxy_mode_helpers")

kXR_vfs = 1


def _statvfs(sock, path, sid=b"\x00\x11"):
    """kXR_stat with options=kXR_vfs and a path (statvfs) — fhandle zeroed."""
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sHB11s4sI", sid, kXR_stat, kXR_vfs,
                      b"\x00" * 11, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _stat_by_handle(sock, fh_first_byte, sid=b"\x00\x12"):
    """kXR_stat by (forged) open handle: fhandle@byte16 nonzero, empty path."""
    fh = bytes([fh_first_byte]) + b"\x00" * 3
    req = struct.pack(">2sHB11s4sI", sid, kXR_stat, 0, b"\x00" * 11, fh, 0)
    sock.sendall(req)
    return _read_resp(sock)


class TestProxyStatVfs:

    def test_statvfs_forwards_and_succeeds(self, proxy_env):
        """statvfs (options=kXR_vfs) must forward to the upstream and return
        kXR_ok — before the fix it was rejected kXR_error 'invalid file handle'."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _statvfs(sock, "/")
            assert status == kXR_ok, f"statvfs status={status} body={body!r}"
            assert body, "statvfs returned an empty vfs body"
        finally:
            sock.close()

    def test_plain_path_stat_unaffected(self, proxy_env):
        """A plain path stat still succeeds, and a nonexistent path yields a
        backend error (not the invalid-file-handle misclassification)."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            ok_status, _ = _stat(sock, "/hello.txt")
            assert ok_status == kXR_ok
            bad_status, _ = _stat(sock, "/no-such-file-xyz")
            assert bad_status == kXR_error
        finally:
            sock.close()

    def test_forged_open_handle_stat_rejected(self, proxy_env):
        """security-neg: a stat carrying a never-opened fhandle (byte 16) must
        still be rejected — the fh-translation guard survives at the right offset,
        so the fix did not simply stop validating handles."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _stat_by_handle(sock, 0x7F)
            assert status == kXR_error
        finally:
            sock.close()
