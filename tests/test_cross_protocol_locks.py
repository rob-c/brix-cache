"""Phase-107 C7 — the VFS lock gate, live across protocol planes.

A WebDAV lock is one xattr on the resource (user.nginx_xrootd.lock), which
means the state was always in the storage layer and visible to every plane —
but only the WebDAV edge ever *checked* it.  W8 hoisted the check into the VFS
mutation path (src/fs/vfs/vfs_lock_gate.c, position 2 of the §3.4 gate order),
so a lock taken over WebDAV now refuses the same file over root://, S3 and
GridFTP, each in its own wire idiom (§5.0):

    root://   EBUSY -> kXR_FileLocked
    WebDAV    EBUSY -> 423 Locked
    S3        423   -> 409 Conflict + OperationAborted
    GridFTP   EBUSY -> 450

These are the seven contract rows from
docs/refactor/phase-107-vfs-mutation-surface-completion.md §4/C7:

  success   davs LOCK, then root:// write -> kXR_FileLocked; the same write
            succeeds after UNLOCK;
  success   the lock owner writing over WebDAV with the If: token succeeds;
  success   an EXPIRED lock refuses nothing, and the xattr is still present
            afterwards on a read-only export (the gate never reaps);
  error     `brix_lock_enforcement advisory` -> the root:// write succeeds,
            one warn names the path (never the token), and the refused-metric
            still books;
  error     `brix_lock_enforcement off` -> today's behaviour exactly: the
            write succeeds, nothing is logged, nothing is booked;
  sec-neg   a forged lock token is refused and the refusal does not echo the
            real token;
  sec-neg   on a read-only export the answer is kXR_fsReadOnly, never
            kXR_FileLocked — EROFS precedes EBUSY, so the lock's existence is
            not disclosed.

Plus the cross-protocol closure the W8 checklist demands: ONE lock refusing
S3 PutObject, S3 CompleteMultipartUpload (the pool-thread path-rename bypass
the MPU pre-flight gate closed), GridFTP STOR and DELE, and root:// — all at
once — and every plane succeeding after UNLOCK.  The OCI publish plane still
re-implements its mutations below the VFS (phase-108 W1 consolidates it) and
is enforced there, not here.

The C object unit (tests/c/test_vfs_lock_gate.c, `vfs_lock_gate` in
cmdscripts/c_object_units.py) proves the gate's state machine hermetically;
this file proves the wire-to-storage composition.  Instance topology in
tests/configs/nginx_p107_locks.conf.
"""
import ftplib
import io
import os
import re
import subprocess
import tempfile
import time

import pytest
import requests

from XRootD import client
from XRootD.client.flags import OpenFlags

from _xrdcl_proxy import real_bindings_available
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p107-locks"),
              pytest.mark.skipif(
                  not real_bindings_available(),
                  reason="real libXrdCl bindings unavailable")]

SPEC = "lc-p107-locks"
BUCKET = "testbucket"
LOCK_XATTR = "user.nginx_xrootd.lock"
LOCK_BODY = ('<?xml version="1.0" encoding="utf-8" ?>'
             '<D:lockinfo xmlns:D="DAV:">'
             '<D:lockscope><D:exclusive/></D:lockscope>'
             '<D:locktype><D:write/></D:locktype>'
             '</D:lockinfo>')


def _need_nginx() -> None:
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


@pytest.fixture(scope="module")
def lock_srv(tmp_path_factory):
    """One instance: four fronts over ONE export + one export per mode
    (see nginx_p107_locks.conf)."""
    _need_nginx()
    base = tmp_path_factory.mktemp("p107-locks")
    dirs = {name: base / name for name in ("shared", "adv", "off", "ro")}
    for d in dirs.values():
        d.mkdir()
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_p107_locks.conf",
            protocol="root",
            data_root=str(dirs["shared"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "ADV_EXPORT": str(dirs["adv"]),
                "OFF_EXPORT": str(dirs["off"]),
                "RO_EXPORT": str(dirs["ro"]),
            },
            reason="phase-107 C7 lock gate across root/WebDAV/S3/GridFTP"))
        yield {"port": ep.port, "extras": ep.extra_ports, "dirs": dirs,
               "error_log": os.path.join(ep.prefix, "logs", "error.log")}
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# plumbing                                                                    #
# --------------------------------------------------------------------------- #
def _dav(srv, path: str) -> str:
    return f"http://{HOST}:{srv['extras']['DAV_PORT']}{path}"


def _lock(srv, path: str, **kw) -> requests.Response:
    headers = {"Timeout": "Second-3600"}
    headers.update(kw.pop("headers", {}))
    return requests.request("LOCK", _dav(srv, path), data=LOCK_BODY,
                            headers=headers, timeout=10, **kw)


def _unlock(srv, path: str, token: str) -> requests.Response:
    if not token.startswith("<"):
        token = f"<{token}>"
    return requests.request("UNLOCK", _dav(srv, path),
                            headers={"Lock-Token": token}, timeout=10)


def _root_url(port: int, path: str) -> str:
    return f"root://{HOST}:{port}/{path.lstrip('/')}"


def _root_write(port: int, path: str, data: bytes = b"cross-proto-lock"):
    """Truncate-create write; returns the FIRST failing XRootD status, or the
    final (ok) close status."""
    f = client.File()
    status, _ = f.open(_root_url(port, path), OpenFlags.DELETE)
    if not status.ok:
        return status
    status, _ = f.write(data, 0)
    if not status.ok:
        f.close()
        return status
    status, _ = f.close()
    return status


def _root_update(port: int, path: str, data: bytes):
    """In-place write to an EXISTING file (OpenFlags.UPDATE).  _root_write's
    DELETE open replaces the inode — and with it any planted lock xattr — so a
    test asserting xattr survival must write through the original inode."""
    f = client.File()
    status, _ = f.open(_root_url(port, path), OpenFlags.UPDATE)
    if not status.ok:
        return status
    status, _ = f.write(data, 0)
    if not status.ok:
        f.close()
        return status
    status, _ = f.close()
    return status


def _root_read(port: int, path: str) -> bytes:
    f = client.File()
    status, _ = f.open(_root_url(port, path), OpenFlags.READ)
    assert status.ok, f"read open failed: {status.message}"
    try:
        status, data = f.read()
        assert status.ok, f"read failed: {status.message}"
        return bytes(data)
    finally:
        f.close()


def _plant_lock(path, expires_at: int, token: str,
                depth: str = "0", owner: str = "tester") -> bytes:
    """Write a schema-v2 lock record exactly as brix_lock_record_encode does
    (needed on exports whose WebDAV LOCK verb is unreachable or read-only)."""
    raw = (f"v=2|token={token}|owner={owner}|expires={expires_at}"
           f"|scope=exclusive|depth={depth}|null=0").encode()
    os.setxattr(path, LOCK_XATTR, raw)
    return raw


def _lock_refused_rows(srv) -> dict:
    r = requests.get(
        f"http://{HOST}:{srv['extras']['METRICS_PORT']}/metrics", timeout=10)
    assert r.status_code == 200
    return {proto: int(v) for proto, v in re.findall(
        r'brix_vfs_lock_refused_total\{proto="([^"]+)"\} (\d+)', r.text)}


def _ftp(srv) -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect(HOST, srv["extras"]["FTP_PORT"], timeout=30)
    ftp.login()
    return ftp


def _s3(srv, key: str) -> str:
    return f"http://{HOST}:{srv['extras']['S3_PORT']}/{BUCKET}/{key}"


def _xml_value(body: str, tag: str) -> str:
    m = re.search(f"<{tag}>(.*?)</{tag}>", body)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- #
# success                                                                     #
# --------------------------------------------------------------------------- #
def test_dav_lock_refuses_root_write_until_unlock(lock_srv):
    """The doc's first row: LOCK over the WebDAV edge, kXR_FileLocked over
    root://, and the identical write succeeding the moment UNLOCK lands."""
    port = lock_srv["port"]
    assert requests.put(_dav(lock_srv, "/gate.bin"), data=b"original",
                        timeout=10).status_code in (200, 201, 204)
    r = _lock(lock_srv, "/gate.bin")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    try:
        status = _root_write(port, "/gate.bin")
        assert not status.ok, "a root:// write went through a live DAV lock"
        msg = status.message.lower()
        assert "busy" in msg or "lock" in msg, (
            f"want the kXR_FileLocked/EBUSY text, got: {status.message}")
        # The lock held: the original bytes are untouched.
        assert (lock_srv["dirs"]["shared"] / "gate.bin").read_bytes() \
            == b"original"
    finally:
        # No assert here: a raise inside finally REPLACES the in-flight
        # failure from the try block.  Unlock unconditionally, verify after.
        unlock_rc = _unlock(lock_srv, "/gate.bin", token).status_code
    assert unlock_rc == 204
    status = _root_write(port, "/gate.bin", b"post-unlock")
    assert status.ok, f"the unlocked write still refused: {status.message}"
    assert _root_read(port, "/gate.bin") == b"post-unlock"


def test_owner_if_token_still_writes_over_dav(lock_srv):
    """The owner presenting the If: token defeats their own lock; the same
    request without the token answers 423."""
    r = _lock(lock_srv, "/owned.bin")
    assert r.status_code == 201, r.text     # lock-null: LOCK created the name
    token = r.headers["Lock-Token"]
    try:
        r = requests.put(_dav(lock_srv, "/owned.bin"), data=b"anon",
                         timeout=10)
        assert r.status_code == 423, (
            f"a tokenless PUT went through the lock: {r.status_code}")
        r = requests.put(_dav(lock_srv, "/owned.bin"), data=b"owner-bytes",
                         headers={"If": f"({token})"}, timeout=10)
        assert r.status_code in (200, 201, 204), (
            f"the owner's own token was refused: {r.status_code} {r.text}")
        assert (lock_srv["dirs"]["shared"] / "owned.bin").read_bytes() \
            == b"owner-bytes"
    finally:
        unlock_rc = _unlock(lock_srv, "/owned.bin", token).status_code
    assert unlock_rc == 204


def test_expired_lock_admits_and_is_never_reaped(lock_srv):
    """The gate treats an expired record as ABSENT without removing it: the
    reap is a mutation only the writable WebDAV edge may perform.  Proven on
    the read-only export (a read under the expired lock leaves the xattr
    byte-identical) and on the writable strict export (a root:// write goes
    through and still does not reap — root:// has no reaping code)."""
    past = int(time.time()) - 100
    # Read-only export: file + expired lock planted directly on disk.
    ro_file = lock_srv["dirs"]["ro"] / "stale.bin"
    ro_file.write_bytes(b"ro-payload")
    raw = _plant_lock(ro_file, past, "opaquelocktoken:planted-ro-stale")
    assert _root_read(lock_srv["extras"]["RO_PORT"], "/stale.bin") \
        == b"ro-payload"
    assert os.getxattr(ro_file, LOCK_XATTR) == raw, (
        "a READ on a read-only export reaped the expired lock record")
    # Writable strict export: the expired lock refuses nothing and survives.
    wr_file = lock_srv["dirs"]["shared"] / "stale-wr.bin"
    wr_file.write_bytes(b"old")
    raw = _plant_lock(wr_file, past, "opaquelocktoken:planted-wr-stale")
    status = _root_update(lock_srv["port"], "/stale-wr.bin", b"new")
    assert status.ok, f"an EXPIRED lock refused a write: {status.message}"
    assert os.getxattr(wr_file, LOCK_XATTR) == raw, (
        "the gate reaped an expired lock record — reaping belongs to the "
        "writable WebDAV edge alone")


# --------------------------------------------------------------------------- #
# error                                                                       #
# --------------------------------------------------------------------------- #
def test_advisory_warns_books_and_admits(lock_srv):
    """brix_lock_enforcement advisory: the write proceeds, ONE warn names the
    path (never the bearer token), and the refused-metric books — the count is
    what tells an operator the relaxed mode is masking real contention."""
    token = "opaquelocktoken:planted-advisory-secret"
    target = lock_srv["dirs"]["adv"] / "adv.bin"
    target.write_bytes(b"old")
    _plant_lock(target, int(time.time()) + 3600, token)
    before = _lock_refused_rows(lock_srv).get("stream", 0)
    status = _root_write(lock_srv["extras"]["ADV_PORT"], "/adv.bin", b"new")
    assert status.ok, f"advisory mode refused the write: {status.message}"
    assert target.read_bytes() == b"new"
    assert _lock_refused_rows(lock_srv).get("stream", 0) == before + 1, (
        "advisory admission did not book brix_vfs_lock_refused_total")
    log = open(lock_srv["error_log"], errors="replace").read()
    warns = [ln for ln in log.splitlines()
             if "proceeds under a live foreign lock" in ln]
    assert any("/adv.bin" in ln for ln in warns), (
        "no advisory warn names the admitted path")
    assert token not in log, (
        "the bearer lock token leaked into the error log")


def test_off_is_todays_behaviour(lock_srv):
    """brix_lock_enforcement off: the write proceeds with zero xattr reads —
    nothing logged, nothing booked, exactly the pre-C7 baseline."""
    target = lock_srv["dirs"]["off"] / "off.bin"
    target.write_bytes(b"old")
    _plant_lock(target, int(time.time()) + 3600,
                "opaquelocktoken:planted-off")
    before = _lock_refused_rows(lock_srv)
    status = _root_write(lock_srv["extras"]["OFF_PORT"], "/off.bin", b"new")
    assert status.ok, f"off mode refused the write: {status.message}"
    assert target.read_bytes() == b"new"
    assert _lock_refused_rows(lock_srv) == before, (
        "off mode booked a lock-refused metric")
    log = open(lock_srv["error_log"], errors="replace").read()
    assert not any("/off.bin" in ln and "lock" in ln.lower()
                   for ln in log.splitlines()), (
        "off mode logged the lock it was told to ignore")


# --------------------------------------------------------------------------- #
# security-negative                                                           #
# --------------------------------------------------------------------------- #
def test_forged_token_refused_without_echoing_the_real_one(lock_srv):
    """A forged If: token is a foreign token: refused, and neither the 423
    body nor its headers may disclose the real bearer secret."""
    r = _lock(lock_srv, "/forge.bin")
    assert r.status_code == 201, r.text
    token = r.headers["Lock-Token"]
    real = token.strip("<>")
    try:
        r = requests.put(_dav(lock_srv, "/forge.bin"), data=b"evil",
                         headers={"If": "(<opaquelocktoken:forged-0000>)"},
                         timeout=10)
        assert r.status_code == 423, (
            f"a FORGED token defeated the lock: {r.status_code}")
        assert real not in r.text, "the 423 body echoes the real lock token"
        assert all(real not in v for v in r.headers.values()), (
            "a 423 response header echoes the real lock token")
    finally:
        unlock_rc = _unlock(lock_srv, "/forge.bin", token).status_code
    assert unlock_rc == 204


def test_read_only_answers_erofs_never_ebusy(lock_srv):
    """EROFS precedes EBUSY (§3.4 position 2 comes AFTER the policy kernel):
    a write on the read-only export refuses kXR_fsReadOnly even under a live
    lock, so the refusal does not disclose the lock's existence."""
    target = lock_srv["dirs"]["ro"] / "held.bin"
    target.write_bytes(b"ro")
    _plant_lock(target, int(time.time()) + 3600,
                "opaquelocktoken:planted-ro-live", depth="0")
    status = _root_write(lock_srv["extras"]["RO_PORT"], "/held.bin")
    assert not status.ok, "a write went through a read-only export"
    msg = status.message.lower()
    assert "read" in msg and "only" in msg, (
        f"want the kXR_fsReadOnly/EROFS text, got: {status.message}")
    assert "busy" not in msg and "lock" not in msg, (
        f"the read-only refusal disclosed the lock: {status.message}")


def _assert_root_plane_locked(lock_srv, key):
    status = _root_write(lock_srv["port"], f"/{key}")
    assert not status.ok and (
        "busy" in status.message.lower()
        or "lock" in status.message.lower()), (
        f"root:// bypassed the lock: {status}")


def _assert_s3_planes_locked(lock_srv, key):
    """PutObject refuses outright; multipart init/part may be staged freely,
    but NO step may publish — the refusal must arrive by
    CompleteMultipartUpload (the MPU publish is a pool-thread path rename,
    gated by the pre-flight check)."""
    r = requests.put(_s3(lock_srv, key), data=b"s3-evil", timeout=10)
    assert r.status_code == 409, (
        f"S3 PutObject bypassed the lock: {r.status_code}")
    assert "OperationAborted" in r.text, r.text
    r = requests.post(_s3(lock_srv, key) + "?uploads", timeout=10)
    if r.status_code != 200:
        assert r.status_code == 409, r.status_code
        return
    upload_id = _xml_value(r.text, "UploadId")
    assert upload_id
    pr = requests.put(
        _s3(lock_srv, key) + f"?partNumber=1&uploadId={upload_id}",
        data=b"mpu-evil", timeout=10)
    if pr.status_code not in (200, 201):
        return
    cr = requests.post(
        _s3(lock_srv, key) + f"?uploadId={upload_id}",
        data=b"<CompleteMultipartUpload>"
             b"<Part><PartNumber>1</PartNumber></Part>"
             b"</CompleteMultipartUpload>", timeout=30)
    assert cr.status_code == 409, (
        f"CompleteMultipartUpload bypassed the lock: "
        f"{cr.status_code} {cr.text}")
    assert "OperationAborted" in cr.text, cr.text


def _assert_ftp_plane_locked(lock_srv, key):
    ftp = _ftp(lock_srv)
    try:
        with pytest.raises(ftplib.error_temp) as exc:
            ftp.storbinary(f"STOR {key}", io.BytesIO(b"ftp-evil"))
        assert str(exc.value).startswith("450"), str(exc.value)
        with pytest.raises(ftplib.error_temp) as exc:
            ftp.delete(key)
        assert str(exc.value).startswith("450"), str(exc.value)
    finally:
        ftp.quit()


def _assert_every_plane_admits(lock_srv, key):
    """After UNLOCK every plane succeeds on the SAME path, in sequence."""
    r = requests.put(_s3(lock_srv, key), data=b"s3-after", timeout=10)
    assert r.status_code in (200, 201), (r.status_code, r.text)
    ftp = _ftp(lock_srv)
    try:
        ftp.storbinary(f"STOR {key}", io.BytesIO(b"ftp-after"))
    finally:
        ftp.quit()
    status = _root_write(lock_srv["port"], f"/{key}", b"root-after")
    assert status.ok, f"post-unlock root write refused: {status.message}"
    assert (lock_srv["dirs"]["shared"] / key).read_bytes() == b"root-after"


def test_one_lock_refuses_every_plane_until_unlock(lock_srv):
    """The W8 closure row: ONE WebDAV lock refusing the same file over
    root:// (kXR_FileLocked), S3 PutObject AND CompleteMultipartUpload
    (409 + OperationAborted), GridFTP STOR and DELE (450) — and every
    plane succeeding on the same path after UNLOCK."""
    key = "everyplane.bin"
    assert requests.put(_dav(lock_srv, f"/{key}"), data=b"original",
                        timeout=10).status_code in (200, 201, 204)
    r = _lock(lock_srv, f"/{key}")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    try:
        _assert_root_plane_locked(lock_srv, key)
        _assert_s3_planes_locked(lock_srv, key)
        _assert_ftp_plane_locked(lock_srv, key)
        assert (lock_srv["dirs"]["shared"] / key).read_bytes() == b"original"
    finally:
        unlock_rc = _unlock(lock_srv, f"/{key}", token).status_code
    assert unlock_rc == 204
    _assert_every_plane_admits(lock_srv, key)


# --------------------------------------------------------------------------- #
# the two W8-completion gates (2026-09-02 drill-down)                         #
# --------------------------------------------------------------------------- #
def test_path_truncate_refuses_locked_file_until_unlock(lock_srv):
    """kXR_truncate by NAME (FileSystem.truncate — no open precedes it, so no
    open-time gate runs for it): kXR_FileLocked under a live DAV lock, admitted
    after UNLOCK.  On this POSIX export the verb takes the open+ftruncate
    fallback, whose gate sits inside brix_vfs_open; on a path-native backend
    the identical refusal comes from the C7 gate on vfs_sync.c's path-native
    branch (pinned hermetically in tests/c/test_vfs_new_mutator_gate.c) — the
    wire answer must not depend on which route the backend forces."""
    port = lock_srv["port"]
    assert requests.put(_dav(lock_srv, "/trunc.bin"), data=b"0123456789",
                        timeout=10).status_code in (200, 201, 204)
    r = _lock(lock_srv, "/trunc.bin")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    fs = client.FileSystem(f"root://{HOST}:{port}")
    try:
        status, _ = fs.truncate("/trunc.bin", 4)
        assert not status.ok, "a path truncate went through a live DAV lock"
        msg = status.message.lower()
        assert "busy" in msg or "lock" in msg, (
            f"want the kXR_FileLocked/EBUSY text, got: {status.message}")
        assert (lock_srv["dirs"]["shared"] / "trunc.bin").read_bytes() \
            == b"0123456789"
    finally:
        unlock_rc = _unlock(lock_srv, "/trunc.bin", token).status_code
    assert unlock_rc == 204
    status, _ = fs.truncate("/trunc.bin", 4)
    assert status.ok, f"the unlocked truncate still refused: {status.message}"
    assert (lock_srv["dirs"]["shared"] / "trunc.bin").read_bytes() == b"0123"


def _bulk_delete_request(lock_srv, keys):
    """POST the two-key DeleteObjects batch and return the response."""
    body = ('<?xml version="1.0" encoding="UTF-8"?><Delete>'
            + "".join(f"<Object><Key>{k}</Key></Object>" for k in keys)
            + "</Delete>").encode()
    url = f"http://{HOST}:{lock_srv['extras']['S3_PORT']}/{BUCKET}/?delete"
    return requests.post(url, data=body,
                         headers={"Content-Type": "application/xml"},
                         timeout=30)


def _assert_bulk_refused_atomically(lock_srv, keys, before):
    """One locked key must refuse the WHOLE batch: 409 OperationAborted,
    every key surviving, and exactly one strict-refusal metric booking."""
    r = _bulk_delete_request(lock_srv, keys)
    assert r.status_code == 409, (
        f"a locked key did not refuse the batch: {r.status_code} {r.text}")
    assert "OperationAborted" in r.text, r.text
    for key in keys:
        assert (lock_srv["dirs"]["shared"] / key).exists(), (
            f"{key} was deleted by a REFUSED batch — the refusal must "
            "be atomic")
    assert _lock_refused_rows(lock_srv).get("s3", 0) == before + 1, (
        "the strict batch refusal did not book brix_vfs_lock_refused_total")


def test_bulk_delete_refuses_locked_key_atomically_until_unlock(lock_srv):
    """S3 DeleteObjects with one LOCKED key among two: the whole batch answers
    409 OperationAborted — the single-key DELETE's own lock answer — and BOTH
    keys survive, because the per-key gate runs before ANY arm touches storage
    (vfs_unlink_many.c): no partial delete hides behind a lock conflict.  The
    strict refusal books brix_vfs_lock_refused_total{proto="s3"}.  After
    UNLOCK the identical batch deletes both keys."""
    locked, free = "bulk-locked.bin", "bulk-free.bin"
    for key in (locked, free):
        assert requests.put(_dav(lock_srv, f"/{key}"), data=b"batch",
                            timeout=10).status_code in (200, 201, 204)
    r = _lock(lock_srv, f"/{locked}")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    try:
        before = _lock_refused_rows(lock_srv).get("s3", 0)
        _assert_bulk_refused_atomically(lock_srv, (free, locked), before)
    finally:
        unlock_rc = _unlock(lock_srv, f"/{locked}", token).status_code
    assert unlock_rc == 204
    r = _bulk_delete_request(lock_srv, (free, locked))
    assert r.status_code == 200, (r.status_code, r.text)
    for key in (locked, free):
        assert not (lock_srv["dirs"]["shared"] / key).exists(), (
            f"the unlocked batch left {key} behind")


def test_owner_token_deletes_its_own_locked_file(lock_srv):
    """The owner's DELETE with its own If: token must succeed (RFC 4918 §7):
    the DAV DELETE ctx (webdav_ns_vfs_ctx_init) must hand the VFS gate the
    same token bytes the edge matched, or the edge admits and the AUTHORITY
    refuses — which surfaced as a 500 before the drill-down fix."""
    r = requests.put(_dav(lock_srv, "/own-del.bin"), data=b"mine", timeout=10)
    assert r.status_code in (200, 201, 204)
    r = _lock(lock_srv, "/own-del.bin")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    try:
        r = requests.delete(_dav(lock_srv, "/own-del.bin"), timeout=10)
        assert r.status_code == 423, (
            f"a tokenless DELETE went through the lock: {r.status_code}")
        r = requests.delete(_dav(lock_srv, "/own-del.bin"),
                            headers={"If": f"({token})"}, timeout=10)
        assert r.status_code == 204, (
            f"the owner's own DELETE was refused: {r.status_code} {r.text}")
        assert not (lock_srv["dirs"]["shared"] / "own-del.bin").exists()
    finally:
        # Best-effort: the successful DELETE removed the lock with the inode;
        # this only matters when an assert above left the lock standing.
        _unlock(lock_srv, "/own-del.bin", token)


def test_owner_token_moves_its_own_locked_file(lock_srv):
    """The owner's MOVE with its own If: token: the rename exec builds its
    OWN ctx (move.c, thread-pool capable) which also had to learn the token;
    tokenless MOVE stays 423 and moves nothing."""
    r = requests.put(_dav(lock_srv, "/own-mv.bin"), data=b"mv-me", timeout=10)
    assert r.status_code in (200, 201, 204)
    r = _lock(lock_srv, "/own-mv.bin")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    dst = _dav(lock_srv, "/own-mv-dst.bin")
    try:
        r = requests.request("MOVE", _dav(lock_srv, "/own-mv.bin"),
                             headers={"Destination": dst}, timeout=10)
        assert r.status_code == 423, (
            f"a tokenless MOVE went through the lock: {r.status_code}")
        assert (lock_srv["dirs"]["shared"] / "own-mv.bin").read_bytes() \
            == b"mv-me"
        r = requests.request("MOVE", _dav(lock_srv, "/own-mv.bin"),
                             headers={"Destination": dst,
                                      "If": f"({token})"}, timeout=10)
        assert r.status_code in (201, 204), (
            f"the owner's own MOVE was refused: {r.status_code} {r.text}")
        assert (lock_srv["dirs"]["shared"] / "own-mv-dst.bin").read_bytes() \
            == b"mv-me"
        assert not (lock_srv["dirs"]["shared"] / "own-mv.bin").exists()
    finally:
        # The lock xattr travelled with the inode to the destination.
        _unlock(lock_srv, "/own-mv-dst.bin", token)
        _unlock(lock_srv, "/own-mv.bin", token)


def test_owner_token_proppatch_its_own_locked_resource(lock_srv):
    """The owner's PROPPATCH with its own If: token: dead-property set/remove
    are gated xattr mutations, and the PROPPATCH ctx builder
    (webdav_dead_prop_vfs_ctx_init) also had to learn the token.  A residual
    VFS refusal renders 423 per propstat, never 507."""
    r = requests.put(_dav(lock_srv, "/own-pp.bin"), data=b"props", timeout=10)
    assert r.status_code in (200, 201, 204)
    r = _lock(lock_srv, "/own-pp.bin")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    body = ('<?xml version="1.0"?>'
            '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x-test:">'
            '<D:set><D:prop><Z:color>blue</Z:color></D:prop></D:set>'
            '</D:propertyupdate>')
    headers = {"Content-Type": "application/xml"}
    try:
        r = requests.request("PROPPATCH", _dav(lock_srv, "/own-pp.bin"),
                             data=body, headers=headers, timeout=10)
        assert r.status_code == 423, (
            f"a tokenless PROPPATCH went through the lock: {r.status_code}")
        r = requests.request("PROPPATCH", _dav(lock_srv, "/own-pp.bin"),
                             data=body,
                             headers={**headers, "If": f"({token})"},
                             timeout=10)
        assert r.status_code == 207, (r.status_code, r.text)
        assert "200 OK" in r.text and "507" not in r.text, r.text
    finally:
        unlock_rc = _unlock(lock_srv, "/own-pp.bin", token).status_code
    assert unlock_rc == 204


def test_owner_token_mkcol_inside_its_own_locked_collection(lock_srv):
    """MKCOL inside a depth-infinity-locked collection: tokenless refuses 423
    (RFC 4918 §9.3.1 — creating a member mutates the locked collection) and
    never 500 (the MKCOL errno map had no EBUSY row before the drill-down
    fix); the owner's MKCOL with its If: token succeeds 201."""
    r = requests.request("MKCOL", _dav(lock_srv, "/own-col/"), timeout=10)
    assert r.status_code in (201, 405), r.text
    r = _lock(lock_srv, "/own-col/")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    try:
        r = requests.request("MKCOL", _dav(lock_srv, "/own-col/sub/"),
                             timeout=10)
        assert r.status_code == 423, (
            f"a tokenless MKCOL went through the collection lock: "
            f"{r.status_code}")
        assert not (lock_srv["dirs"]["shared"] / "own-col" / "sub").exists()
        r = requests.request("MKCOL", _dav(lock_srv, "/own-col/sub/"),
                             headers={"If": f"({token})"}, timeout=10)
        assert r.status_code == 201, (
            f"the owner's own MKCOL was refused: {r.status_code} {r.text}")
        assert (lock_srv["dirs"]["shared"] / "own-col" / "sub").is_dir()
    finally:
        unlock_rc = _unlock(lock_srv, "/own-col/", token).status_code
    assert unlock_rc == 204


def test_owner_token_copies_onto_its_own_locked_destination(lock_srv):
    """COPY onto a LOCKED destination: tokenless refuses 423 with the
    destination bytes untouched (the COPY errno map used to render the lock
    refusal as a generic 409), and the owner's COPY with its If: token
    overwrites the destination."""
    src, dst = "own-cp-src.bin", "own-cp-dst.bin"
    for key, data in ((src, b"fresh"), (dst, b"stale")):
        r = requests.put(_dav(lock_srv, f"/{key}"), data=data, timeout=10)
        assert r.status_code in (200, 201, 204)
    r = _lock(lock_srv, f"/{dst}")
    assert r.status_code in (200, 201), r.text
    token = r.headers["Lock-Token"]
    headers = {"Destination": _dav(lock_srv, f"/{dst}"), "Overwrite": "T"}
    try:
        r = requests.request("COPY", _dav(lock_srv, f"/{src}"),
                             headers=headers, timeout=10)
        assert r.status_code == 423, (
            f"a tokenless COPY went through the destination lock: "
            f"{r.status_code}")
        assert (lock_srv["dirs"]["shared"] / dst).read_bytes() == b"stale"
        r = requests.request("COPY", _dav(lock_srv, f"/{src}"),
                             headers={**headers, "If": f"({token})"},
                             timeout=10)
        assert r.status_code in (201, 204), (
            f"the owner's own COPY was refused: {r.status_code} {r.text}")
        assert (lock_srv["dirs"]["shared"] / dst).read_bytes() == b"fresh"
    finally:
        unlock_rc = _unlock(lock_srv, f"/{dst}", token).status_code
    assert unlock_rc == 204


# --------------------------------------------------------------------------- #
# nginx -t negative                                                           #
# --------------------------------------------------------------------------- #
def _write_bad_enforcement_conf(d: str) -> str:
    os.makedirs(os.path.join(d, "logs"), exist_ok=True)
    os.makedirs(os.path.join(d, "exp"), exist_ok=True)
    conf = os.path.join(d, "nginx.conf")
    modules = [m for m in os.environ.get(
        "TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    with open(conf, "w") as fh:
        fh.write("".join(f"load_module {m};\n" for m in modules)
                 + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                 + "events {}\nstream {\n  server {\n"
                 + f"    listen {BIND_HOST}:{SHARED_PARSE_PLACEHOLDER_PORT};\n"
                 + "    brix_root on;\n    brix_auth none;\n"
                 + f"    brix_export {d}/exp;\n"
                 + "    brix_allow_write on;\n"
                 + "    brix_lock_enforcement yes;\n"
                 + "  }\n}\n")
    return conf


def test_lock_enforcement_bad_value_refused_at_nginx_t():
    """`brix_lock_enforcement yes;` is not an enum member: [emerg] at parse."""
    _need_nginx()
    with tempfile.TemporaryDirectory() as d:
        conf = _write_bad_enforcement_conf(d)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    out = r.stdout + r.stderr
    assert r.returncode != 0, "nginx -t accepted brix_lock_enforcement yes"
    assert 'invalid value "yes"' in out, out[-1500:]
