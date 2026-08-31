"""
test_audit15_read_only.py — live coverage for the hard read-only switch
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15: `brix_read_only`
had ZERO test coverage on every plane while being fully wired).

The enforcement under test is brix_shared_apply_read_only()
(src/core/config/shared_conf.h): when `brix_read_only on`, allow_write is
forced OFF at merge time — even against an explicit `brix_allow_write on` —
so every existing protocol-edge write gate rejects writes before the VFS and
BEFORE token scope (INVARIANT 3).  These tests deliberately configure
`brix_allow_write on; brix_read_only on;` together: a pass proves the override,
not just the ordinary allow_write-off path (which other suites already cover).

  * WebDAV plane: PUT/DELETE/MKCOL -> 403 at the access phase
    (src/protocols/webdav/access.c write-method gate), GET still 200,
    and the backing store is byte-identical afterwards.
  * root:// plane: a write-mode kXR_open -> kXR_fsReadOnly
    "this is a read-only server" (src/protocols/root/read/open_request.c),
    read-mode opens unaffected.
  * Control: an identical instance WITHOUT read_only accepts the same PUT —
    the refusals above are read_only-driven, not a broken write path.
"""

import hashlib
import os
import pathlib
import re
import signal
import stat
import struct
import time

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from port_ladder import PORT_LAST
from utils.make_token import TokenIssuer
from test_phase25_ratelimit import (
    _start_http,
    _start_stream,
    _xrd_login,
    _xrd_open,
    _xrd_recv_status,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15-readonly")]

KXR_OK = 0
KXR_ERROR = 4003
KXR_FS_READONLY = 3025    # filesystem is mounted read-only (opcodes.h)

SEED = "read-only-seed\n"

# Both flags together on purpose — see module docstring.
_RO_KNOBS = ("            brix_allow_write on;\n"
             "            brix_read_only on;\n")
_RW_KNOBS = "            brix_allow_write on;\n"


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _xrd_open_write(s, path):
    # kXR_open = 3010; body: mode[2] options[2] reserved[12]; payload=path.
    payload = path.encode()
    opts = 0x0008 | 0x4000 | 0x0100   # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, opts, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _tree_witness(root):
    """Everything about an export tree a mutation could possibly disturb.

    Names alone would miss an in-place overwrite, a mode change from SITE CHMOD,
    a dead property or lock token written into an xattr, or a multipart part
    file assembled over the seed.  Comparing this mapping before and after a
    sweep is the W5 "no export digest/stat/xattr change" assertion in one value,
    and it also catches the stage/multipart/queue artefacts of W5 by noticing
    any path that appeared.
    """
    out = {}
    for path in sorted(root.rglob("*")):
        st = path.lstat()
        try:
            xattrs = {n: os.getxattr(path, n) for n in sorted(os.listxattr(path))}
        except OSError:                      # tmpfs without user_xattr
            xattrs = {}
        digest = (hashlib.sha256(path.read_bytes()).hexdigest()
                  if path.is_file() else None)
        out[str(path.relative_to(root))] = (stat.S_IFMT(st.st_mode),
                                            stat.S_IMODE(st.st_mode),
                                            st.st_size, st.st_mtime_ns,
                                            xattrs, digest)
    return out


def test_webdav_read_only_rejects_writes_serves_reads(lifecycle, tmp_path):
    """Success + error path (WebDAV): reads flow, every write method is 403,
    and the store on disk is untouched afterwards."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-readonly-http-reload",
                       _RO_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 1)
    base = f"http://{HOST}:{port}"
    data = tmp_path / "data"

    r = requests.get(f"{base}/seed.txt", timeout=5)
    assert r.status_code == 200 and r.text == SEED

    assert requests.put(f"{base}/new.txt", data=b"x", timeout=5).status_code == 403
    assert not (data / "new.txt").exists(), \
        "read-only PUT was refused but still materialised a file"

    assert requests.delete(f"{base}/seed.txt", timeout=5).status_code == 403
    assert (data / "seed.txt").read_text() == SEED, \
        "read-only DELETE was refused but still mutated the store"

    assert requests.request("MKCOL", f"{base}/newdir", timeout=5).status_code == 403
    assert not (data / "newdir").exists()


def test_webdav_control_without_read_only_accepts_put(lifecycle, tmp_path):
    """Negative control: the identical instance minus read_only accepts the
    same PUT — proving the 403s above are the read_only override at work."""
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-http-ctl-reload", _RW_KNOBS,
                       port=PORT_LAST + 2)
    r = requests.put(f"http://{HOST}:{port}/new.txt", data=b"payload", timeout=5)
    assert r.status_code in (200, 201, 204), r.status_code
    assert (tmp_path / "data" / "new.txt").read_bytes() == b"payload"


def test_root_read_only_write_open_refused_read_open_ok(lifecycle, tmp_path):
    """Security-negative (root://): with allow_write EXPLICITLY on, read_only
    still refuses a write-mode open with kXR_fsReadOnly at the protocol edge
    (nothing is created on disk), while a read open of the seeded file works."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "seed.bin").write_bytes(b"\x5a" * 64)
    knobs = ("        brix_allow_write on;\n"
             "        brix_read_only on;\n")
    port = _start_stream(lifecycle, data,
                         "lc-audit15-readonly-stream-reload", knobs, "",
                         port=PORT_LAST + 3)
    s = _xrd_login(HOST, port)
    try:
        st_r, b_r = _xrd_open(s, "/seed.bin")
        assert st_r == KXR_OK, (st_r, b_r)

        st_w, b_w = _xrd_open_write(s, "/forged.bin")
        assert st_w == KXR_ERROR, (st_w, b_w)
        assert struct.unpack(">I", b_w[:4])[0] == KXR_FS_READONLY, b_w
        assert b"read-only" in b_w, b_w
    finally:
        s.close()
    assert not (data / "forged.bin").exists(), \
        "write-open was refused but still created the file"


# --------------------------------------------------------------------------- #
# Phase 105 W4 — the complete WebDAV mutating-method surface                   #
#                                                                             #
# The tests above cover PUT/DELETE/MKCOL, the methods nginx itself knows as    #
# writes.  Phase 105 W4 additionally requires that LOCK, UNLOCK, PROPPATCH,    #
# COPY and MOVE refuse a read-only export BEFORE any body is read and before   #
# any work happens — LOCK/UNLOCK in particular are classified                  #
# BRIX_PROTO_OP_LOCK and not BRIX_PROTO_OP_WRITE in operation_table.c, so they #
# are the methods most likely to slip past a write-flag-only edge gate and     #
# reach the VFS.                                                              #
# --------------------------------------------------------------------------- #

_LOCKINFO = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
    '<D:locktype><D:write/></D:locktype>'
    '<D:owner><D:href>tester</D:href></D:owner></D:lockinfo>'
)
_PROPPATCH = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:propertyupdate xmlns:D="DAV:" xmlns:X="urn:brix:test">'
    '<D:set><D:prop><X:phase>105</X:phase></D:prop></D:set>'
    '</D:propertyupdate>'
)

# (method, request body, extra headers) — every mutating DAV verb the tests
# above do not already reach.
_DAV_MUTATIONS = (
    ("PROPPATCH", _PROPPATCH, {"Content-Type": "text/xml"}),
    ("LOCK",      _LOCKINFO,  {"Content-Type": "text/xml",
                               "Timeout": "Second-60"}),
    ("UNLOCK",    "",         {"Lock-Token": "<opaquelocktoken:phase105>"}),
    ("COPY",      "",         {"Destination": "/copied.txt", "Overwrite": "T"}),
    ("MOVE",      "",         {"Destination": "/moved.txt", "Overwrite": "T"}),
)


def test_read_only_refuses_the_whole_dav_mutation_surface(lifecycle, tmp_path):
    """Error + security-negative (WebDAV): every remaining mutating DAV verb is
    refused on a read-only export with 403, and afterwards the export is
    byte-identical — no lock target, no dead property, no copy, no move.

    403 is the WebDAV read-only answer; a 405 would mean the method is simply
    unimplemented, which proves nothing about the policy, so it is rejected
    just as loudly as a 200 would be.
    """
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-dav-surface-reload", _RO_KNOBS,
                       seed_files=(("seed.txt", SEED),), port=PORT_LAST + 4)
    base = f"http://{HOST}:{port}"
    data = tmp_path / "data"

    before = _tree_witness(data)

    seen = {}
    for method, body, headers in _DAV_MUTATIONS:
        r = requests.request(method, f"{base}/seed.txt", data=body.encode(),
                             headers=headers, timeout=5)
        seen[method] = r.status_code

    assert seen == {m[0]: 403 for m in _DAV_MUTATIONS}, seen
    assert (data / "seed.txt").read_text() == SEED
    assert _tree_witness(data) == before, \
        "a refused DAV mutation still disturbed the export tree"


def test_writable_control_accepts_the_dav_lock_surface(lifecycle, tmp_path):
    """Success control: the identical instance minus read_only answers LOCK
    with a lock token rather than 403, proving the refusals above come from the
    policy and not from an unimplemented or globally broken lock path."""
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-dav-ctl-reload", _RW_KNOBS,
                       seed_files=(("seed.txt", SEED),), port=PORT_LAST + 5)
    r = requests.request("LOCK", f"http://{HOST}:{port}/seed.txt",
                         data=_LOCKINFO.encode(),
                         headers={"Content-Type": "text/xml",
                                  "Timeout": "Second-60"}, timeout=5)
    assert r.status_code in (200, 201), (r.status_code, r.text[:200])
    assert "opaquelocktoken" in r.text, r.text[:200]


# --------------------------------------------------------------------------- #
# Phase 105 W4 — the S3 mutating surface                                      #
#                                                                             #
# W4 requires object writes, tagging, user metadata, batch delete, the whole   #
# multipart lifecycle and server-side copy to answer an S3-SHAPED 403 (an      #
# <Error><Code>AccessDenied</Code></Error> document, not nginx's HTML page),   #
# with no upload, part or finalise side effect anywhere on the export.  The    #
# gates sit at the top of the PUT/DELETE/POST dispatchers in                   #
# handler_object_route.c and handler_dispatch.c, ahead of every query-flag     #
# branch, so this sweep is what proves none of those branches routes around    #
# them.                                                                       #
# --------------------------------------------------------------------------- #

_S3_RO_KNOBS = ("            brix_allow_write on;\n"
                "            brix_read_only on;\n")
_S3_RW_KNOBS = "            brix_allow_write on;\n"

_S3_TAGGING = ("<Tagging><TagSet><Tag><Key>phase</Key><Value>105</Value>"
               "</Tag></TagSet></Tagging>")
_S3_BATCH_DELETE = ("<Delete><Object><Key>seed.txt</Key></Object></Delete>")
_S3_MPU_COMPLETE = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                    "</Part></CompleteMultipartUpload>")

# (label, method, url suffix under the bucket, body, headers)
_S3_MUTATIONS = (
    ("put-object",     "PUT",    "/seed.txt",                    b"x",   {}),
    ("put-usermeta",   "PUT",    "/meta.txt",                    b"x",
     {"x-amz-meta-phase": "105"}),
    ("server-copy",    "PUT",    "/copy.txt",                    b"",
     {"x-amz-copy-source": "/robucket/seed.txt"}),
    ("put-tagging",    "PUT",    "/seed.txt?tagging",            _S3_TAGGING.encode(), {}),
    ("delete-object",  "DELETE", "/seed.txt",                    b"",    {}),
    ("delete-tagging", "DELETE", "/seed.txt?tagging",            b"",    {}),
    ("mpu-initiate",   "POST",   "/mpu.txt?uploads",             b"",    {}),
    ("mpu-upload-part","PUT",    "/mpu.txt?partNumber=1&uploadId=phase105", b"x", {}),
    ("mpu-complete",   "POST",   "/mpu.txt?uploadId=phase105",   _S3_MPU_COMPLETE.encode(), {}),
    ("mpu-abort",      "DELETE", "/mpu.txt?uploadId=phase105",   b"",    {}),
    ("batch-delete",   "POST",   "?delete",                      _S3_BATCH_DELETE.encode(), {}),
)


def _start_s3(lifecycle, tmp_path, name, knobs, port):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "seed.txt").write_text(SEED)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_ro_s3.conf", protocol="http",
        data_root=str(data), port=port,
        template_values={"BIND_HOST": BIND_HOST, "S3_KNOBS": knobs},
        reason="phase-105 W4 read-only S3 mutation surface"))
    return endpoint.port, data


def test_read_only_refuses_the_whole_s3_mutation_surface(lifecycle, tmp_path):
    """Error + security-negative (S3): every mutating S3 request is refused
    with an S3-shaped 403 AccessDenied, and afterwards the export holds exactly
    the seed — no object, no tag sidecar, no multipart upload directory."""
    port, data = _start_s3(lifecycle, tmp_path, "lc-audit15-readonly-s3-reload",
                           _S3_RO_KNOBS, PORT_LAST + 6)
    base = f"http://{HOST}:{port}/robucket"

    before = _tree_witness(data)

    seen = {}
    for label, method, suffix, body, headers in _S3_MUTATIONS:
        r = requests.request(method, f"{base}{suffix}", data=body,
                             headers=headers, timeout=5)
        seen[label] = (r.status_code, "AccessDenied" in r.text)

    assert seen == {m[0]: (403, True) for m in _S3_MUTATIONS}, seen

    # The read side still works, and nothing beneath the export root moved.
    # s3_get_mpu_dir() stages a multipart upload at <fs_path>/<upload_id> and
    # assembles it into a sibling temp, so an initiate or upload-part that got
    # past the gate would show up here as a new path.
    assert requests.get(f"{base}/seed.txt", timeout=5).text == SEED
    assert _tree_witness(data) == before, \
        "a refused S3 mutation still disturbed the export tree"


def test_writable_s3_control_accepts_the_same_object_put(lifecycle, tmp_path):
    """Success control: the identical endpoint minus read_only accepts the very
    first request of the sweep, proving the 403s are the policy and not a
    broken or unauthenticated S3 write path."""
    port, data = _start_s3(lifecycle, tmp_path, "lc-audit15-readonly-s3-ctl-reload",
                           _S3_RW_KNOBS, PORT_LAST + 7)
    r = requests.put(f"http://{HOST}:{port}/robucket/written.txt",
                     data=b"payload", timeout=5)
    assert r.status_code == 200, (r.status_code, r.text[:200])
    assert (data / "written.txt").read_bytes() == b"payload"


# ---------------------------------------------------------------------------
# W5 — configuration reload
#
# The typed policy is copied by value into the VFS context at request time and
# into every object that outlives it (Appendix D.5/D.7/D.8), which is what makes
# a queued job immune to a policy swap under its feet.  The flip side is the
# question this section answers: a reload MUST still be able to change the
# policy, or "immutable" would have quietly become "unchangeable", and an
# operator who took an export read-only after an incident would be told the
# reload succeeded while the old policy kept serving.
#
# nginx's own model gives the answer both directions: the master re-reads the
# file, forks workers that build fresh merged configuration, and the old workers
# finish their in-flight requests under the configuration they were forked with.
# So the assertion is about the NEW workers, and it is made by polling — a
# graceful reload is not synchronous, and a fixed sleep would either flake or
# waste the difference.
# ---------------------------------------------------------------------------

_RELOAD_TIMEOUT = 20.0


def _start_dav_endpoint(lifecycle, tmp_path, name, knobs, port):
    """Same instance the surface tests use, but handing back the endpoint —
    a reload needs the rendered config path and the pidfile, not just a port."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "seed.txt").write_text(SEED)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_rl_http.conf", protocol="http",
        data_root=str(data), port=port,
        template_values={"BIND_HOST": BIND_HOST, "RL_KNOBS": knobs,
                         "HTTP_EXTRA": "", "EXTRA_LOCATIONS": ""},
        reason="phase-105 W5 read-only policy across a config reload"))
    return endpoint, data


def _reload(endpoint, old_knobs, new_knobs):
    """Swap the policy knobs in the live config and SIGHUP the master."""
    conf = pathlib.Path(endpoint.config)
    text = conf.read_text()
    assert old_knobs in text, "the knob block moved; this test edits the wrong text"
    conf.write_text(text.replace(old_knobs, new_knobs, 1))

    pid = int(pathlib.Path(endpoint.pidfile).read_text().split()[0])
    os.kill(pid, signal.SIGHUP)


def _poll_put(base, deadline_s, want):
    """Poll a PUT until it answers `want`, or give up.  Returns the last status.

    Each probe writes to its own name so a success cannot be mistaken for the
    idempotent replay of an earlier one.
    """
    deadline = time.monotonic() + deadline_s
    last = None
    i = 0
    while time.monotonic() < deadline:
        i += 1
        r = requests.put(f"{base}/reload-probe-{i}.txt", data=b"payload",
                         timeout=5)
        last = r.status_code
        if last == want:
            return last
        time.sleep(0.25)
    return last


def test_a_reload_can_open_a_read_only_export(lifecycle, tmp_path):
    """Success: read-only is policy, not a one-way door.

    Refuse first, drop `brix_read_only`, SIGHUP, and the new workers accept the
    same PUT.  Without this the immutability the phase relies on could be
    satisfied by a policy that simply never changes, which is a different and
    much worse property.
    """
    endpoint, data = _start_dav_endpoint(
        lifecycle, tmp_path, "lc-audit15-readonly-reload-open",
        _RO_KNOBS, PORT_LAST + 8)
    base = f"http://{HOST}:{endpoint.port}"

    assert requests.put(f"{base}/before.txt", data=b"x",
                        timeout=5).status_code == 403
    assert not (data / "before.txt").exists()

    _reload(endpoint, _RO_KNOBS, _RW_KNOBS)

    assert _poll_put(base, _RELOAD_TIMEOUT, 201) == 201, \
        "the reload never took: the export stayed read-only"


def test_a_reload_can_close_a_writable_export(lifecycle, tmp_path):
    """Security-negative, and the direction that actually matters: an operator
    taking a live export read-only must be obeyed.

    Write first to prove the endpoint really was writable, then add
    `brix_read_only`, SIGHUP, and the same PUT must become 403 and stay 403 —
    and the object written before the reload must still be readable, because a
    read-only export is still an export.
    """
    endpoint, data = _start_dav_endpoint(
        lifecycle, tmp_path, "lc-audit15-readonly-reload-close",
        _RW_KNOBS, PORT_LAST + 9)
    base = f"http://{HOST}:{endpoint.port}"

    assert requests.put(f"{base}/before.txt", data=b"payload",
                        timeout=5).status_code == 201
    assert (data / "before.txt").read_bytes() == b"payload"

    _reload(endpoint, _RW_KNOBS, _RO_KNOBS)

    assert _poll_put(base, _RELOAD_TIMEOUT, 403) == 403, \
        "the export was still accepting writes after being taken read-only"

    # Settled, not merely transiently refusing while a worker was still forking.
    before = _tree_witness(data)
    for verb, kwargs in (("PUT", {"data": b"again"}),
                         ("DELETE", {}),
                         ("MKCOL", {})):
        r = requests.request(verb, f"{base}/before.txt", timeout=5, **kwargs)
        assert r.status_code == 403, (verb, r.status_code)
    assert _tree_witness(data) == before
    assert requests.get(f"{base}/before.txt", timeout=5).content == b"payload"


# ---------------------------------------------------------------------------
# W5 / §9.3 — a write-scoped bearer does not buy a write
#
# INVARIANT 3 says the endpoint write check runs BEFORE token scope, and this is
# the test that makes that ordering observable rather than merely intended.  A
# WLCG `storage.modify:/` token is exactly the credential an operator would
# expect to work, which is what makes it the right probe: if scope were consulted
# first, or if the two were ANDed in the wrong order by some future refactor,
# this bearer is the one that would slip through.  The refusal must not depend on
# the token being bad — it must not depend on the token at all.
# ---------------------------------------------------------------------------

_TOK_ISSUER = "https://phase105.example/"
_TOK_AUD = "phase105"


def _start_token_endpoint(lifecycle, tmp_path, name, read_only, port):
    """A token-trusting WebDAV export with `brix_webdav_auth required`, so the
    bearer below is genuinely validated rather than waved through."""
    issuer = TokenIssuer(str(tmp_path / "tokens"), issuer=_TOK_ISSUER,
                         audience=_TOK_AUD)
    issuer.init_keys()

    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "seed.txt").write_text(SEED)

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_ro_token.conf", protocol="http",
        data_root=str(data), port=port,
        template_values={"BIND_HOST": BIND_HOST, "JWKS": issuer.jwks_path,
                         "ISSUER": _TOK_ISSUER, "AUD": _TOK_AUD,
                         "RO_KNOBS": _RO_KNOBS if read_only else _RW_KNOBS},
        reason="phase-105 W5 write-scoped token vs endpoint read-only"))
    return endpoint, data, issuer


def _write_bearer(issuer):
    return {"Authorization": "Bearer " + issuer.generate(
        sub="writer", scope="storage.read:/ storage.modify:/")}


def test_a_write_scoped_token_cannot_bypass_endpoint_read_only(lifecycle,
                                                               tmp_path):
    """Security-negative: the strongest credential the system mints is refused.

    `storage.modify:/` is a genuine write grant from a trusted issuer, on an
    endpoint configured `brix_webdav_auth required` so the bearer is actually
    verified — and it is still 403, because endpoint read-only is not an
    authorization question and no credential answers it.

    The unauthenticated probe first is what makes the rest evidence: it proves
    the endpoint really does demand a token, so the 403s below cannot be the
    endpoint refusing everyone, and the 200 on the read proves this particular
    token really is accepted.
    """
    endpoint, data, issuer = _start_token_endpoint(
        lifecycle, tmp_path, "lc-audit15-readonly-token-scope",
        read_only=True, port=PORT_LAST + 10)
    base = f"http://{HOST}:{endpoint.port}"
    bearer = _write_bearer(issuer)

    # No bearer: refused, so the endpoint is genuinely token-gated.
    assert requests.get(f"{base}/seed.txt", timeout=5).status_code in (401, 403)

    # With the bearer: the token is good and opens the read side of this export.
    got = requests.get(f"{base}/seed.txt", headers=bearer, timeout=5)
    assert got.status_code == 200 and got.text == SEED, got.status_code

    before = _tree_witness(data)
    for verb, kwargs in (("PUT", {"data": b"scoped"}),
                         ("DELETE", {}),
                         ("MKCOL", {}),
                         ("PROPPATCH", {"data": _PROPPATCH.encode(),
                                        "headers": {"Content-Type": "text/xml"}})):
        headers = dict(bearer, **kwargs.pop("headers", {}))
        r = requests.request(verb, f"{base}/seed.txt", headers=headers,
                             timeout=5, **kwargs)
        assert r.status_code == 403, (verb, r.status_code, r.text[:200])
    assert _tree_witness(data) == before


def test_the_same_token_writes_once_read_only_is_lifted(lifecycle, tmp_path):
    """Success control: identical endpoint and identical write-scoped bearer,
    minus `brix_read_only`, and the PUT lands.  This is what pins the refusal
    above to the endpoint policy rather than to anything about the token, the
    scope parser, or the auth mode."""
    endpoint, data, issuer = _start_token_endpoint(
        lifecycle, tmp_path, "lc-audit15-readonly-token-scope-ctl",
        read_only=False, port=PORT_LAST + 11)

    r = requests.put(f"http://{HOST}:{endpoint.port}/written.txt",
                     data=b"scoped", headers=_write_bearer(issuer), timeout=5)
    assert r.status_code == 201, (r.status_code, r.text[:200])
    assert (data / "written.txt").read_bytes() == b"scoped"


# ---------------------------------------------------------------------------
# W5 / §9.2 — the positive control the whole phase is judged against
#
# Every assertion above is a refusal, and a gate that refused EVERYTHING would
# satisfy all of them.  These are the read verbs that must be untouched: the
# plain read, the metadata read, the enumeration, the digest, and the space
# report — the last two being the interesting ones, because `query_checksum`
# WRITES a `user.XrdCks.<alg>` cache xattr on success and `space` reaches the
# driver.  A read-only export must answer both correctly; the digest is simply
# not cached, and integrity_persist_computed() drops the EROFS on purpose.
# ---------------------------------------------------------------------------

def test_read_only_leaves_every_read_verb_working(lifecycle, tmp_path):
    """Success control across the read surface of a read-only export."""
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-read-surface", _RO_KNOBS,
                       seed_files=(("seed.txt", SEED),), port=PORT_LAST + 12)
    base = f"http://{HOST}:{port}"

    assert requests.get(f"{base}/seed.txt", timeout=5).text == SEED
    assert requests.head(f"{base}/seed.txt", timeout=5).status_code == 200

    # Enumeration and the RFC-4331 space report, both via PROPFIND.
    propfind = requests.request(
        "PROPFIND", f"{base}/", timeout=5,
        headers={"Depth": "1", "Content-Type": "text/xml"},
        data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
             b"<D:allprop/></D:propfind>")
    assert propfind.status_code == 207, propfind.status_code
    assert "seed.txt" in propfind.text

    # Want-Digest: computed on the fly, answered, and NOT cached — the cache
    # write is the one mutation this request would otherwise make.
    digest = requests.get(f"{base}/seed.txt", timeout=5,
                          headers={"Want-Digest": "sha-256"})
    assert digest.status_code == 200 and digest.text == SEED
    assert "Digest" in digest.headers, sorted(digest.headers)

    seed = tmp_path / "data" / "seed.txt"
    assert "XrdCks" not in str(os.listxattr(seed)), \
        "a read-only export cached a checksum xattr it was not allowed to write"


# ---------------------------------------------------------------------------
# The denial counter is a TRIPWIRE, and this proves both of its states.       #
#                                                                             #
# Every ordinary mutation on a read-only endpoint is refused at the protocol  #
# edge (403/550/kXR_fsReadOnly) before the VFS is reached, so                 #
# brix_vfs_mutation_denied_total must stay ALL ZERO across the whole refused  #
# sweep — a non-zero cell here means a verb slipped past its edge gate and    #
# only the VFS authority of last resort caught it, which the wire status can  #
# never reveal (both layers answer 403).  The counter's ability to move at    #
# all is proved by tests/c/test_vfs_read_only_spy.c, which drives the kernel  #
# directly and asserts the metric sink fires on every EROFS refusal.         #
# ---------------------------------------------------------------------------

_METRICS_LOCATION = "        location /metrics { brix_metrics on; }\n"


def _denied_cells(base):
    """Every brix_vfs_mutation_denied_total sample as {(proto, op): value}."""
    scrape = requests.get(f"{base}/metrics", timeout=5)
    assert scrape.status_code == 200
    pat = re.compile(
        r'^brix_vfs_mutation_denied_total\{proto="([^"]+)",op="([^"]+)",'
        r'reason="read_only"\} (\d+)$', re.M)
    return {(proto, op): int(value)
            for proto, op, value in pat.findall(scrape.text)}


def _fire_refused_sweep(base):
    """Drive every mutating DAV verb at the endpoint; the simple three must be
    403, the _DAV_MUTATIONS statuses are already pinned by the surface test."""
    for verb, kwargs in (("PUT", {"data": b"tripwire"}),
                         ("DELETE", {}),
                         ("MKCOL", {})):
        assert requests.request(verb, f"{base}/tripwire-probe",
                                timeout=5, **kwargs).status_code == 403
    for method, body, headers in _DAV_MUTATIONS:
        requests.request(method, f"{base}/seed.txt", data=body.encode(),
                         headers=headers, timeout=5)


def test_every_refusal_happens_at_the_edge_not_the_vfs(lifecycle, tmp_path):
    """Security-negative (depth): the full refused DAV sweep leaves the VFS
    denial counter untouched — the edge caught every verb first, wire-shaped
    and before any body was read.  The family itself must be present with the
    closed vocabulary, or the tripwire is dark rather than quiet."""
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-metric-tripwire", _RO_KNOBS,
                       extra_locations=_METRICS_LOCATION,
                       seed_files=(("seed.txt", SEED),), port=PORT_LAST + 13)
    base = f"http://{HOST}:{port}"

    _fire_refused_sweep(base)
    cells = _denied_cells(base)

    assert cells, "brix_vfs_mutation_denied_total missing from the exporter"
    ops = {op for _, op in cells}
    assert ops == {"open", "write", "truncate", "sync", "mkdir", "remove",
                   "rename", "copy", "setattr", "xattr", "publish"}, ops
    tripped = {cell: n for cell, n in cells.items() if n}
    assert not tripped, (
        f"a mutation slipped past its protocol edge and was only refused by "
        f"the VFS authority of last resort: {tripped}")


# ---------------------------------------------------------------------------
# Expired-lock reaping is a WRITE (phase-105 Appendix H.2): the read verbs    #
# that normally reap a stale lock (GET, lockdiscovery PROPFIND) must leave    #
# even a decodable, long-expired lock xattr byte-identical on a read-only    #
# export.  The writable control proves the fixture record IS reapable, so    #
# survival above is the policy's doing rather than an unparseable payload.   #
# ---------------------------------------------------------------------------

_LOCK_XATTR = "user.nginx_xrootd.lock"      # WEBDAV_LOCK_XATTR_KEY (webdav.h)


def _seed_expired_lock(data):
    """Plant a schema-v2 lock xattr on seed.txt that expired an hour ago."""
    payload = ("v=2|token=opaquelocktoken:00000000-dead-beef-0000-0000phase105"
               f"|owner=phase105|expires={int(time.time()) - 3600}"
               "|scope=exclusive|depth=infinity|null=0").encode()
    os.setxattr(data / "seed.txt", _LOCK_XATTR, payload)
    return payload


def _lock_after_read_sweep(base, data):
    """GET + explicit lockdiscovery PROPFIND (the expired-lock cleanup call
    sites in lock_discovery.c), then the lock xattr's current value, or None
    once a reap removed it."""
    assert requests.get(f"{base}/seed.txt", timeout=5).text == SEED
    r = requests.request(
        "PROPFIND", f"{base}/seed.txt", timeout=5,
        headers={"Depth": "0", "Content-Type": "text/xml"},
        data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
             b"<D:prop><D:lockdiscovery/></D:prop></D:propfind>")
    assert r.status_code == 207, r.status_code
    try:
        return os.getxattr(data / "seed.txt", _LOCK_XATTR)
    except OSError:
        return None


def test_read_only_export_keeps_an_expired_lock_xattr(lifecycle, tmp_path):
    """Security-negative: expired-lock cleanup is a mutation, and a read-only
    endpoint performs none — not even against metadata it itself planted."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-readonly-lock-reap",
                       _RO_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 14)
    data = tmp_path / "data"
    payload = _seed_expired_lock(data)

    after = _lock_after_read_sweep(f"http://{HOST}:{port}", data)
    assert after == payload, \
        "a read verb on a read-only export reaped or rewrote the lock xattr"


def test_writable_export_reaps_the_same_expired_lock(lifecycle, tmp_path):
    """Success control: writes allowed, the identical stale record is reaped by
    the same read sweep."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-rw-lock-reap",
                       _RW_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 15)
    data = tmp_path / "data"
    _seed_expired_lock(data)

    after = _lock_after_read_sweep(f"http://{HOST}:{port}", data)
    assert after is None, "the writable control did not reap the expired lock"
