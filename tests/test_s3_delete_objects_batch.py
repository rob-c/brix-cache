"""Phase-107 C4 — S3 DeleteObjects as ONE VFS batch, live over the wire.

Pre-C4 the handler parsed the <Delete> document and called brix_vfs_unlink
once per key: 1,000 policy checks, 1,000 metric observations and — over a
remote (s3://) backend — 1,000 signed upstream round trips to serve the one
request whose purpose was to avoid exactly that.  C4 collects and CONFINES
every key first (nothing deleted yet), then disposes the batch in ONE
brix_vfs_delete_many() call: one phase-105 write gate, one OP_DELETE
observation, one driver batch where the leaf has unlink_many
(docs/refactor/phase-107-vfs-mutation-surface-completion.md §C4).

The doc's test matrix, over five fronts (nginx_p107_bulk_delete.conf):

  success   a 1,000-key DeleteObjects against an sd_remote export issues ONE
            upstream POST ?delete (origin access-log witness) and returns
            1,000 <Deleted> — and the bulk-delete metric pair books one batch
            carrying 1,000 keys in its VALUE, never a label;
  success   a mixed 998-present / 1-absent / 1-forbidden batch returns 999
            <Deleted> (ENOENT is idempotent-success) and exactly one
            <Error><Code>AccessDenied</Code> at the right key;
  success   collect-before-execute: a malformed <Object> anywhere in the body
            rejects the request BEFORE anything is deleted (the old
            parse-and-delete loop had already removed the keys ahead of it);
  error     a transport failure (dead origin) reports every key as untried —
            never as <Deleted>;
  sec-neg   brix_allow_write off => 403 for the WHOLE batch with no per-key
            disclosure of which keys exist;
  sec-neg   a ../ key is refused at confinement, identically whether or not
            the escaped path exists, and the file outside the root survives.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_s3_delete_objects_batch.py -v
"""
import os
import pathlib
import re
from xml.sax.saxutils import escape

import pytest
import requests

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p107-bulkdel")]

SPEC = "lc-p107-bulkdel"
BUCKET = "testbucket"
S3_AK = "AKIDP107BULKDELTST1"
S3_SK = "cDEwNy1idWxrLWRlbGV0ZS1iYXRjaC1zZWNyZXQ"


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    """One instance: s3-over-remote front + posix / read-only / dead-origin
    fronts + the origin whose access log witnesses the round-trip count."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    base = tmp_path_factory.mktemp("p107-bulkdel")
    dirs = {name: base / name for name in (
        "origin", "front_export", "posix_root", "ro_root", "dead_export")}
    for d in dirs.values():
        d.mkdir()
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_p107_bulk_delete.conf",
            protocol="s3",
            data_root=str(dirs["origin"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_DIR": str(dirs["origin"]),
                "FRONT_EXPORT": str(dirs["front_export"]),
                "POSIX_ROOT": str(dirs["posix_root"]),
                "RO_ROOT": str(dirs["ro_root"]),
                "DEADFRONT_EXPORT": str(dirs["dead_export"]),
                "S3_ACCESS_KEY": S3_AK,
                "S3_SECRET_KEY": S3_SK,
            },
            reason="phase-107 C4 DeleteObjects batch postures"))
        yield {
            "port": ep.port,
            "posix_port": ep.extra_ports["POSIX_PORT"],
            "ro_port": ep.extra_ports["RO_PORT"],
            "dead_port": ep.extra_ports["DEADFRONT_PORT"],
            "metrics": f"http://{HOST}:{ep.extra_ports['METRICS_PORT']}/metrics",
            "dirs": dirs,
            "origin_log": pathlib.Path(ep.prefix) / "logs" / "origin_access.log",
        }
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def _body(*keys):
    objects = "".join(f"<Object><Key>{escape(k)}</Key></Object>" for k in keys)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            f'<Delete>{objects}</Delete>').encode()


def _delete(port, payload):
    return requests.post(f"http://{HOST}:{port}/{BUCKET}/?delete",
                         data=payload,
                         headers={"Content-Type": "application/xml"},
                         timeout=120)


def _deleted_keys(xml_text):
    return re.findall(r"<Deleted><Key>(.*?)</Key></Deleted>", xml_text)


def _error_entries(xml_text):
    """[(key, code)] per <Error> element."""
    return re.findall(
        r"<Error><Key>(.*?)</Key><Code>(.*?)</Code>", xml_text)


def _origin_lines(srv):
    log = srv["origin_log"]
    return log.read_text().splitlines() if log.exists() else []


def _metric(srv, name, driver):
    text = requests.get(srv["metrics"], timeout=15).text
    m = re.search(
        rf'^{name}{{driver="{driver}"}} (\d+)$', text, re.MULTILINE)
    assert m, f"{name}{{driver={driver!r}}} missing from /metrics"
    return int(m.group(1))


def _seed(root, keys, payload=b"x"):
    for k in keys:
        (root / k).write_bytes(payload)


def _assert_all_gone(root, keys):
    survivors = [k for k in keys if (root / k).exists()]
    assert survivors == [], f"keys survived the batch: {survivors[:5]}"


def _upstream_batch_shape(new_lines):
    """(?delete POSTs, per-key DELETEs) among the new origin-log lines."""
    batch = [ln for ln in new_lines
             if ln.startswith("POST") and "delete" in ln]
    per_key = [ln for ln in new_lines if ln.startswith("DELETE ")]
    return batch, per_key


# --------------------------------------------------------------------------- #
# success                                                                      #
# --------------------------------------------------------------------------- #

def test_thousand_key_batch_is_one_upstream_request(srv):
    """(success) 1,000 keys over sd_remote: ONE upstream POST ?delete where
    the pre-C4 loop issued 1,000 signed DELETEs — and the metric pair books
    one batch whose VALUE carries the 1,000 keys (INVARIANT #8: the count is
    never a label)."""
    origin = srv["dirs"]["origin"]
    keys = [f"bulk/obj-{i:04d}.bin" for i in range(1000)]
    (origin / "bulk").mkdir(exist_ok=True)
    _seed(origin, keys)

    before_lines = len(_origin_lines(srv))
    batches0 = _metric(srv, "brix_vfs_bulk_delete_batches_total", "remote")
    keys0 = _metric(srv, "brix_vfs_bulk_delete_keys_total", "remote")

    r = _delete(srv["port"], _body(*keys))
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text[:400]}"
    assert len(_deleted_keys(r.text)) == 1000
    assert _error_entries(r.text) == []

    batch_posts, per_key = _upstream_batch_shape(_origin_lines(srv)[before_lines:])
    assert len(batch_posts) == 1, (
        f"expected ONE upstream ?delete batch, saw {len(batch_posts)}:\n"
        + "\n".join(batch_posts[:5]))
    assert per_key == [], (
        f"per-key upstream DELETEs leaked past the batch:\n"
        + "\n".join(per_key[:5]))

    _assert_all_gone(origin, keys)

    after = (_metric(srv, "brix_vfs_bulk_delete_batches_total", "remote"),
             _metric(srv, "brix_vfs_bulk_delete_keys_total", "remote"))
    assert after == (batches0 + 1, keys0 + 1000), (
        f"metric pair moved {after} from ({batches0}, {keys0}) — "
        "expected ONE batch carrying 1000 keys in its VALUE")


def test_mixed_batch_vocabulary(srv):
    """(success) 998 present + 1 absent + 1 forbidden: 999 <Deleted> (ENOENT
    is idempotent-success) and exactly one AccessDenied at the right key."""
    root = srv["dirs"]["posix_root"]
    present = [f"mix-{i:04d}.dat" for i in range(998)]
    _seed(root, present, b"y")
    absent = "never-existed.dat"
    forbidden = "../escaped.dat"

    r = _delete(srv["posix_port"], _body(*present, absent, forbidden))
    assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"

    deleted = _deleted_keys(r.text)
    assert len(deleted) == 999
    assert absent in deleted, "the absent key must render as idempotent <Deleted>"
    errors = _error_entries(r.text)
    assert len(errors) == 1, f"expected exactly one <Error>, got {errors[:5]}"
    assert errors[0][1] == "AccessDenied"
    assert errors[0][0] == escape(forbidden)

    _assert_all_gone(root, present)


def test_malformed_object_aborts_before_any_delete(srv):
    """(success — the collect-before-execute pin) a malformed <Object> after a
    valid key rejects the whole request with MalformedXML and the valid key's
    object SURVIVES.  The pre-C4 parse-and-delete loop had already removed
    every key ahead of the malformed one."""
    root = srv["dirs"]["posix_root"]
    victim = "survives-malformed.dat"
    (root / victim).write_bytes(b"z")

    payload = ('<?xml version="1.0" encoding="UTF-8"?><Delete>'
               f'<Object><Key>{victim}</Key></Object>'
               '<Object></Object>'          # no <Key> — malformed
               '</Delete>').encode()
    r = _delete(srv["posix_port"], payload)
    assert r.status_code == 400
    assert "MalformedXML" in r.text
    assert (root / victim).exists(), (
        "a key ahead of the malformed <Object> was deleted — the collect "
        "phase executed early")


# --------------------------------------------------------------------------- #
# error                                                                        #
# --------------------------------------------------------------------------- #

def test_transport_failure_reports_untried(srv):
    """(error) a dead origin fails the batch itself: *done stops short and
    every key renders as an <Error> (untried), never as <Deleted>."""
    keys = ["t/one.bin", "t/two.bin", "t/three.bin"]
    r = _delete(srv["dead_port"], _body(*keys))
    assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"
    assert _deleted_keys(r.text) == [], (
        "a key was reported <Deleted> through a DEAD origin")
    errors = _error_entries(r.text)
    assert len(errors) == 3
    assert all(code == "InternalError" for _, code in errors)


# --------------------------------------------------------------------------- #
# security-negative                                                            #
# --------------------------------------------------------------------------- #

def test_read_only_refuses_whole_batch_without_disclosure(srv):
    """(sec-neg) brix_allow_write off: ONE 403 for the whole request, before
    any key is examined — the response must not distinguish the existing key
    from the absent one, and the existing object survives."""
    root = srv["dirs"]["ro_root"]
    existing = "ro-present.dat"
    (root / existing).write_bytes(b"keep")

    r = _delete(srv["ro_port"], _body(existing, "ro-absent.dat"))
    assert r.status_code == 403, f"{r.status_code} {r.text[:400]}"
    assert "AccessDenied" in r.text
    assert "<Deleted>" not in r.text and "<DeleteResult" not in r.text, (
        "a read-only refusal leaked per-key results")
    assert existing not in r.text and "ro-absent.dat" not in r.text, (
        "the refusal echoed key names — per-key disclosure")
    assert (root / existing).exists()


def test_traversal_key_refused_without_existence_leak(srv):
    """(sec-neg) two ../ keys — one whose escaped target EXISTS, one whose
    target does not — must produce byte-identical refusals, and the file
    outside the export root survives."""
    root = srv["dirs"]["posix_root"]
    outside = root.parent / "outside-victim.bin"
    outside.write_bytes(b"must survive")

    r = _delete(srv["posix_port"],
                _body("../outside-victim.bin", "../no-such-target.bin"))
    assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"
    assert _deleted_keys(r.text) == []
    errors = _error_entries(r.text)
    assert len(errors) == 2
    codes = {code for _, code in errors}
    assert codes == {"AccessDenied"}, (
        f"traversal refusals differed — an existence oracle: {errors}")
    assert outside.exists() and outside.read_bytes() == b"must survive"
