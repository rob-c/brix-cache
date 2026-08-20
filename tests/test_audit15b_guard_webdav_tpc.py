"""
test_audit15b_guard_webdav_tpc.py — the guard × WebDAV-TPC pair (audit §B1.5,
testsuite-combinatorial-coverage-audit 2026-08-15: "whether a guard-narrowed
location still admits COPY/MOVE for TPC is untested in both directions").

Now tested — and the answer, pinned here, is that the pair is INCOMPATIBLE by
construction today:

  * request time (src/net/httpguard/guard_http_req.c method_to_op): COPY and
    MOVE map to GUARD_OP_UNKNOWN, which no built-in profile admits — under the
    `xrdhttp` profile every WebDAV-TPC COPY/MOVE is grammar-bounced before the
    handler, regardless of prefix or signatures;
  * config time (src/net/httpguard/module.c method_name_to_op): the
    `brix_guard_valid_method` table has no COPY/MOVE entries either, so an
    operator cannot even allowlist them — the directive refuses the names at
    nginx -t.

So `brix_guard on` in front of a WebDAV location silently breaks HTTP-TPC (and
MKCOL/PROPPATCH DAV writes).  These tests pin the current behavior; if guard
ever learns a COPY op-class, the parse-negative here is the test that will
flag the semantic change.
"""

import os

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from guard_http_lib import AuditLog, GuardServer
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15b-guard-copy")]

SEED_BODY = "guarded-tpc-payload\n"

KNOBS = "            brix_guard_bounce_status 403;\n"


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


@pytest.fixture()
def guard(lifecycle, tmp_path):
    data = tmp_path / "data"
    (data / "store" / "data").mkdir(parents=True, exist_ok=True)
    (data / "store" / "data" / "file.txt").write_text(SEED_BODY)
    audit_path = tmp_path / "guard-copy-audit.log"
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15b-guard-copy",
        template="nginx_guard_knobs.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "AUDIT_LOG": str(audit_path),
                         "GUARD_KNOBS": KNOBS},
        reason="audit-15b guard x webdav-tpc COPY/MOVE pair"))
    server = GuardServer(HOST, endpoint.port)
    server.wait_ready("/store/data/file.txt")
    return server, AuditLog(str(audit_path))


def test_reads_pass_while_copy_is_probed(guard):
    # Control half: the same location serves plain reads, so the COPY bounce
    # below is method classification, not a broken instance.
    server, _ = guard
    r = server.get("/store/data/file.txt")
    assert r.status == 200 and r.body.decode() == SEED_BODY, r.status


@pytest.mark.parametrize("method", ["COPY", "MOVE"])
def test_dav_tpc_methods_grammar_bounced(guard, method):
    """CURRENT BEHAVIOR PIN: COPY/MOVE -> GUARD_OP_UNKNOWN -> grammar bounce
    under the xrdhttp profile, even on an in-prefix, non-signature path with a
    well-formed TPC Destination header.  A WebDAV-TPC deployment therefore
    cannot sit behind the guard today."""
    server, audit = guard
    baseline = audit.line_count()
    r = server.request(method, "/store/data/file.txt",
                       headers={"Destination":
                                f"http://{HOST}:1/store/data/copy.txt"})
    assert r.status == 403, (method, r.status)
    assert audit.wait_for_count(baseline + 1), method
    assert audit.last_line_has(signal="grammar"), method


def test_valid_method_cannot_allowlist_copy(tmp_path):
    """The other direction: the operator escape hatch does not exist —
    brix_guard_valid_method refuses the COPY name at nginx -t (its name table
    stops at the profile op-classes)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_guard_knobs.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, BIND_HOST=BIND_HOST,
                     DATA_ROOT=str(data), LOG_DIR=str(tmp_path),
                     TMP_DIR=str(tmp_path),
                     AUDIT_LOG=str(tmp_path / "audit.log"),
                     GUARD_KNOBS="            brix_guard_valid_method GET COPY;\n")
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0, out
    assert 'unknown method "COPY"' in out, out
