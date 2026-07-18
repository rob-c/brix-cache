"""Config-time HARD guard: a cache/state/stage tree nested inside an export is rejected.

Sidecars (.cinfo/.meta) and upload temps must never sit in a client-visible namespace. Beyond
the runtime name filter (test_mu_sidecar_hidden.py), the STRUCTURAL guarantee is that the
service trees are not in the export at all — enforced at config time: a nesting is a
deploy-blocking `nginx -t` error, not a warning. This test asserts each protocol rejects a
nested cache/stage tree and accepts one placed outside the export.

Run: PYTHONPATH=tests pytest tests/test_mu_sidecar_config_guard.py -v   (no root needed)
"""
import os
from types import SimpleNamespace

import pytest

from mu_authz_lib import ports, principals
from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

_TEMPLATES = {
    "stream": "nginx_mu_guard_stream.conf",
    "webdav": "nginx_mu_guard_webdav.conf",
    "s3": "nginx_mu_guard_s3.conf",
}


@pytest.fixture(scope="module")
def guard(tmp_path_factory):
    """The export tree plus a nested (inside-export) and an outside service tree.

    build_cast() ensures the test CA exists — the WebDAV auth precheck opens it
    during `nginx -t`."""
    principals.build_cast()
    root = tmp_path_factory.mktemp("mu_guard")
    export = root / "export"
    outside = root / "outside"
    nested = export / "svc"          # inside the export → must be rejected
    for d in (export, outside, nested):
        d.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        export=str(export), outside=str(outside), nested=str(nested),
        ca=os.path.join(ports.MU.CA_DIR, "ca.pem"),
    )


def _svc_directives(shape, kind, where, g):
    """The service-tree directive(s) under test, pointing inside or outside the export."""
    path = g.nested if where == "nested" else g.outside
    if shape == "stream":
        return {"stage": f"brix_stage_dir {path};",
                "state": f"brix_cache_state_root {path};"}[kind]
    if shape == "webdav":
        if kind == "cache_root":
            return f"brix_webdav_cache_root {path};"
        # cache_root OUTSIDE (valid) + stage nested (the tree under test)
        return f"brix_webdav_cache_root {g.outside};\nbrix_webdav_stage_dir {g.nested};"
    return f"brix_s3_cache_root {path};"   # s3


def _spec(label, shape, svc, g):
    return NginxInstanceSpec(
        name=f"lc-mu-guard-{label}",
        template=_TEMPLATES[shape],
        readiness="none",
        data_root=g.export,
        template_values={"EXPORT": g.export, "CA": g.ca, "SVC_DIRECTIVES": svc},
        reason="MU config-guard: nested service tree rejected at nginx -t.",
    )


def _nginx_t(lifecycle, spec):
    """Render + `nginx -t` via the harness; return (returncode, combined output).
    The launcher raises on a failing `nginx -t` — expected here, so unwrap it."""
    reg = lifecycle.register(spec)
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as failure:
        return failure.returncode, failure.stdout_tail + failure.stderr_tail
    return res.returncode, res.stdout + res.stderr


# (label, shape, kind, where, nested?) — nested must be rejected, outside accepted.
CASES = [
    ("stream-stage-nested",      "stream", "stage",      "nested",  True),
    ("stream-stage-outside",     "stream", "stage",      "outside", False),
    ("stream-state-nested",      "stream", "state",      "nested",  True),
    ("stream-state-outside",     "stream", "state",      "outside", False),
    ("webdav-cacheroot-nested",  "webdav", "cache_root", "nested",  True),
    ("webdav-cacheroot-outside", "webdav", "cache_root", "outside", False),
    ("webdav-stage-nested",      "webdav", "stage",      "nested",  True),
    ("s3-cacheroot-nested",      "s3",     "cache_root", "nested",  True),
    ("s3-cacheroot-outside",     "s3",     "cache_root", "outside", False),
]


@pytest.mark.parametrize("label,shape,kind,where,nested", CASES, ids=[c[0] for c in CASES])
def test_config_guard_rejects_nested_service_tree(lifecycle, guard, label, shape, kind, where, nested):
    svc = _svc_directives(shape, kind, where, guard)
    rc, out = _nginx_t(lifecycle, _spec(label, shape, svc, guard))
    if nested:
        assert rc != 0, f"{label}: a service tree inside the export MUST be rejected\n{out}"
        assert "at or beneath export root" in out, (
            f"{label}: rejected for the wrong reason (not the export-guard)\n{out}")
    else:
        assert rc == 0, f"{label}: a service tree outside the export must be accepted\n{out}"
