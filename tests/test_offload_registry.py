"""Per-worker (sessid,pathid) -> secondary-connection offload map (audit §1.1).

Slice 1 of pathid response offloading: kXR_bind records a secondary data
channel's connection in a per-worker table (`brix_offload_register`), the
disconnect path clears it (`brix_offload_unregister`), and — in the next slice —
the read/readv handler will consult it (`brix_offload_lookup`) to route a
pathid-tagged response out the secondary's socket instead of the control stream.

This slice only maintains the table (nothing consults it yet, so the data path is
unchanged); its logic is verified as a standalone C unit test against the real
compiled offload_registry.o — register/lookup/replace/unregister, the pathid-0
and miss cases, NULL-arg guards, and the bounded-capacity refusal.

Run:
    PYTHONPATH=tests pytest tests/test_offload_registry.py -v
"""

import os

import pytest

from cmdscripts import c_object_units

_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_OBJ = os.path.join(_OBJS, "addon", "session", "offload_registry.o")

pytestmark = [pytest.mark.timeout(120)]


def test_offload_registry_unit(tmp_path):
    if not os.path.exists(_OBJ):
        pytest.skip(f"offload_registry.o not built under {_OBJS}; build the module first")
    (ok, out), = c_object_units.run_checks(tmp_path, ["offload_registry"])
    if out.startswith("SKIP"):
        pytest.skip(out)
    assert ok, f"offload_registry unit tests failed:\n{out}"
    assert "0 failed" in out, f"unexpected offload_registry output:\n{out}"
