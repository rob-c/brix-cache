"""Render + start/stop the paired MU fleet (spec §8.1).

Registry-lifecycle rewrite (phase-81): every server is a dynamically-ported
``NginxInstanceSpec`` rendered from a committed ``configs/multiuser/*.conf``
template and driven through a ``LifecycleHarness`` — no nginx config is
hand-rolled and no nginx process is launched directly.  Ports are allocated
dynamically on first ``start()`` and written back onto ``ports.MU`` so the
``url()`` seam and every consumer that reads ``ports.MU.*`` transparently see
the live port; the assignment is remembered so ``apply_policy``/``revoke``
reloads (stop→start) keep each endpoint stable.

Live start/stop needs privilege (real accounts + setuid); the whole suite is
root-gated in conftest_mu.py.  ``render_configs`` + ``url`` are usable
unprivileged (config generation happens lazily at ``start()``).
"""
import os

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

from . import creds, ports

_svc_s3 = creds.s3_key_for("svc")

# (template, ports.MU attribute, protocol).  Order is load-bearing: the anonymous
# origin must be up before the cache node that fills from it over root://.
_SERVERS = [
    ("multiuser/root_origin_noimp.conf",      "ORIGIN_NOIMP", "root"),
    ("multiuser/root_cache_noimp.conf",       "CACHE_NOIMP",  "root"),
    ("multiuser/root_direct_authz_noimp.conf", "DIRECT_AUTHZ", "root"),
    ("multiuser/sidecar_root_anon.conf",      "SIDECAR_ROOT", "root"),
    ("multiuser/webdav_authz_noimp.conf",     "WEBDAV_AUTHZ", "https"),
    ("multiuser/webdav_stage_noimp.conf",     "WEBDAV_STAGE", "https"),
]

_harness: "LifecycleHarness | None" = None
_backends: dict = {}
_assigned: "dict[str, int]" = {}  # ports.MU attr -> port (stable across reloads)


def _common_values() -> dict:
    """Placeholder values shared by every MU template (brace-less kwargs form).
    The launcher supplies PORT / LOG_DIR / TMP_DIR / DATA_ROOT per instance."""
    return {
        "BIND_HOST": ports.MU.HOST,
        "DATA_DIR": ports.MU.DATA_ROOT,
        "CACHE_DIR": ports.MU.CACHE_ROOT,
        "VOMSDIR": ports.MU.VOMSDIR,
        "CA_DIR": ports.MU.CA_DIR,
        "CA": os.path.join(ports.MU.CA_DIR, "ca.pem"),
        "CERT": os.path.join(ports.MU.PKI_DIR, "server", "hostcert.pem"),
        "KEY": os.path.join(ports.MU.PKI_DIR, "server", "hostkey.pem"),
        "JWKS": os.path.join(ports.MU.TOKENS_DIR, "jwks.json"),
        "S3_SVC_KEY": _svc_s3[0],
        "S3_SVC_SECRET": _svc_s3[1],
        "GRIDMAP": _backends.get("gridmap", ""),
        "AUTHDB": _backends.get("authdb", ""),
        "VO": _backends.get("vo", ""),
        "S3KEYS": _backends.get("s3keys", ""),
    }


def render_configs(backends: dict) -> None:
    """Stash the policy-rendered backends and ensure the shared trees exist.
    The actual per-server config render + ``nginx -t`` validation happens inside
    the harness at ``start()`` (one prefix per instance)."""
    global _backends
    _backends = dict(backends)
    for d in (ports.MU.DATA_ROOT, ports.MU.CACHE_ROOT, ports.MU.LOG_DIR):
        os.makedirs(d, exist_ok=True)


def start() -> None:
    global _harness
    _harness = LifecycleHarness()
    for template, attr, proto in _SERVERS:
        values = _common_values()
        # The cache node fills from the anonymous origin started just above.
        values["ORIGIN_NOIMP_PORT"] = ports.MU.ORIGIN_NOIMP
        endpoint = _harness.start(NginxInstanceSpec(
            name=f"mu-{attr.lower()}",
            template=template,
            port=_assigned.get(attr),   # None => dynamic; pinned on reload
            protocol=proto,
            data_root=ports.MU.DATA_ROOT,
            readiness="tcp",
            template_values=values,
        ))
        _assigned[attr] = endpoint.port
        setattr(ports.MU, attr, endpoint.port)


def stop() -> None:
    global _harness
    if _harness is not None:
        _harness.close()
        _harness = None


def wait_listening(timeout: int = 15) -> None:
    """No-op: the harness gates TCP readiness per instance at ``start()``."""
    return None


def url(proto: str, variant: str) -> str:
    port = getattr(ports.MU, f"{proto.upper()}_{variant.upper()}")
    scheme = {"root": "root", "webdav": "https", "s3": "http"}[proto]
    return f"{scheme}://{ports.MU.HOST}:{port}"
