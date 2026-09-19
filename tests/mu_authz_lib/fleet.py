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
    ("multiuser/webdav_cache_noimp.conf",     "WEBDAV_CACHE", "https"),
    ("multiuser/webdav_stage_noimp.conf",     "WEBDAV_STAGE", "https"),
    ("multiuser/root_write_imp.conf",         "ROOT_WRITE",   "root"),
    ("multiuser/s3_direct.conf",              "S3_DIRECT",    "http"),
    ("multiuser/s3_cache.conf",               "S3_CACHE",     "http"),
    ("multiuser/cvmfs_cache.conf",            "CVMFS_CACHE",  "https"),
]

# The oracle speaks (protocol, variant); the fleet speaks instance names.  This
# table is the ONLY place the two vocabularies meet, and it must name instances
# that ``_SERVERS`` actually starts.
#
# It exists because they silently diverged once: ``url()`` read ports.MU.ROOT_
# DIRECT / ROOT_CACHE / WEBDAV_* / S3_* — the fixed-port attributes of a fleet
# that a harness rewrite had already replaced — so every measurement addressed a
# port nothing listened on.  XrdCl does not report a refused connect, it RETRIES
# it for the whole 120 s ConnectionWindow, so each cell died as an opaque
# pytest-timeout inside selectors.poll() with the endpoint nowhere in the
# traceback.  Naming the mapping, and failing loudly below when it names an
# instance that is not up, is what keeps that from being re-discovered.
_ENDPOINT = {
    ("root",   "direct"):  "DIRECT_AUTHZ",   # cache OFF, full gate == the oracle
    ("root",   "cache"):   "CACHE_NOIMP",    # cache ON, fills from ORIGIN_NOIMP
    ("root",   "origin"):  "ORIGIN_NOIMP",
    ("root",   "sidecar"): "SIDECAR_ROOT",
    ("root",   "write"):   "ROOT_WRITE",     # the one impersonating node

    ("webdav", "direct"):  "WEBDAV_AUTHZ",
    ("webdav", "cache"):   "WEBDAV_CACHE",
    ("webdav", "stage"):   "WEBDAV_STAGE",
    ("s3",     "direct"):  "S3_DIRECT",
    ("s3",     "cache"):   "S3_CACHE",
    ("cvmfs",  "cache"):   "CVMFS_CACHE",
}

_harness: "LifecycleHarness | None" = None
_backends: dict = {}
_assigned: "dict[str, int]" = {}  # ports.MU attr -> port (stable across reloads)
_broker_socks: "set[str]" = set()  # map-mode broker sockets to reap on stop()


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
        # Only map-mode nodes leave a broker behind; its socket lives in the
        # instance prefix the launcher just created, so the path is not knowable
        # until now.  Remember it for _reap_brokers().
        if template.endswith("root_write_imp.conf"):
            _broker_socks.add(os.path.join(endpoint.prefix, "logs",
                                           "imp_root_write.sock"))


def _reap_brokers() -> None:
    """Kill the impersonation brokers the fleet's map-mode nodes left behind.

    ``brix_idmap map`` double-forks its privileged broker into its own session
    so nginx never reaps it, which means ``nginx -s quit`` on the master — all
    ``LifecycleHarness.close()`` does — stops the master and its workers and
    leaves a ROOT daemon running.  Every ``revoke``/``apply_policy`` reload is a
    stop+start, so without this each MU session would strand one more privileged
    process per reload, and the fresh broker's bind of the 0600 socket would be
    racing the stale one's hold on it.  The broker writes its pid beside its
    socket; that is the only handle on it."""
    import signal
    for sock in _broker_socks:
        try:
            pid = int(open(sock + ".pid").read().strip())
        except (FileNotFoundError, ValueError, OSError):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            continue


def stop() -> None:
    global _harness
    if _harness is not None:
        _harness.close()
        _harness = None
    _reap_brokers()


def wait_listening(timeout: int = 15) -> None:
    """No-op: the harness gates TCP readiness per instance at ``start()``."""
    return None


def url(proto: str, variant: str) -> str:
    """Endpoint URL for one (protocol, variant) of the live fleet.

    Raises rather than returning a URL for an endpoint this run never started:
    an unbound port is not a slow server, and handing one to XrdCl buys a
    two-minute retry storm instead of an error (see ``_ENDPOINT``)."""
    try:
        attr = _ENDPOINT[(proto, variant)]
    except KeyError:
        raise KeyError(f"no MU endpoint for protocol {proto!r} variant {variant!r}; "
                       f"known: {sorted(_ENDPOINT)}") from None
    if attr not in _assigned:
        raise RuntimeError(
            f"MU endpoint {proto}/{variant} maps to instance {attr}, which this "
            f"fleet did not start (started: {sorted(_assigned)}). Either add its "
            f"template to _SERVERS or stop addressing it.")
    scheme = {"root": "root", "webdav": "https", "s3": "http", "cvmfs": "https"}[proto]
    return f"{scheme}://{ports.MU.HOST}:{getattr(ports.MU, attr)}"
