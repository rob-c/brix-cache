"""MU fleet ports and directory layout.

Overridable via TEST_MU_* env vars, matching the tests/settings.py convention
(int() + literal default). The fleet is a set of PAIRED servers per protocol:
a cache-OFF `direct` server (the authoritative oracle) and a cache-ON `cache`
server (the read cache + stage path under test).
"""
import os
from settings import HOST


def _p(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


class MU:
    HOST = os.environ.get("TEST_MU_HOST", HOST)

    # Paired direct (cache-off, oracle) + cache (cache-on) servers per protocol.
    # These are INSTANCE names, one per template in mu_authz_lib.fleet._SERVERS,
    # and the values here are only the historical defaults: fleet.start() writes
    # the lifecycle ledger's assignment back onto each attribute.  The oracle's
    # (protocol, variant) vocabulary maps onto these through fleet._ENDPOINT, so
    # an attribute no template starts is dead weight that reads like a live
    # endpoint — which is how the root:// pair once pointed at unbound ports.
    WEBDAV_CACHE  = _p("TEST_MU_WEBDAV_CACHE",  12103)
    S3_DIRECT     = _p("TEST_MU_S3_DIRECT",     12104)
    S3_CACHE      = _p("TEST_MU_S3_CACHE",      12105)
    CVMFS_CACHE   = _p("TEST_MU_CVMFS_CACHE",   12106)
    # No-impersonation cache node + its anonymous origin — a no-root verification of the
    # cache-transparency fix (real remote-origin cache-HIT path).
    CACHE_NOIMP   = _p("TEST_MU_CACHE_NOIMP",   12110)
    ORIGIN_NOIMP  = _p("TEST_MU_ORIGIN_NOIMP",  12111)
    WEBDAV_AUTHZ  = _p("TEST_MU_WEBDAV_AUTHZ",  12127)  # 12120 collides with fleet upstream-redirect
    # Direct (non-cache) GSI+authdb root:// node — verifies the read-open existence oracle fix.
    DIRECT_AUTHZ  = _p("TEST_MU_DIRECT_AUTHZ",  12130)
    # WebDAV write node — verifies staging temp-file modes (stage-private / publish-intended).
    WEBDAV_STAGE  = _p("TEST_MU_WEBDAV_STAGE",  12140)
    # root:// anon node — verifies internal metadata sidecars are never listed/served.
    SIDECAR_ROOT  = _p("TEST_MU_SIDECAR_ROOT",  12150)
    # root:// write node with real impersonation — the byte-attribution subject.
    ROOT_WRITE    = _p("TEST_MU_ROOT_WRITE",    12160)

    # Directory layout (kept out of the shared fleet data/registry roots but
    # under the same TEST_ROOT, so postures with different roots — e.g. the
    # unprivileged runner's /tmp/xrd-test-brixtest — never collide on /tmp/xrd-test).
    _TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
    MU_ROOT    = os.environ.get("TEST_MU_ROOT", os.path.join(_TEST_ROOT, "mu"))
    PKI_DIR    = os.environ.get("TEST_MU_PKI_DIR", os.path.join(_TEST_ROOT, "pki"))
    CA_DIR     = os.path.join(PKI_DIR, "ca")
    TOKENS_DIR = os.path.join(MU_ROOT, "tokens")
    DATA_ROOT  = os.path.join(MU_ROOT, "data")     # the export origin
    CACHE_ROOT = os.path.join(MU_ROOT, "cache")    # read-cache store
    STATE_ROOT = os.path.join(MU_ROOT, "state")
    GRIDMAP    = os.path.join(MU_ROOT, "gridmap")
    AUTHDB     = os.path.join(MU_ROOT, "authdb")
    VOMSDIR    = os.path.join(MU_ROOT, "vomsdir")
    CONFIG_DIR = os.path.join(MU_ROOT, "conf")
    LOG_DIR    = os.path.join(MU_ROOT, "logs")

    @classmethod
    def all_ports(cls) -> "list[int]":
        """Every fleet instance's port, in _SERVERS order."""
        return [cls.ORIGIN_NOIMP, cls.CACHE_NOIMP, cls.DIRECT_AUTHZ, cls.SIDECAR_ROOT,
                cls.WEBDAV_AUTHZ, cls.WEBDAV_CACHE, cls.WEBDAV_STAGE, cls.ROOT_WRITE,
                cls.S3_DIRECT, cls.S3_CACHE, cls.CVMFS_CACHE]

    @classmethod
    def enforcing_ports(cls) -> "list[int]":
        """The cache servers that MUST enforce per-user authz (excludes cvmfs)."""
        return [cls.CACHE_NOIMP, cls.WEBDAV_CACHE, cls.S3_CACHE]
