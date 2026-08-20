"""The always-on core: the shared nginx and the reference xrootd servers.

The instances bash ``start_all_dedicated`` brought up before any
dedicated role.  Split out of ``fleet_specs.py`` (TS-4 item 7).
"""

from __future__ import annotations

from brix_suite.registry import NginxInstanceSpec
from brix_suite.settings import (
    NGINX_ANON_PORT,
    PROXY_NGINX_PORT,
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    PROXY_BRIDGE_BRIX_PORT,
    ROOT_TPC_REF_PORT,
    XRDHTTP_HTTP_PORT,
    XRDHTTP_ROOT_PORT,
)

from brix_suite.catalogue._shared import _data, _xrdcp_bin

__all__ = ["core_specs"]


def core_specs() -> list[NginxInstanceSpec]:
    """The pre-dedicated core: main nginx + reference xrootd servers + XrdHttp."""
    shared_data = _data("data")
    return [
        # The canonical multi-listen nginx: every standard port (anon/gsi/token/
        # webdav/s3/metrics) lives in this one config, keyed off session values.
        # Readiness anchors on the anon root:// port. Critical: no suite without it.
        NginxInstanceSpec(
            name="main",
            template="nginx_shared.conf",
            port=NGINX_ANON_PORT,
            protocol="root",
            data_root=shared_data,
            readiness="root",
            tags=("core", "critical"),
            reason="Main shared nginx — all standard listen ports.",
        ),
        # Reference (stock) xrootd on the SHARED export, anonymous auth. Critical:
        # the differential-conformance suite compares our nginx against it.
        NginxInstanceSpec(
            name="ref-anon",
            template="xrootd_ref.conf",
            port=REF_BRIX_PORT,
            protocol="root",
            data_root=shared_data,
            kind="xrootd",
            readiness="root",
            tags=("core", "critical"),
            reason="Reference xrootd (anonymous) on the shared export.",
        ),
        # Reference xrootd with GSI. SECLIB/CA_DIR/SERVER_CERT/KEY come from the
        # session values + the launcher's generic SECLIB supply.
        NginxInstanceSpec(
            name="ref-gsi",
            template="xrootd_ref_gsi.conf",
            port=REF_BRIX_GSI_PORT,
            protocol="root",
            # Bash harness rooted the GSI reference at data-gsi-bridge (refxrootd.sh:
            # REF_BRIX_GSI_DATA_DIR=${TEST_ROOT}/data-gsi-bridge). test_gsi_bridge
            # writes its source files there and expects REF_BRIX_GSI_PORT to serve
            # them — keep the export path identical, not a fresh data-ref-gsi.
            data_root=_data("data-gsi-bridge"),
            kind="xrootd",
            readiness="root",
            tags=("core",),
            reason="Reference xrootd (GSI).",
        ),
        # GSI reference sharing the MAIN export (identity-mapping conformance).
        NginxInstanceSpec(
            name="ref-gsi-shared",
            template="xrootd_ref_gsi.conf",
            port=REF_BRIX_GSI_SHARED_PORT,
            protocol="root",
            data_root=shared_data,
            kind="xrootd",
            readiness="root",
            tags=("core",),
            reason="Reference xrootd (GSI) on the shared export.",
        ),
        # root:// TPC reference — drives third-party copies via xrdcp.
        NginxInstanceSpec(
            name="root-tpc-ref",
            template="xrootd_root_tpc.conf",
            port=ROOT_TPC_REF_PORT,
            protocol="root",
            data_root=_data("data-root-tpc-ref"),
            kind="xrootd",
            readiness="root",
            tags=("core",),
            template_values={"XRDCP_BIN": _xrdcp_bin()},
            reason="Reference xrootd for native root:// TPC.",
        ),
        # XrdPss proxy bridge — forwards to the proxy-mode nginx upstream.
        NginxInstanceSpec(
            name="pss-bridge",
            template="xrootd_pss_bridge.conf",
            port=PROXY_BRIDGE_BRIX_PORT,
            protocol="root",
            data_root=_data("data-pss-bridge"),
            kind="xrootd",
            readiness="root",
            env={"XRD_PARALLELEVTLOOP": "1", "XRD_WORKERTHREADS": "1"},
            template_values={"ORIGIN": f"localhost:{PROXY_NGINX_PORT}"},
            tags=("core",),
            reason="XrdPss reference bridge to the proxy-mode nginx.",
        ),
        # XrdHttp gateway (stock xrootd + XrdHttp module) — davs:// conformance.
        # HTTP_PORT is the readiness anchor; ROOT_PORT is the sibling root:// port.
        NginxInstanceSpec(
            name="xrdhttp",
            template="xrootd_xrdhttp.conf",
            port=XRDHTTP_HTTP_PORT,
            protocol="https",
            data_root=_data("data-xrdhttp"),
            kind="xrdhttp",
            readiness="tcp",
            extra_ports={"HTTP_PORT": XRDHTTP_HTTP_PORT, "ROOT_PORT": XRDHTTP_ROOT_PORT},
            tags=("core",),
            reason="Reference XrdHttp gateway (davs:// conformance).",
        ),
    ]
