"""Hostile-PKI scenario forge -- the package behind ``tests/x509forge.py``.

TS-5 replaced the ``split_continuation`` composition (``x509forge.py`` compiled
``x509forge_part2.py`` and ``_part3.py`` into its own globals) with a topical
package: :mod:`primitives` makes one certificate, :mod:`cadir` puts it in a
hashed CA directory, :mod:`scenarios` composes those into a hostile tree,
:mod:`catalogue` names the trees, and :mod:`matrix` builds them combinatorially
from clauses.

This facade re-exports every name the flat module exposed, private helpers
included: the shards referred to each other's underscore-prefixed helpers
freely, so a public-only surface would have broken callers that the flat
namespace had made legitimate.  ``tests/x509forge.py`` and its two ``_part``
spellings are §10.2 shims onto this package, so all four names are ONE module
object.
"""

from brix_suite.security.x509.constants import (  # noqa: F401
    OID_GLOBUS_LIMITED,
    OID_PPL_INDEPENDENT,
    OID_PPL_INHERIT_ALL,
    OID_PROXY_CERT_INFO,
    _DAY,
    _EPOCH,
)
from brix_suite.security.x509.primitives import (  # noqa: F401
    Cert,
    _der_int,
    _der_len,
    _der_oid,
    _der_seq,
    _der_tlv,
    _digest,
    _encode_oid,
    _key,
    _make_ca_openssl,
    _make_eec_openssl,
    _make_key,
    _name,
    make_ca,
    make_crl,
    make_eec,
    make_proxy,
    proxy_cert_info_der,
)
from brix_suite.security.x509.cadir import (  # noqa: F401
    CA_DN,
    Scenario,
    _openssl_hashes,
    _openssl_hashes_cached,
    _scenario,
    _symlink,
    signing_policy_text,
    write_hashed_ca_dir,
)
from brix_suite.security.x509.scenarios import (  # noqa: F401
    ProxyResult,
    _cad_expired_ca,
    _cad_md5_only,
    _cad_sha1_only,
    _crl_expired,
    _crl_revoked_eec,
    _px_limited_to_full,
    _px_noncritical_pci,
    _px_rfc3820_ok,
    _sp_in_namespace,
    _sp_no_policy,
    _sp_out_of_namespace,
    _sp_proxy_cn_exempt,
    _sp_wrong_ca_block,
    make_proxy_from,
    rewrite_crl,
)
from brix_suite.security.x509.catalogue import (  # noqa: F401
    BASELINE_SPEC,
    _BUILDERS,
    forge_all,
    forge_scenario,
    rewrite_signing_policy,
)
from brix_suite.security.x509.matrix import (  # noqa: F401
    Clause,
    ForgeCtx,
    GROUPS,
    _place_ca_in_dir,
    build_all,
    build_report,
)
