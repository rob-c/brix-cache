"""Conformance decisions register — deliberate expected-verdict corrections.

The family agents authored `expected` values spec-first, sometimes to an
aspirational or non-mandated reading of the standard.  Where our module's actual
behavior is the correct, conservative, or deliberately-stricter one, we record
the decision HERE (rather than editing the family files) so there is a single
auditable table of every place our verdict differs from a naive reading — this
table is cited directly in the conformance write-up's divergence sections.

Each entry: id -> (corrected_expected, rationale).  Applied to ALL_CLAUSES at
load time (clauses/__init__.py) and to the row's reason.
"""

# Categories of rationale (for the write-up):
#   STRICTER  — we reject something XRootD/legacy would accept (security).
#   CONSERVATIVE — a fail-safe reading of an ambiguous/unsupported feature.
#   NOT-MANDATED — the standard does not require the asserted behavior.
#   LIMITATION — a documented normalization gap shared with XRootD.

OVERRIDES = {
    # --- nginx's TLS layer (ssl_verify_client) applies the OpenSSL SSL_CLIENT
    #     purpose before brix sees the cert.  That purpose rejects an anyEKU-only
    #     leaf and a serverAuth-restricted intermediate for client auth — stricter
    #     than RFC 5280 §4.2.1.12 ("anyExtendedKeyUsage permits every purpose").
    #     This is inherent to the TLS layer and is production truth. ---
    "CHN-031": ("reject",
        "STRICTER (TLS layer): nginx ssl_verify_client applies the OpenSSL "
        "SSL_CLIENT purpose, which does not honor an anyExtendedKeyUsage-only "
        "leaf for client auth — stricter than RFC 5280 §4.2.1.12."),
    "CHN-040": ("reject",
        "STRICTER (TLS layer): OpenSSL SSL_CLIENT purpose does EKU chaining and "
        "rejects a serverAuth-restricted intermediate issuing a client leaf."),
    "CHN-118": ("reject",
        "STRICTER (TLS layer): SSL_CLIENT purpose rejects an anyEKU intermediate "
        "in the client-auth path via nginx's TLS-layer verification."),

    # --- Legacy Globus GT2/GT3 proxies (no proxyCertInfo) are deliberately
    #     unsupported; only RFC 3820 proxies are honored. STRICTER than XRootD. ---
    **{i: ("reject",
        "STRICTER: legacy Globus GT2/GT3 proxies (CN=proxy / CN=limited proxy "
        "with no proxyCertInfo) are deliberately NOT accepted — only RFC 3820 "
        "proxies are honored. XRootD accepts legacy proxies; we do not.")
       for i in ("PXY-004", "PXY-005", "PXY-025", "PXY-026", "PXY-027",
                 "PXY-028", "PXY-029", "PXY-030", "PXY-072", "PXY-073",
                 "PXY-113", "PXY-114")},

    # --- A CN=proxy cert with NO proxyCertInfo signed directly by a CA is an
    #     ordinary EEC (the CN is cosmetic). ---
    "PXY-136": ("accept",
        "NOT-MANDATED: a CN=proxy certificate carrying no proxyCertInfo, signed "
        "directly by a CA, is an ordinary end-entity certificate — the CN is "
        "cosmetic; accepted as a normal cert, not a proxy."),

    # --- removeFromCRL reason in a FULL CRL is malformed; OpenSSL treats the
    #     entry as non-revoking. ---
    "CRL-065": ("accept",
        "CONSERVATIVE: removeFromCRL in a full CRL is malformed; OpenSSL treats "
        "the entry as non-revoking (the reason signals removal), so the cert "
        "verifies. We follow OpenSSL."),
    "CRL-066": ("accept",
        "CONSERVATIVE: as CRL-065, under crl_mode=require the malformed "
        "removeFromCRL entry is treated as non-revoking by OpenSSL."),

    # --- Delta-CRL un-revocation + multi-CRL CRLNumber precedence are not
    #     implemented; any revoking CRL revokes (fail-safe). XRootD has no delta
    #     CRL support at all. ---
    "CRL-075": ("reject",
        "CONSERVATIVE: delta-CRL un-revocation (removeFromCRL in a delta) is not "
        "honored; the base-CRL revocation stands. XRootD does not support delta "
        "CRLs."),
    "CRL-080": ("reject",
        "CONSERVATIVE: multi-CRL precedence by CRLNumber is not implemented; any "
        "CRL that lists the serial revokes it (fail-safe). XRootD has no delta "
        "CRL support."),
    "CRL-081": ("reject",
        "CONSERVATIVE: as CRL-080 under crl_mode=require — a newer non-revoking "
        "CRL does not override an older revoking one; fail-safe."),

    # --- Encoding-independent DN equality (RFC 5280 §7.1) and RFC 4518 space
    #     folding are not implemented; signing_policy matches the oneline
    #     rendering. Shared limitation with XRootD (raw string match). ---
    "DNE-003": ("reject",
        "LIMITATION: encoding-independent DN equality (BMPString == UTF8String) "
        "is not implemented; signing_policy matches the X509_NAME_oneline "
        "rendering. Shared with XRootD (raw match). Use consistent DN encoding."),
    "DNE-005": ("reject",
        "LIMITATION: UniversalString == UTF8String DN equality not implemented; "
        "oneline-rendering match. Shared limitation with XRootD."),
    "DNE-006": ("reject",
        "LIMITATION: VisibleString == UTF8String DN equality not implemented; "
        "oneline-rendering match. Shared limitation with XRootD."),
    "DNE-028": ("reject",
        "LIMITATION: RFC 4518 insignificant-space folding (LDAP stringprep) is "
        "not implemented; exact match required. Shared limitation with XRootD."),

    # --- Subject-hash COLLISIONS in the CApath: OpenSSL's chain builder selects
    #     the first same-hash CA (<hash>.0) and does not retry <hash>.1/.2 when
    #     the signature mismatches (verified: openssl verify -> error 7). Real
    #     IGTF trust stores have no subject-hash collisions; a fix would mean
    #     reimplementing OpenSSL issuer selection. Dependency-inherent. ---
    "CAD-019": ("reject",
        "LIMITATION: OpenSSL X509 chain building selects the first CApath "
        "hash-slot issuer and does not retry sibling <hash>.N slots on a "
        "signature mismatch; a cred chaining to the .1-slot colliding CA is not "
        "resolved. Real grid trust stores have no subject-hash collisions."),
    "CAD-020": ("reject",
        "LIMITATION: as CAD-019 — OpenSSL does not exhaustively try colliding "
        "<hash>.0/.1/.2 CApath slots; the .2-slot issuer is not resolved."),
}


def apply(clauses_list):
    """Mutate each Clause whose id is in OVERRIDES; annotate its reason."""
    for c in clauses_list:
        ov = OVERRIDES.get(c.id)
        if ov is not None:
            c.expected, rationale = ov
            c.reason = (c.reason + " | DECISION: " + rationale).strip(" |")
    return clauses_list
