"""scenarios — data tables for the topology tests (kept out of the test body).

DRY_RUN: profile -> tokens the dry-run ``xrd-lab test <profile>`` must name.
LIVE:    profile -> (deploy target or None, tokens the live run emits).
"""

DRY_RUN = {
    "fleet":       ["brix-fleet-anon:11094", "CRL/JWKS"],
    "chaos":       ["chaos-tier1", "discovery-redir"],
    "cms":         ["brix-cms-manager:1094"],
    "readonly":    ["role.configKey=readonly", "write-rejected"],
    "authorities": ["grid-ca", "token-issuer"],
}

LIVE = {
    "fleet":       ("fleet", ["FLEET_ANON_OK", "gsi role Ready", "token role Ready", "fleet OK"]),
    "chaos":       ("chaos", ["CACHE_PATH_OK", "CMS_REGISTERED_OK", "chaos OK"]),
    "cms":         ("cms",   ["CMS_REGISTERED_OK", "cms OK"]),
    "readonly":    (None,    ["WRITE_REJECTED_OK", "readonly OK"]),
    "authorities": ("gsi",   ["CRL OK", "JWKS OK"]),
}

# lab image -> (Dockerfile, build context). smoke builds from its own dir.
IMAGES = {
    "smoke":     ("smoke/Dockerfile",     "images/smoke"),
    "server":    ("server/Dockerfile",    "."),
    "client":    ("client/Dockerfile",    "."),
    "authority": ("authority/Dockerfile", "."),
}
