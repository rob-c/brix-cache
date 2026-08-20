"""WLCG token conformance fixture forge.

Extends `utils.make_token.TokenIssuer` into a full hostile-token mint.  Every
minted artifact is described by a manifest row so the C and pytest layers share
one verdict source.  See
`docs/superpowers/specs/2026-07-06-wlcg-token-conformance-design.md`.

TS-5 moved the seven flat `tokenforge*` modules here.  Before the move the
class was assembled by `exec`: `tokenforge.py` compiled `tokenforge_part2.py`
and `tokenforge_part3.py` into its own globals, and part 2 in turn imported
four mixin modules whose only reason to be separate was line count.  The
composition is ordinary imports now, and the parts are named for what they
hold rather than for the order they were sliced in:

    jose        base64url/JWK encoding and JWKS emission — ONE copy
    issuer_cfg  the SciTokens issuer INI writer
    mint        base claims, header/alg basics, alternate key material
    signing     real signature algorithms, raw signing, `crit`/`typ` headers
    claims      claim types, NumericDate edges, base64 variants, scope grammar
    manifest    conformance artifacts and the manifest rows

Two defects fell out of the move rather than being hunted separately.
`_b64url` and `_seg` had five byte-identical definitions; they have one.  And
`signing.header_jwk_injection` called `_rsa_jwk`, which existed only in
`tokenforge.py`'s globals and never in the slice that used it — so the method
raised `NameError` for every caller, silently disabling the two security tests
that assert an embedded `jwk` header is not trusted.
"""

import sys
from pathlib import Path

# `utils.make_token` lives at the repository root, which the flat module reached
# with a `dirname(__file__)/..` two levels up.  Naming the root by parent count
# from here keeps that reachable after the move instead of resolving to
# `brix_suite/security`, which exists and would therefore fail silently.
_REPO_ROOT = str(Path(__file__).resolve().parents[4])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from utils.make_token import TokenIssuer  # noqa: E402

from brix_suite.security.tokens.claims import _TokenForgeClaims  # noqa: E402
from brix_suite.security.tokens.issuer_cfg import write_scitokens_cfg  # noqa: E402,F401
from brix_suite.security.tokens.jose import (  # noqa: E402,F401 — re-exported
    _b64url,
    _ec_jwk,
    _rsa_jwk,
    _seg,
    write_jwks,
)
from brix_suite.security.tokens.mint import _TokenForgeMint  # noqa: E402
from brix_suite.security.tokens.signing import _TokenForgeSigning  # noqa: E402

#: Slice-letter names from the pre-TS-5 split.  Aliases, not subclasses, so the
#: MRO below is the same object graph either way.  C and D both name the claims
#: module: mixin D held the single method `aud_any` and was merged into it.
_TokenForgeMixinA = _TokenForgeMint
_TokenForgeMixinB = _TokenForgeSigning
_TokenForgeMixinC = _TokenForgeClaims
_TokenForgeMixinD = _TokenForgeClaims

__all__ = [
    "Manifest",
    "TokenForge",
    "alg_jwks",
    "build_manifest",
    "fleet_artifacts",
    "write_jwks",
    "write_scitokens_cfg",
]


class TokenForge(_TokenForgeMint, _TokenForgeSigning, _TokenForgeClaims, TokenIssuer):
    """A TokenIssuer that can also emit deliberately-malformed tokens."""


# Last, and deliberately: `manifest` mints through `TokenForge`, so it can only
# be imported once the class above is bound.
from brix_suite.security.tokens.manifest import (  # noqa: E402,F401 — closes the cycle
    Manifest,
    alg_jwks,
    build_manifest,
    fleet_artifacts,
)
