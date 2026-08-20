# ARCHIVE — the pre-TS-5 flat body of ``tests/_tokenforge_part2_mixind.py``, kept byte-identical so
# the "verbatim move" claim in the TS-5 decision note is checkable on disk
# rather than only in git history.  Nothing imports this; the live forge is
# ``brix_suite.security.tokens``.  ``test_ci_ts5_tokens_move.py`` diffs every
# moved method against this text.
"""WLCG token conformance fixture forge.

Extends utils.make_token.TokenIssuer into a full hostile-token mint. Every
minted artifact is described by a manifest row so the C and pytest layers
share one verdict source. See docs/superpowers/specs/2026-07-06-wlcg-token-
conformance-design.md.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer



def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _seg(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


class _TokenForgeMixinD:
    """A TokenIssuer that can also emit deliberately-malformed tokens."""

    def aud_any(self):
        """SciTokens wildcard audience 'ANY' (rule 132; accept).

        WHY:  SciTokens §2 / rule 132 — the special audience value 'ANY'
              indicates the token is valid for any endpoint; a conformant
              SciTokens validator MUST accept this value.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(aud="ANY"))
