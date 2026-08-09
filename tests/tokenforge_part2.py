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

from _tokenforge_part2_mixina import _TokenForgeMixinA
from _tokenforge_part2_mixinb import _TokenForgeMixinB
from _tokenforge_part2_mixinc import _TokenForgeMixinC
from _tokenforge_part2_mixind import _TokenForgeMixinD

class TokenForge(_TokenForgeMixinA, _TokenForgeMixinB, _TokenForgeMixinC, _TokenForgeMixinD, TokenIssuer):
    """A TokenIssuer that can also emit deliberately-malformed tokens."""
