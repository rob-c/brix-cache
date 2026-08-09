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


class _TokenForgeMixinC:
    """A TokenIssuer that can also emit deliberately-malformed tokens."""

    def iss_non_string(self):
        """iss is a numeric value 12345 — non-string type → reject (rule 4).

        WHY: RFC 7519 §4.1.1 / rule 4 — the iss claim MUST be a StringOrURI;
             a numeric value violates the type constraint.
        """
        now = int(time.time())
        payload = (
            '{"iss":12345' +
            ',"sub":"conformance"' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":' + str(now + 3600) +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def sub_non_string(self):
        """sub is an array ["a","b"] — non-string type → reject (rules 4/6).

        WHY: RFC 7519 §4.1.2 / rules 4/6 — the sub claim MUST be a StringOrURI;
             an array value violates the type constraint.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":["a","b"]' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":' + str(now + 3600) +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def sub_absent(self):
        """sub omitted entirely — accept (rules 4/6: sub is OPTIONAL).

        WHY: RFC 7519 §4.1.2 — "sub" is an OPTIONAL claim. The sub-type
             hardening rejects a present-but-non-string sub, but must NOT reject
             a token that simply carries no sub at all.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":' + str(now + 3600) +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def iat_after_exp(self):
        """iat > exp — issued after expiry (nonsensical; rule 155; characterize).

        WHY: A token whose iat is in the future relative to its exp timestamp
             is logically contradictory; rule 155 characterises whether the
             implementation rejects such tokens.
        """
        now = int(time.time())
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(exp=now - 10, iat=now + 10, nbf=now - 20))

    def nbf_after_exp(self):
        """nbf > exp — not-before is after expiry (rule 155; characterize).

        WHY: A token that is not yet valid (nbf far past exp) can never be used;
             characterises whether this impossible validity window is caught.
        """
        now = int(time.time())
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(exp=now + 10, nbf=now + 3600))

    def unknown_claims_ok(self):
        """Valid token with extra unknown claims — MUST accept (rule 16).

        WHY: RFC 7519 §4.3 / rule 16 — unrecognised claim names MUST be ignored;
             their presence MUST NOT cause rejection.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(**{"custom_x": "y", "https://ex/z": 1}))

    def numericdate_fractional(self):
        """exp as a fractional NumericDate (now+3600.5) — MUST accept (rule 2).

        WHY: RFC 7519 §2 / rule 2 — NumericDate is a JSON numeric value
             representing seconds; fractional seconds are permitted.  A
             conformant implementation must not reject a float exp.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":"conformance"' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":' + str(now + 3600) + '.5' +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def numericdate_negative(self):
        """nbf as a negative NumericDate (-1) — nbf in past, MUST accept (rule 3).

        WHY: RFC 7519 §2 / rule 3 — NumericDate may be negative (before Unix
             epoch); nbf=-1 is in the past so the token is immediately valid.
             The implementation must not overflow or reject negative values.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":"conformance"' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":' + str(now + 3600) +
            ',"nbf":-1' +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def numericdate_huge(self):
        """exp as a huge integer (99999999999999999999) — far future, MUST accept (rule 3).

        WHY: RFC 7519 §2 / rule 3 — NumericDate may be very large; the
             implementation must not overflow (e.g. truncate to int32/int64)
             in a way that treats a far-future expiry as expired.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":"conformance"' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":99999999999999999999' +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    def exp_null(self):
        """exp is JSON null — non-number type → reject (rule 1).

        WHY: RFC 7519 §4.1.4 / rule 1 — exp MUST be a NumericDate (integer or
             float); null is not a number → parse failure → exp effectively 0
             (expired) or explicit rejection.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":"conformance"' +
            ',"aud":' + json.dumps(self.audience) +
            ',"exp":null' +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)

    # --- base64 / structure ------------------------------------------

    def padded_base64(self):
        """Re-encode all three JWS segments with base64url = padding (rule 25 → reject).

        WHAT: Take a valid compact JWS; decode each segment; re-encode with
              base64.urlsafe_b64encode keeping trailing '=' padding chars.
        WHY:  RFC 7515 §2 / rule 25 — base64url MUST NOT include '=' padding;
              a token with padded segments MUST be rejected.
        HOW:  The signature segment is 256 bytes (RSA-2048); 256 % 3 == 1,
              so urlsafe_b64encode always produces two '=' chars there.
        """
        tok = self.generate()
        parts = []
        for seg in tok.split("."):
            raw = base64.urlsafe_b64decode(seg + "=" * ((4 - len(seg) % 4) % 4))
            parts.append(base64.urlsafe_b64encode(raw).decode("ascii"))
        return ".".join(parts)

    def plus_slash_base64(self):
        """Payload segment uses standard base64 +/ alphabet (rule 25 → reject).

        WHAT: Encode the payload JSON with standard base64 ('+'/'/') instead of
              the url-safe alphabet ('-'/'_').  Header and signature remain valid
              url-safe base64url.
        WHY:  RFC 7515 §2 / rule 25 — JWS compact serialization requires
              base64url encoding; tokens containing standard-base64 '+' or '/'
              characters that are invalid in base64url MUST be rejected.
        HOW:  Serialize the payload JSON; base64.b64encode (standard alphabet);
              strip '=' padding; the segment will contain '+' and '/' for payload
              byte sequences that map to base64 values 62 and 63.
        """
        hdr = {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID}
        payload = self._base_claims()
        payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        hdr_seg = _seg(hdr)
        p_std = base64.b64encode(payload_json).rstrip(b"=").decode("ascii")
        signing_input = (hdr_seg + "." + p_std).encode("ascii")
        sig = self.private_key.sign(signing_input, padding.PKCS1v15(),
                                    hashes.SHA256())
        return signing_input.decode("ascii") + "." + _b64url(sig)

    # --- SCP2 family (scope syntax) ----------------------------------

    def scope_forbidden_quote(self):
        """scope-token contains a forbidden '"' character (rule 97 → reject).

        WHY:  WLCG Token Profile §4 / rule 97 — the double-quote character
              (0x22) is not permitted inside a scope-token value; a scope
              containing it is malformed.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope='storage.read:/a"b'))

    def scope_forbidden_backslash(self):
        r"""scope-token contains a forbidden '\' character (rule 97 → reject).

        WHY:  WLCG Token Profile §4 / rule 97 — the backslash character (0x5C)
              is not permitted inside a scope-token value; a scope containing
              it is malformed.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope="storage.read:/a\\b"))

    def scope_reordered(self, a, b):
        """Mint a token with scope '{a} {b}'; helper for order-independence tests (rule 98).

        WHY:  WLCG Token Profile §4 / rule 98 — multiple scope-tokens are
              space-separated; the order MUST NOT affect whether any individual
              scope-token grants access to the requested path.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope=f"{a} {b}"))

    def scope_storage_no_path(self):
        """scope 'storage.read' with no ':PATH' component (rule 112 → reject).

        WHY:  WLCG Token Profile §4 / rule 112 — a storage scope MUST include a
              path component (storage.action:/path); the path-less form
              'storage.read' is malformed for storage authorization.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope="storage.read"))

    def scope_sibling(self, path="/foo"):
        """scope 'storage.read:{path}' — used to test rule 117 segment boundary.

        WHY:  WLCG Token Profile §4 / rule 117 — a scope for /foo MUST NOT
              cover /foobar; the prefix match must respect directory-boundary
              semantics (/foo covers /foo/bar but not /foobar).
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope=f"storage.read:{path}"))

    def scope_unnormalized(self):
        """scope path contains '/../' traversal — reject (rules 113/141).

        WHY:  WLCG Token Profile §4 / rules 113/141 — scope paths must be
              normalized; a path containing '..' components is either an
              invalid scope-token or a traversal attempt → reject.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope="storage.read:/foo/../bar"))

    def scope_compute(self, action="read"):
        """scope 'compute.{action}:/queue' — HEP compute scope (rule 118; characterize).

        WHY:  WLCG Token Profile §4 / rule 118 — compute scopes use a different
              action namespace (compute.*) and apply to compute resources, not
              storage paths; characterises whether compute scopes parse cleanly.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope=f"compute.{action}:/queue"))

    def scope_create_only(self):
        """scope 'storage.create:/data' — create does not imply modify (rule 115).

        WHY:  WLCG Token Profile §4 / rule 115 — storage.create grants permission
              to create new objects but does NOT grant permission to modify or
              overwrite existing ones.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope="storage.create:/data"))

    # --- WLCG / SCITOK families --------------------------------------

    def aud_wildcard(self):
        """aud = WLCG wildcard URI — MUST accept (rules 104/105).

        WHY:  WLCG Token Profile §3 / rules 104/105 — the special audience value
              'https://wlcg.cern.ch/jwt/v1/any' is a wildcard that any WLCG
              endpoint must accept regardless of its configured audience.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(aud="https://wlcg.cern.ch/jwt/v1/any"))

    def wlcg_missing_ver(self):
        """wlcg.ver claim absent — characterize (rule 101).

        WHY:  WLCG Token Profile §2.1 / rule 101 — the WLCG profile requires
              wlcg.ver; its absence characterises whether the implementation
              enforces the profile version claim or treats it as advisory.
        """
        c = self._base_claims()
        c.pop("wlcg.ver", None)
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID}, c)

    def wlcg_groups(self, groups=None):
        """Token carrying wlcg.groups claim (rule 119; characterize).

        WHY:  WLCG Token Profile §4 / rule 119 — wlcg.groups carries VO group
              membership; characterises whether the group list is parsed and
              available for authorization decisions.
        """
        if groups is None:
            groups = ["/wlcg", "/wlcg/xfers"]
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(**{"wlcg.groups": groups}))

    def scitokens_ver(self):
        """SciTokens 2.0 profile token: ver='scitokens:2.0' (rule 126; accept).

        WHY:  SciTokens §2 / rule 126 — the 'ver' claim identifies the SciTokens
              profile version; 'scitokens:2.0' is the current stable version and
              MUST be accepted.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(ver="scitokens:2.0"))

    def scitokens_ver_unknown(self):
        """SciTokens token with unknown ver='scitokens:9.9' (rule 127; characterize).

        WHY:  SciTokens §2 / rule 127 — an unrecognised SciTokens version
              SHOULD cause rejection; characterises whether the implementation
              enforces the version constraint.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(ver="scitokens:9.9"))

    def scitokens_scope(self, authz="read", path="/data"):
        """SciTokens scope form: '{authz}:{path}' (rule 135; characterize).

        WHY:  SciTokens §3 / rule 135 — SciTokens uses 'read:/path' and
              'write:/path' forms (NOT 'storage.read:/path' as in WLCG);
              characterises whether both scope syntaxes are parsed correctly.
        """
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope=f"{authz}:{path}"))
