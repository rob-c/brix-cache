"""SigV4 verification mixin for the controlled Phase-118 S3 origin."""
import hashlib
import hmac
import re
import urllib.parse
from datetime import datetime, timezone


S3_ACCESS = "test-access-key"
S3_SECRET = "test-secret-key"
S3_REGION = "us-east-1"


class S3AuthMixin:
    """Authenticate header and query SigV4 requests without an AWS SDK."""

    def _readonly_put(self, body):
        """Serve the S3-009 read-only fixture, including hostile variants."""
        if not self._request_path().endswith("brix-conform-s3-readonly"):
            return False
        if self.server.behaviour == "s3_readonly_mutates":
            self.server.scratch[self._request_path()] = body
        if self.server.behaviour not in (
                "s3_readonly", "s3_readonly_wrong_code",
                "s3_readonly_mutates"):
            return False
        code = "InternalError" \
            if self.server.behaviour == "s3_readonly_wrong_code" \
            else "AccessDenied"
        error = f"<Error><Code>{code}</Code></Error>".encode()
        self._reply(403, error, (("Content-Type", "application/xml"),))
        return True

    @staticmethod
    def _hmac(key, value):
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    def _signing_key(self, date, region):
        key = self._hmac(f"AWS4{S3_SECRET}".encode(), date)
        key = self._hmac(key, region)
        key = self._hmac(key, "s3")
        return self._hmac(key, "aws4_request")

    def _sigv4_expected(self, method, canonical_query, date, scope,
                        signed_headers, payload_hash):
        canonical_uri = urllib.parse.quote(
            self._request_path(), safe="/-_.~"
        )
        canonical = (
            f"{method}\n{canonical_uri}\n{canonical_query}\n"
            f"host:{self.headers.get('Host', '')}\n"
        )
        if signed_headers != "host":
            canonical += (
                f"x-amz-content-sha256:{payload_hash}\n"
                f"x-amz-date:{date}\n"
            )
        canonical += f"\n{signed_headers}\n{payload_hash}"
        canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
        string_to_sign = f"AWS4-HMAC-SHA256\n{date}\n{scope}\n{canonical_hash}"
        date_scope, region, service, terminal = scope.split("/")
        if service != "s3" or terminal != "aws4_request" \
                or not date.startswith(date_scope):
            return None
        return hmac.new(self._signing_key(date_scope, region),
                        string_to_sign.encode(), hashlib.sha256).hexdigest()

    def _header_sigv4_valid(self, authorization):
        match = re.fullmatch(
            r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), "
            r"SignedHeaders=([^,]+), Signature=([0-9a-f]{64})",
            authorization,
        )
        if match is None or match.group(1) != S3_ACCESS:
            return False
        date = self.headers.get("x-amz-date", "")
        payload_hash = self.headers.get("x-amz-content-sha256", "")
        parsed = urllib.parse.urlsplit(self.path)
        expected = self._sigv4_expected(
            self.command, parsed.query, date, match.group(2), match.group(3),
            payload_hash,
        )
        return expected is not None and hmac.compare_digest(
            expected, match.group(4)
        )

    def _presigned_fields(self, parsed):
        query = urllib.parse.parse_qs(parsed.query)
        required = ("X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
                    "X-Amz-SignedHeaders", "X-Amz-Signature")
        for name in required:
            if len(query.get(name, [])) != 1:
                return None
        credential = query["X-Amz-Credential"][0].split("/", 1)
        if len(credential) != 2 or credential[0] != S3_ACCESS:
            return None
        try:
            instant = datetime.strptime(
                query["X-Amz-Date"][0], "%Y%m%dT%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
            expires = int(query["X-Amz-Expires"][0])
        except (ValueError, OverflowError):
            return None
        return query, credential, instant, expires

    def _presigned_valid(self, parsed):
        fields = self._presigned_fields(parsed)
        if fields is None:
            return False, False
        query, credential, instant, expires = fields
        expired = (datetime.now(timezone.utc) - instant).total_seconds() \
            > expires
        unsigned_query, separator, signature = parsed.query.rpartition(
            "&X-Amz-Signature="
        )
        expected = self._sigv4_expected(
            self.command, unsigned_query, query["X-Amz-Date"][0],
            credential[1], query["X-Amz-SignedHeaders"][0],
            "UNSIGNED-PAYLOAD",
        )
        if separator == "" or expected is None:
            return False, expired
        if not hmac.compare_digest(expected, signature):
            return False, expired
        return not expired, expired

    def _authorize_presigned(self, is_s3, parsed):
        if not is_s3 or "X-Amz-Algorithm" not in parsed.query:
            return None
        valid, expired = self._presigned_valid(parsed)
        path_replay = ".brix-conform-presign-replay" in self._request_path()
        if valid:
            return True
        accepted_fault = {
            "s3_presign_expired_accepted": expired,
            "s3_presign_path_accepted": path_replay,
        }.get(self.server.behaviour, False)
        if accepted_fault:
            return True
        self._reply(403)
        return False

    def _authorize_bearer(self, is_s3, authorization):
        if not is_s3 or not authorization.startswith("Bearer "):
            return None
        if self.server.behaviour == "s3_bearer_accepted":
            return True
        self._reply(403)
        return False

    def _authorize_sigv4(self, is_s3, authorization):
        if not authorization.startswith("AWS4-HMAC-SHA256 "):
            return None
        if self._sigv4_accepted(is_s3, authorization):
            return True
        self._reply(403)
        return False

    def _sigv4_accepted(self, is_s3, authorization):
        cases = (
            is_s3 and self._header_sigv4_valid(authorization),
            is_s3
            and self.server.behaviour == "s3_tampered_signature_accepted",
            not is_s3 and self.server.behaviour == "http_sigv4_accepted",
        )
        return any(cases)

    def _authorize(self):
        authorization = self.headers.get("Authorization", "")
        path = self._request_path()
        is_s3 = path.startswith("/bucket") \
            or path.startswith("/brix-conform-missing-")
        parsed = urllib.parse.urlsplit(self.path)
        verdict = self._authorize_presigned(is_s3, parsed)
        if verdict is not None:
            return verdict
        verdict = self._authorize_bearer(is_s3, authorization)
        if verdict is not None:
            return verdict
        verdict = self._authorize_sigv4(is_s3, authorization)
        if verdict is not None:
            return verdict
        return True
