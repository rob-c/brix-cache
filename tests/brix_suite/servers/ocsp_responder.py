#!/usr/bin/env python3
"""ocsp_responder.py — the controllable OCSP responder the suite never had.

``test_ocsp_require_nonce.py`` says it in its own docstring: "Live OCSP
negatives need a controllable responder that this suite does not stand up", so
every OCSP property in the tree is pinned against the C source and no test has
ever driven ``brix_ocsp`` at runtime.  This is that responder.

It answers whatever the caller told it to answer, per certificate:

    --entry <cert.pem>,<issuer.pem>,<good|revoked|unknown>

The verdict is keyed on the SERIAL in the request, because that is what the
server asks about: ``brix_ocsp_check_cert`` builds its OCSP_CERTID with
``OCSP_cert_to_id(NULL, leaf, issuer)`` (SHA-1 issuer name/key hash + leaf
serial), and ``OCSP_resp_find_status`` matches the response's CertID against it
byte for byte.  So an entry is a (cert, issuer) PAIR, not a certificate: the
same certificate answered under the wrong issuer produces a CertID the server
will not find, which is the "certificate not found in OCSP response" deny and
not the verdict the test asked for.  A serial with no entry gets
``UNAUTHORIZED`` — what a real responder says about a CA it does not serve.

Control plane, on the same port (mirrors tests/cvmfs/mock_stratum1.py):

    GET  /ctl/log        -> [{"serial": <int>, "verdict": "good"}, ...]
    POST /ctl/reset-log  -> forget them

The log is the attribution evidence for every verdict in the test files: it is
the only thing that distinguishes "the login was refused because the responder
said REVOKED" from "the login was refused and the responder was never asked".

Behaviour switches for the negatives:

    --omit-nonce   never echo the request's nonce (the replay case
                   brix_ocsp_require_nonce is written against)
    --wrong-nonce  echo a DIFFERENT nonce.  OCSP_check_nonce() reports a missing
                   nonce as <0 and a mismatched one as 0, and check_ocsp_response()
                   denies the mismatch unconditionally while only the missing one
                   is under the flag — so this is the boundary that says
                   brix_ocsp_require_nonce means "missing", not "checked at all".
    --stale        date the response a week into the past, outside
                   BRIX_OCSP_VALIDITY_MAX_AGE_SEC, so it degrades to UNKNOWN

Usage:
    ocsp_responder.py --port 30761 --signer-cert ca.pem --signer-key ca.key \
                      --entry proxy.pem,eec.pem,good ...

Runs in the foreground; the caller backgrounds it and probes the port.
"""

import argparse
import datetime
import http.server
import json
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

_STATUS = {
    "good": ocsp.OCSPCertStatus.GOOD,
    "revoked": ocsp.OCSPCertStatus.REVOKED,
    "unknown": ocsp.OCSPCertStatus.UNKNOWN,
}


def _load_cert(path):
    with open(path, "rb") as handle:
        return x509.load_pem_x509_certificate(handle.read())


def _load_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


class _Responder:
    """The verdict table plus the request log, shared by every handler thread."""

    def __init__(self, signer_cert, signer_key, entries, *,
                 omit_nonce=False, wrong_nonce=False, stale=False):
        self.signer_cert = signer_cert
        self.signer_key = signer_key
        self.entries = entries          # serial -> (cert, issuer, verdict)
        self.omit_nonce = omit_nonce
        self.wrong_nonce = wrong_nonce
        self.stale = stale
        self.log = []
        self.lock = threading.Lock()

    def _window(self):
        """thisUpdate/nextUpdate for one answer.

        Real "now", never x509forge's fixed epoch: check_ocsp_response() runs
        OCSP_check_validity() against the clock, and a response dated at the
        forge epoch would come back UNKNOWN — which is a soft_fail verdict, so
        the whole table would silently collapse onto one arm.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        if self.stale:
            now -= datetime.timedelta(days=7)
        return now - datetime.timedelta(minutes=1), now + datetime.timedelta(hours=12)

    def answer(self, der):
        request = ocsp.load_der_ocsp_request(der)
        serial = request.serial_number
        entry = self.entries.get(serial)
        verdict = entry[2] if entry else "unauthorized"
        self._record(serial, verdict)
        if entry is None:
            return _unauthorized_response()
        builder = self._response_builder(entry)
        builder = self._with_nonce(builder, request)
        response = builder.sign(self.signer_key, hashes.SHA256())
        return response.public_bytes(serialization.Encoding.DER)

    def _record(self, serial, verdict):
        with self.lock:
            self.log.append({"serial": serial, "verdict": verdict})

    def _response_builder(self, entry):
        cert, issuer, _ = entry
        verdict = entry[2]
        this_update, next_update = self._window()
        revoked_at, reason = _revocation_fields(verdict, this_update)
        return ocsp.OCSPResponseBuilder().add_response(
            cert=cert, issuer=issuer, algorithm=hashes.SHA1(),
            cert_status=_STATUS[verdict],
            this_update=this_update, next_update=next_update,
            revocation_time=revoked_at, revocation_reason=reason,
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, self.signer_cert)

    def _with_nonce(self, builder, request):
        if self.omit_nonce:
            return builder
        nonce = _request_nonce(request)
        if nonce is None:
            return builder
        if self.wrong_nonce:
            nonce = _wrong_nonce(nonce)
        return builder.add_extension(nonce, critical=False)


def _unauthorized_response():
    return ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(
            serialization.Encoding.DER)


def _revocation_fields(verdict, this_update):
    if verdict == "revoked":
        return (this_update - datetime.timedelta(days=1),
                x509.ReasonFlags.key_compromise)
    return None, None


def _request_nonce(request):
    try:
        return request.extensions.get_extension_for_class(x509.OCSPNonce).value
    except x509.ExtensionNotFound:
        return None


def _wrong_nonce(nonce):
    changed = bytes([nonce.nonce[0] ^ 0xFF]) + nonce.nonce[1:]
    return x509.OCSPNonce(changed)


class _Handler(http.server.BaseHTTPRequestHandler):
    responder = None                    # set by main()
    protocol_version = "HTTP/1.0"       # OCSP_sendreq_new() speaks HTTP/1.0

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") == "/ctl/reset-log":
            with self.responder.lock:
                self.responder.log.clear()
            self._send(200, b"", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            der = self.responder.answer(body)
        except Exception as exc:        # a malformed request is not a crash
            self._send(400, str(exc).encode(), "text/plain")
            return
        self._send(200, der, "application/ocsp-response")

    def do_GET(self):
        if self.path.rstrip("/") == "/ctl/log":
            with self.responder.lock:
                body = json.dumps(self.responder.log).encode()
            self._send(200, body, "application/json")
            return
        self._send(405, b"POST an OCSP request", "text/plain")

    def log_message(self, *args):
        pass


def _entries(specs):
    """--entry cert,issuer,verdict triples into {serial: (cert, issuer, verdict)}."""
    table = {}
    for spec in specs:
        cert_path, issuer_path, verdict = spec.split(",")
        if verdict not in _STATUS:
            raise SystemExit(f"unknown verdict {verdict!r} in --entry {spec}")
        cert = _load_cert(cert_path)
        table[cert.serial_number] = (cert, _load_cert(issuer_path), verdict)
    return table


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", default="127.0.0.1")  # net-literal-allow: CLI default, callers pass settings.BIND_HOST
    parser.add_argument("--signer-cert", required=True)
    parser.add_argument("--signer-key", required=True)
    parser.add_argument("--entry", action="append", default=[],
                        metavar="CERT,ISSUER,VERDICT")
    parser.add_argument("--omit-nonce", action="store_true")
    parser.add_argument("--wrong-nonce", action="store_true")
    parser.add_argument("--stale", action="store_true")
    args = parser.parse_args(argv)

    _Handler.responder = _Responder(
        _load_cert(args.signer_cert), _load_key(args.signer_key),
        _entries(args.entry), omit_nonce=args.omit_nonce,
        wrong_nonce=args.wrong_nonce, stale=args.stale)
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), _Handler)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
