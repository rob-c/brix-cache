"""Bounded XRootD splice for hostile native-TPC GSI peer-certificate tests.

The proxy reuses the suite's response-aware TPC fault splice and changes only
the first ``kXR_authmore`` reply to a GSI request.  It either removes every
``kXRS_x509`` bucket or replaces it with malformed PEM while leaving the real
source's unsigned-DH public key and negotiation buckets intact.  A vulnerable
destination can therefore complete key agreement and send round two; a fixed
destination must close before that credential-bearing request.
"""

import struct

from test_tpc_pull_integrity import _KxrPullFaultProxy


KXR_AUTH = 3000
KXR_AUTHMORE = 4002
KXRS_NONE = 0
KXRS_X509 = 3022
_MALFORMED_CERT = b"not a PEM certificate\n"


def _bucket_start(body):
    """Return the first bucket offset after a bounded GSI preamble."""
    name_end = body.find(b"\x00")
    cursor = name_end + 1 + 4
    return cursor if name_end >= 0 and cursor <= len(body) else None


def _bucket_extent(body, cursor):
    """Decode one bounded bucket as ``(type, end)``, or return ``None``."""
    if len(body) - cursor < 4:
        return None
    bucket_type = struct.unpack("!I", body[cursor:cursor + 4])[0]
    if bucket_type == KXRS_NONE:
        return bucket_type, len(body)
    if len(body) - cursor < 8:
        return None
    bucket_length = struct.unpack("!I", body[cursor + 4:cursor + 8])[0]
    bucket_end = cursor + 8 + bucket_length
    return (bucket_type, bucket_end) if bucket_end <= len(body) else None


def _append_rewritten_bucket(rewritten, body, cursor, bucket_type, bucket_end,
                             mode):
    """Copy a non-certificate bucket, or append the requested cert mutation."""
    if bucket_type != KXRS_X509:
        rewritten.extend(body[cursor:bucket_end])
        return False
    if mode == "malformed-cert":
        rewritten.extend(struct.pack("!II", KXRS_X509, len(_MALFORMED_CERT)))
        rewritten.extend(_MALFORMED_CERT)
    if mode == "empty-cert":
        rewritten.extend(struct.pack("!II", KXRS_X509, 0))
    return True


def _rewrite_peer_certificate(body, mode):
    """Return a bounded GSI body with its certificate removed or malformed.

    ``None`` means the body was malformed or contained no certificate, so the
    proxy leaves it untouched and the calling test fails its mutation-count
    assertion instead of accidentally attributing an unrelated refusal.
    """
    cursor = _bucket_start(body)
    if cursor is None:
        return None

    rewritten = bytearray(body[:cursor])
    found = False
    while cursor < len(body):
        extent = _bucket_extent(body, cursor)
        if extent is None:
            return None
        bucket_type, bucket_end = extent
        if bucket_type == KXRS_NONE:
            rewritten.extend(body[cursor:])
            return bytes(rewritten) if found else None
        found |= _append_rewritten_bucket(
            rewritten, body, cursor, bucket_type, bucket_end, mode)
        cursor = bucket_end

    return bytes(rewritten) if found else None


class GsiPeerMutationProxy(_KxrPullFaultProxy):
    """Mutate one GSI server certificate and observe any round-two request."""

    MODES = ("missing-cert", "empty-cert", "malformed-cert")

    def __init__(self, target_host, target_port):
        super().__init__(target_host, target_port)
        self.mutation_count = 0
        self.round2_request_count = 0
        self._round1_mutated = False

    def arm(self, mode):
        """Arm one mutation and reset observations for the next connection."""
        super().arm(mode)
        with self._lock:
            self.mutation_count = 0
            self.round2_request_count = 0
            self._round1_mutated = False

    def observations(self):
        """Return an atomic snapshot of mutation and round-two observations."""
        with self._lock:
            return self.mutation_count, self.round2_request_count

    def _observe_request(self, header, opcode, payload):
        """Count a post-mutation GSI auth request at the disclosure sink."""
        if opcode != KXR_AUTH or header[16:20] != b"gsi\x00":
            return
        with self._lock:
            if self._round1_mutated:
                self.round2_request_count += 1

    def _fault_opcode(self, opcode, status, body):
        """Rewrite the first GSI authmore while preserving every other frame."""
        if opcode != KXR_AUTH:
            return status, body

        with self._lock:
            if self._mode is not None and status == KXR_AUTHMORE:
                rewritten = _rewrite_peer_certificate(body, self._mode)
                if rewritten is None:
                    return status, body
                self._mode = None
                self.mutation_count += 1
                self._round1_mutated = True
                return status, rewritten
        return status, body
