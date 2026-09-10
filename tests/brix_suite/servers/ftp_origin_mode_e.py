"""GridFTP MODE E framing for the test FTP origin (GFD.020 §3.4).

Kept beside ftp_origin_server.py rather than inside it: the origin is an
RFC-959 server, and extended block mode is a separable layer that the outbound
driver's `mode=e` store param turns on.  Splitting it also keeps both files
comfortably under the repo's file-size cap.

An extended-block header is 17 bytes, network order:

    +--------+------------------+------------------+
    | 1 desc |   8 byte count   |   8 byte offset  |
    +--------+------------------+------------------+

The descriptor bits BriX consumes are EOF (0x40 — OFFSET then carries the TOTAL
number of EOD blocks the sender promises) and EOD (0x08 — this connection is
finished).  Blocks are ABSOLUTE-offset addressed and may legally arrive out of
order, which is exactly why the receiver must police them: a block overlapping
bytes it has already committed is corruption or an attempt to rewrite accepted
(and possibly already-checksummed) data.

`fault=` deliberately emits streams a conforming sender never would.  They are
not decoration — each one is a receiver refusal that has to be proven, and a
test origin that could only be well-behaved could not prove any of them.
"""

from __future__ import annotations

import struct

FTP_EB_HDR = 17

FTP_EB_EOR = 0x80
FTP_EB_EOF = 0x40
FTP_EB_ERROR = 0x20
FTP_EB_RESTART = 0x10
FTP_EB_EOD = 0x08

CHUNK = 65536

# Every fault this module can inject, with the receiver refusal it must provoke.
FAULTS = {
    # a second block covering bytes already committed
    "overlap": "overlaps committed bytes",
    # the same replay, but withheld until the transfer has moved past the first
    # read window.  The distinction is the whole point: with `overlap` the very
    # first driver read fails and the response header has not been sent yet, so
    # a status code is still available; with `late-overlap` the first window
    # succeeded, the 200 and its Content-Length are already on the wire, and
    # the only report left is to stop.  A serve path that answered the second
    # case with a status would be inventing one for a response it had already
    # begun.
    "late-overlap": "overlaps committed bytes",
    # a block addressed past the window the client asked for
    "out-of-window": "outside the requested window",
    # a header cut in half, then a close
    "truncated-header": "closed mid-header",
    # EOF promises more EODs than are ever sent: the transfer must NOT be
    # reported complete just because the socket went quiet
    "short-eod": None,
}


def pack(descriptor: int, count: int, offset: int) -> bytes:
    """One 17-byte extended-block header."""
    return struct.pack("!BQQ", descriptor, count, offset)


def unpack(header: bytes) -> tuple[int, int, int]:
    """(descriptor, count, offset) from a 17-byte header."""
    return struct.unpack("!BQQ", header)


def _blocks(payload: bytes, base: int, chunk: int):
    for i in range(0, len(payload), chunk):
        yield base + i, payload[i:i + chunk]


def _resolve_fault(fault: str | None, base: int) -> str | None:
    """Validate `fault` and resolve the ones addressed by the restart offset.

    `late-overlap` is not a distinct wire behaviour — it is `overlap`, withheld
    until the transfer has moved past the first window.  It has to be resolved
    HERE rather than counted, because the driver opens a fresh control
    connection per window: this module sees each window as an independent
    transfer, and `base` is the only thing that says which one it is looking at.
    """
    if fault is not None and fault not in FAULTS:
        raise ValueError(f"unknown MODE E fault {fault!r}")
    if fault == "late-overlap":
        return "overlap" if base > 0 else None
    return fault


def _send_truncated_header(sock, payload: bytes, base: int) -> None:
    """Half a header, then a close — a stream that ends mid-frame."""
    sock.sendall(pack(0, len(payload), base)[:9])


def _send_out_of_window(sock, payload: bytes, base: int) -> None:
    """One legitimate byte, then one addressed far outside the window.

    The legitimate byte is not decoration: without it a receiver could refuse
    the transfer for being empty and the test would never learn whether the
    OFFSET was policed at all.
    """
    sock.sendall(pack(0, 1, base) + payload[:1])
    far = base + len(payload) + (1 << 20)
    sock.sendall(pack(0, 1, far) + b"\x00")


def _send_blocks(sock, payload: bytes, base: int, chunk: int,
                 replay: bool) -> bool:
    """Frame `payload` as blocks.  True when a replay cut the stream short.

    The replay is a block repeated verbatim: a benign-looking retransmit the
    receiver must still refuse, because it cannot tell it from a rewrite of
    bytes it has already accepted and possibly already checksummed.
    """
    for offset, block in _blocks(payload, base, chunk):
        sock.sendall(pack(0, len(block), offset) + block)
        if replay:
            sock.sendall(pack(0, len(block), offset) + block)
            return True
    return False


def _send_trailer(sock, fault: str | None) -> None:
    """The EOF|EOD trailer, whose OFFSET promises how many EODs are owed.

    A single-connection transfer owes exactly one; `short-eod` promises two and
    sends one, so a receiver that treated a quiet socket as completion would
    accept a truncated file.
    """
    promised = 2 if fault == "short-eod" else 1
    sock.sendall(pack(FTP_EB_EOF | FTP_EB_EOD, 0, promised))


def send_transfer(sock, payload: bytes, base: int = 0, *,
                  chunk: int = CHUNK, fault: str | None = None) -> None:
    """Frame `payload` as MODE E blocks starting at absolute offset `base`.

    Each fault owns a function rather than a branch in this one: they share no
    body — two of them never reach the block loop at all — and the shape that
    reads as one flow with five conditionals inside it is the shape that made
    `late-overlap` hard to add.
    """
    fault = _resolve_fault(fault, base)

    if fault == "truncated-header":
        _send_truncated_header(sock, payload, base)
        return

    if fault == "out-of-window":
        _send_out_of_window(sock, payload, base)
        return

    if _send_blocks(sock, payload, base, chunk, fault == "overlap"):
        return

    _send_trailer(sock, fault)


def _recv_at_least(sock, buffer: bytes, want: int) -> tuple[bytes, bool]:
    """Read until `buffer` holds `want` bytes.  Returns (buffer, closed).

    `closed` says the peer hung up before that, and deliberately does not say
    whether that was an error: the same close is the clean end of a transfer
    between blocks and a truncation inside one, so only the caller — which
    knows WHERE in a block the stream stopped — can tell them apart.
    """
    while len(buffer) < want:
        more = sock.recv(65536)
        if not more:
            return buffer, True
        buffer += more
    return buffer, False


def _recv_exact(sock, buffer: bytes, want: int, what: str) -> bytes:
    """Read until `buffer` holds `want` bytes; a close before that is an error.

    `what` names the part of the block still outstanding, so a truncated stream
    reports WHERE it stopped rather than only that it stopped.
    """
    buffer, closed = _recv_at_least(sock, buffer, want)
    if closed:
        raise OSError(f"MODE E stream ended mid-{what}")
    return buffer


def _recv_blocks(sock, limit: int):
    """Yield (descriptor, offset, payload) for each block arriving on `sock`.

    Framing lives here and placement lives in the caller, so neither has to
    reason about the other: every way a stream can be malformed raises from
    this generator, and the only close it accepts is one BETWEEN blocks.
    """
    buffer = b""
    while True:
        buffer, closed = _recv_at_least(sock, buffer, FTP_EB_HDR)
        if closed and not buffer:
            return
        buffer = _recv_exact(sock, buffer, FTP_EB_HDR, "header")
        descriptor, count, offset = unpack(buffer[:FTP_EB_HDR])
        if offset + count > limit:
            raise OSError("MODE E block past the accepted limit")
        buffer = _recv_exact(sock, buffer[FTP_EB_HDR:], count, "payload")
        yield descriptor, offset, buffer[:count]
        buffer = buffer[count:]
        if descriptor & FTP_EB_EOD:
            return


def recv_transfer(sock, *, limit: int = 64 * 1024 * 1024) -> bytes:
    """Reassemble one inbound MODE E transfer into a bytes object.

    Mirrors the receiver contract rather than trusting it: blocks are placed at
    their own offsets, so an out-of-order sender round-trips correctly.
    """
    chunks: dict[int, bytes] = {}
    end = 0
    for _descriptor, offset, block in _recv_blocks(sock, limit):
        if block:
            chunks[offset] = block
            end = max(end, offset + len(block))
    return _flatten(chunks, end)


def _flatten(chunks: dict[int, bytes], end: int) -> bytes:
    out = bytearray(end)
    for offset, block in chunks.items():
        out[offset:offset + len(block)] = block
    return bytes(out)
