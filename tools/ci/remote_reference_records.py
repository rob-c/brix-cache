"""Bound logical oracle requests separately from their smaller transport frames.

Only the isolated reference bridge uses this framing. It never splits or
rewrites the XRootD operation, changes its payload, or relaxes BriX limits.
"""
from __future__ import annotations

import base64


def check_worker_length(length):
    """Reject a logical record over 64 MiB before extending its buffer."""
    if length > 64 * 1024 * 1024:
        raise ValueError('remote worker input exceeds 64 MiB')


def bounded_worker_record(record):
    """Apply the same logical cap after credential metadata transformation."""
    check_worker_length(len(record))
    return record


class WorkerRecords:
    """One connection's ordered JSON lines, never unbounded partial requests."""

    def __init__(self):
        self.pending = bytearray()

    def feed(self, data):
        """Dispatch only complete records; check size before every append."""
        cursor = 0
        while cursor < len(data):
            end = data.find(b'\n', cursor)
            stop = len(data) if end < 0 else end + 1
            check_worker_length(len(self.pending) + stop - cursor)
            self.pending.extend(memoryview(data)[cursor:stop])
            if end < 0:
                return
            record = bytes(self.pending)
            self.pending.clear()
            yield record
            cursor = stop

    def finish(self, *, allow_unterminated=False):
        """Native stdin may end a JSON line; wire EOF must end a whole record."""
        if self.pending and not allow_unterminated:
            raise ValueError('truncated remote worker input record')
        record = bytes(self.pending)
        self.pending.clear()
        return record


def worker_input_records(chunks):
    """Keep native pipe-read boundaries independent of JSON request boundaries."""
    records = WorkerRecords()
    for data in chunks:
        yield from records.feed(data)
    final = records.finish(allow_unterminated=True)
    if final:
        yield final


def input_frames(data):
    """Encode bounded fragments without changing one logical worker operation."""
    for cursor in range(0, len(data), 65536):
        yield dict(kind='input', data=base64.b64encode(data[cursor:cursor + 65536]).decode())
