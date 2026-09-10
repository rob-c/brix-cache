"""The retrieve half of the test FTP origin — RETR, ERET and the block sender.

WHAT: `FtpOriginRetrieveMixin`, the methods FtpOriginHandler uses to push bytes
out of a file and onto a data channel: the shared window sender, the two fault
injectors that make a misbehaving door spellable, and the RETR/ERET commands
themselves.

WHY it is a separate module: three phase-115 waves land here (W5.1 MODE E,
W5.2 ERET, W5.3 SPAS) and each brings a body plus the faults that prove the
driver refuses it, while the command loop, the namespace commands and the
listener bookkeeping next door change hardly at all.  Splitting on that seam
keeps ftp_origin_server.py under the file-size cap and keeps the retrieve
behaviours — the ones a phase-115 test actually reads — in one place.

HOW: a mixin, not a helper class.  Every method here needs the handler's own
`self` (the control socket, the negotiated mode, the pending stripes, the
server's option block), so composing it any other way would mean threading
five arguments through each call for no gain in isolation.
"""

import math

from pathlib import Path

from brix_suite.servers import ftp_origin_mode_e as eb
from brix_suite.servers import ftp_origin_striped as spas

#: ERET misbehaviours, selected by filename prefix `eret-<fault>-*`.
#:
#: `refuse` — advertised in FEAT, then answered 500 at use time.  Real doors do
#: this: FEAT says ERET, the implementation supports retrieve-modes this driver
#: never sends.  The driver must fall back to POSITIONED REST+RETR.
#: `liar`   — answered with the whole file from offset 0 instead of the window
#: that was asked for.  In MODE E the blocks then carry offsets outside the
#: request and the receiver must refuse them; the alternative is a sink that
#: takes the head of a file for its middle, silently.
#: `overrun` — honoured the OFFSET and ignored the LENGTH, answering the window
#: with everything from there to EOF.  This is the only fault that separates a
#: receiver which polices a DECLARED window from one that stops politely at the
#: edge of any window: `liar` is refused on its offsets alone, so a driver that
#: had dropped window policing entirely would still pass it.  A real door does
#: this by reusing its RETR path for ERET and forgetting the third argument.
ERET_FAULTS = ("refuse", "liar", "overrun", "hole")


class FtpOriginRetrieveMixin:
    def _eb_fault(self, path: Path) -> str | None:
        """Which MODE E fault, if any, this transfer should inject.

        A process-wide ``--eb-fault`` wins when it is set, but by default the
        fault is addressed BY NAME: ``eb-<fault>-*`` is served with that fault.
        A per-process switch would cost one origin process and one nginx front
        per refusal, and a lab that expensive grows only the refusals someone
        had the patience for; name-addressing puts every entry in
        ``ftp_origin_mode_e.FAULTS`` one seed file away.
        """
        if self.server.eb_fault is not None:
            return self.server.eb_fault
        if not path.name.startswith("eb-"):
            return None
        for fault in eb.FAULTS:
            if path.name.startswith(f"eb-{fault}-"):
                return fault
        return None

    def _send_window(self, path: Path, offset: int, length: int | None) -> None:
        """Push [offset, offset+length) — the one body RETR and ERET share.

        `length is None` is RETR's contract: everything from the restart marker
        to EOF.  A window is ERET's, and in MODE E it matters that the blocks
        carry `offset` as their ABSOLUTE address, because that is precisely what
        the driver's receiver checks the window against.
        """
        self._reply(150, "Opening data connection")
        try:
            with path.open("rb") as source:
                source.seek(offset)
                if self.stripes:
                    body = source.read() if length is None else source.read(length)
                    self._send_striped(body, offset)
                else:
                    self._send_single(source, path, offset, length)
        except OSError:
            self._reply(426, "Data connection failed")
            return
        self._reply(226, "Transfer complete")

    def _send_single(self, source, path: Path, offset: int,
                     length: int | None) -> None:
        with self._data_connection() as data:
            if self.mode == "E":
                body = source.read() if length is None else source.read(length)
                eb.send_transfer(data, body, offset,
                                 chunk=self.server.eb_chunk,
                                 fault=self._eb_fault(path))
            else:
                self._stream_window(data, source, length)

    def _send_striped(self, body: bytes, offset: int) -> None:
        """Fan one window across the stripes the client dialled.

        Striping is MODE E only — the blocks carry the absolute offsets the
        receiver reassembles by — and the driver refuses `streams>1` without
        `mode=e` at config time, so reaching here in MODE S would be a bug on
        both sides.  It is asserted rather than accommodated.
        """
        listeners, self.stripes = self.stripes, []
        wrap = None
        if self.prot == "P":
            wrap = lambda sock: self.server.data_tls.wrap_socket(
                sock, server_side=True)
        connections = spas.accept_all(listeners, wrap=wrap)
        try:
            assert self.mode == "E", "striped transfers exist only in MODE E"
            spas.send_striped(connections, body, offset,
                              chunk=self.server.eb_chunk)
        finally:
            spas.close_connections(connections)

    @staticmethod
    def _stream_window(data, source, length: int | None) -> None:
        """Copy `length` bytes (or the rest of the file) onto the data channel.

        "to the end" is carried as an infinite budget rather than as a None to
        be re-tested every iteration: the loop then has one shape, not two.
        """
        remaining = math.inf if length is None else length
        while remaining > 0:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                return
            data.sendall(chunk)
            remaining -= len(chunk)

    def _eret_fault(self, path: Path) -> str | None:
        """Which ERET misbehaviour, if any, this transfer should inject.

        Addressed by name for the same reason `_eb_fault` is: a per-process
        switch would cost one origin and one nginx front per refusal, and the
        refusals someone had the patience to wire are never all of them.
        """
        if not path.name.startswith("eret-"):
            return None
        for fault in ERET_FAULTS:
            if path.name.startswith(f"eret-{fault}-"):
                return fault
        return None

    @staticmethod
    def _eret_window(arg: str):
        """Parse `P <offset> <length> <path>`.

        Returns `(offset, length, path)`, or the text of the 501 that argument
        earned — an operator reading a trace wants to know WHICH half of the
        argument was wrong, and the caller has no other way to tell.
        """
        parts = arg.split(" ", 3)
        if len(parts) != 4 or parts[0].upper() != "P":
            return "Unsupported ERET retrieve mode"
        try:
            offset, length = int(parts[1], 10), int(parts[2], 10)
        except ValueError:
            return "Invalid ERET window"
        if offset < 0 or length <= 0:
            return "Invalid ERET window"
        return offset, length, parts[3]

    def _command_eret(self, arg: str) -> None:
        """ERET <retrieve-mode> <offset> <length> <path> (GFD.020 5.3)."""
        if not self.server.eret:
            self._reply(502, "Command not implemented")
            return
        window = self._eret_window(arg)
        if isinstance(window, str):
            self._reply(501, window)
            return
        offset, length, name = window
        path = self._require_path(name)
        if path is None:
            return
        fault = self._eret_fault(path)
        if fault == "refuse":
            self._reply(500, "ERET not supported here after all")
            return
        if fault == "liar":
            offset, length = 0, None
        if fault == "overrun":
            length = None
        if fault == "hole":
            # Accept the window, open the data connection, send nothing.  A
            # receiver that treats an unsent window as a copied one leaves the
            # caller's buffer holding whatever was already there — zeroes, on
            # any freshly allocated or sparse destination — and cannot tell
            # them from the object's own zero bytes.  That hands the origin a
            # way to write zeroes into a client's file by staying silent.
            length = 0
        self.rest_offset = 0     # ERET carries its own position; REST is spent
        self._send_window(path, offset, length)

    def _command_retr(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        offset, self.rest_offset = self.rest_offset, 0
        self._send_window(path, offset, None)
