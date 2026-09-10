"""GFD.020 §5.1 striped passive (SPAS) for the test FTP origin — phase-115 W5.3.

WHAT: opening several data listeners at once, spelling them as a SPAS reply,
and fanning one MODE E transfer across the connections a client dials on them.

WHY it lives outside ftp_origin_server.py: the listener STRATEGY is the whole
difference between passive and striped-passive, and it is the half a test wants
to bend — advertising a stripe on an address the origin does not own is the
FTP-bounce negative, and it has to be spellable without touching the command
loop.  Keeping it here also keeps the origin under the file-size cap.

HOW the reply is shaped (GFD.020 §5.1): one PASV-style `h1,h2,h3,h4,p1,p2`
tuple per CONTINUATION line, terminated by a `229 End` line —

    229-Entering Striped Passive Mode
     127,0,0,1,201,166
     127,0,0,1,201,167
    229 End

which is why the driver's continuation-line capture (added for the W5.2 FEAT
probe) is what makes SPAS parseable at all.

HOW the transfer is shaped: blocks are dealt round-robin across the accepted
connections, each carrying its own ABSOLUTE offset, so a receiver that honours
offsets reassembles the file no matter which socket a block arrived on and in
what order.  Every connection closes with an EOD block; the last one closes
with EOF|EOD whose OFFSET field promises the total EOD count.  Getting that
count wrong is precisely the `short-eod` fault ftp_origin_mode_e.py already
injects for the single-connection case, so it is not re-invented here.
"""

import socket

from ephemeral_port import free_port
from brix_suite.servers import ftp_origin_mode_e as eb


def open_listeners(bind_host: str, count: int, timeout: float):
    """`count` listening sockets on `bind_host`, ready to be advertised."""
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((bind_host, free_port()))
            listener.listen(1)
            listener.settimeout(timeout)
            listeners.append(listener)
    except OSError:
        close_listeners(listeners)
        raise
    return listeners


def close_listeners(listeners) -> None:
    for listener in listeners:
        listener.close()


def spas_reply(listeners, advertise_host: str) -> bytes:
    """The full 229 reply advertising `listeners`, as bytes ready to write.

    `advertise_host` is deliberately separate from the bind host: a test that
    advertises a stripe the origin does not own is how the driver's address
    check gets exercised, and that difference has to be expressible.
    """
    octets = advertise_host.split(".")
    lines = ["229-Entering Striped Passive Mode"]
    for listener in listeners:
        port = listener.getsockname()[1]
        lines.append(" " + ",".join(octets + [str(port >> 8), str(port & 255)]))
    lines.append("229 End")
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def accept_all(listeners, wrap=None):
    """Accept one connection per listener, in advertised order.

    A client that dials fewer than it was offered leaves a listener blocking
    until its timeout — which is the right shape for a test origin: the
    accept raises, the transfer fails, and nobody waits forever.
    """
    connections = []
    try:
        for listener in listeners:
            connection, _ = listener.accept()
            connection.settimeout(listener.gettimeout())
            if wrap is not None:
                connection = wrap(connection)
            connections.append(connection)
    except OSError:
        close_connections(connections)
        raise
    return connections


def close_connections(connections) -> None:
    for connection in connections:
        try:
            connection.close()
        except OSError:
            pass


def send_striped(connections, payload: bytes, base: int = 0, *,
                 chunk: int = eb.CHUNK) -> None:
    """Deal `payload` across `connections` as offset-addressed MODE E blocks.

    Round-robin rather than contiguous ranges on purpose: it guarantees the
    receiver sees blocks arriving OUT OF ORDER relative to the file, which is
    the property that separates a real striped reassembly from a receiver that
    merely concatenates whatever socket it read first.
    """
    n = len(connections)
    if n == 0:
        raise ValueError("no striped connections")

    for i, offset in enumerate(range(0, len(payload), chunk)):
        block = payload[offset:offset + chunk]
        connection = connections[i % n]
        connection.sendall(eb.pack(0, len(block), base + offset) + block)

    # Every connection retires with an EOD; the LAST also carries the EOF whose
    # OFFSET field promises how many EODs the receiver must see before it may
    # call the transfer complete.
    for connection in connections[:-1]:
        connection.sendall(eb.pack(eb.FTP_EB_EOD, 0, 0))
    connections[-1].sendall(eb.pack(eb.FTP_EB_EOF | eb.FTP_EB_EOD, 0, n))
