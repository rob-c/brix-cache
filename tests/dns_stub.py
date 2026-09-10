"""
dns_stub.py — an in-process nameserver for the phase-116 runtime-DNS tests.

WHAT: A UDP + TCP DNS responder (RFC 1035 wire format, no dependencies) with
      a mutable zone (A / AAAA / CNAME / PTR), per-name rcode overrides, TTLs,
      a timestamped query log, a pause switch that drops every query (the
      "nameserver unreachable" case) and two poisoning knobs — an answer
      carrying a different question name or a different transaction id — for
      the security negatives.  Plus `write_resolv_conf()` and a Prometheus
      text-format parser for the assertions that read `/metrics`.
WHY:  The phase pins *behaviour* — one query per TTL window, the glibc search
      order, re-resolution on a record swap, a dead name never blocking a
      start — and none of that is observable against a real resolver.  brix
      accepts `nameserver <ip>:<port>` in resolv.conf precisely so an
      unprivileged stub can be the nameserver.
HOW:  One thread per transport; every socket has a short timeout so `stop()`
      returns promptly.  Names are lowercased and stored without the trailing
      dot; the query log records every question with its transport and time.
      The zone lock is a plain mutex — the stub is a test fixture, not a
      server.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ephemeral_port import free_port

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_AAAA = 28
TYPE_ANY = 255
CLASS_IN = 1

RCODE_OK = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

TYPE_NAMES = {TYPE_A: "A", TYPE_AAAA: "AAAA", TYPE_CNAME: "CNAME",
              TYPE_PTR: "PTR", TYPE_NS: "NS", TYPE_SOA: "SOA", TYPE_ANY: "ANY"}


def norm(name: str) -> str:
    return name.rstrip(".").lower()


def encode_name(name: str) -> bytes:
    out = b""
    for label in norm(name).split("."):
        if label:
            raw = label.encode("ascii")
            out += bytes([len(raw)]) + raw
    return out + b"\0"


def _follow_pointer(buf: bytes, off: int, hops: int) -> tuple[int, int]:
    """Target offset of the compression pointer at `off`, and the hop count."""
    if hops >= 16:
        raise ValueError("compression loop")
    return ((buf[off] & 0x3F) << 8) | buf[off + 1], hops + 1


def _read_label(buf: bytes, off: int, labels: list[str]) -> tuple[int, bool]:
    """Append the label at `off`; returns (next offset, reached-the-root)."""
    n = buf[off]
    off += 1
    if n == 0:
        return off, True
    labels.append(buf[off:off + n].decode("ascii", "replace"))
    return off + n, False


def _labels_from(buf: bytes, off: int, labels: list[str], hops: int = 0) -> int:
    """Append every label of the name at `off` (following compression
    pointers into the rest of the packet) and return the offset just past
    the name AS WRITTEN HERE: the root label, or a pointer's two bytes."""
    while True:
        if buf[off] & 0xC0 == 0xC0:
            target, _ = _follow_pointer(buf, off, hops)
            _labels_from(buf, target, labels, hops + 1)
            return off + 2
        off, root = _read_label(buf, off, labels)
        if root:
            return off


def decode_name(buf: bytes, off: int) -> tuple[str, int]:
    """Return (name, offset-after-name); follows compression pointers."""
    labels: list[str] = []
    end = _labels_from(buf, off, labels)
    return ".".join(labels).lower(), end


def ptr_name(ip: str) -> str:
    """The in-addr.arpa / ip6.arpa owner name for an address literal."""
    return ipaddress.ip_address(ip).reverse_pointer


@dataclass
class Record:
    rtype: int
    data: str          # address literal or target name
    ttl: int = 60

    def rdata(self) -> bytes:
        if self.rtype == TYPE_A:
            return socket.inet_pton(socket.AF_INET, self.data)
        if self.rtype == TYPE_AAAA:
            return socket.inet_pton(socket.AF_INET6, self.data)
        return encode_name(self.data)


@dataclass
class Query:
    name: str
    qtype: int
    qid: int
    proto: str
    at: float = field(default_factory=time.monotonic)

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, str(self.qtype))


class DnsStub:
    """A scriptable nameserver on an ephemeral loopback port."""

    def __init__(self, host: str = "127.0.0.1", port: int | None = None):  # net-literal-allow: default bind of the test-only stub resolver, loopback
        self.host = host
        self.fixed_port = port is not None
        self.port = port if port is not None else free_port(host)
        self._zone: dict[str, list[Record]] = {}
        self._rcode: dict[str, int] = {}
        self._lock = threading.Lock()
        self.queries: list[Query] = []
        self.paused = False               # drop every query -> client timeout
        self.spoof_qname: str | None = None   # answer under another name
        self.spoof_id = False             # answer with a wrong transaction id
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None

    # ---- zone ------------------------------------------------------------
    def add(self, name: str, rtype: int, data: str, ttl: int = 60) -> None:
        with self._lock:
            self._zone.setdefault(norm(name), []).append(Record(rtype, data, ttl))

    def add_a(self, name: str, ip: str, ttl: int = 60) -> None:
        self.add(name, TYPE_A, ip, ttl)

    def add_aaaa(self, name: str, ip: str, ttl: int = 60) -> None:
        self.add(name, TYPE_AAAA, ip, ttl)

    def add_cname(self, name: str, target: str, ttl: int = 60) -> None:
        self.add(name, TYPE_CNAME, target, ttl)

    def add_ptr(self, ip: str, target: str, ttl: int = 60) -> None:
        self.add(ptr_name(ip), TYPE_PTR, target, ttl)

    def remove(self, name: str, rtype: int | None = None) -> None:
        with self._lock:
            if rtype is None:
                self._zone.pop(norm(name), None)
            else:
                kept = [r for r in self._zone.get(norm(name), []) if r.rtype != rtype]
                self._zone[norm(name)] = kept

    def swap_a(self, name: str, ip: str, ttl: int = 60) -> None:
        """Replace every A record of `name` with one pointing at `ip`."""
        with self._lock:
            kept = [r for r in self._zone.get(norm(name), []) if r.rtype != TYPE_A]
            self._zone[norm(name)] = kept + [Record(TYPE_A, ip, ttl)]

    def set_rcode(self, name: str, rcode: int | None) -> None:
        """Force an rcode for `name` (None clears the override)."""
        with self._lock:
            if rcode is None:
                self._rcode.pop(norm(name), None)
            else:
                self._rcode[norm(name)] = rcode

    # ---- query log -------------------------------------------------------
    def clear_queries(self) -> None:
        with self._lock:
            self.queries.clear()

    def queries_for(self, name: str, qtype: int | None = None) -> list[Query]:
        with self._lock:
            return [q for q in self.queries
                    if q.name == norm(name) and (qtype is None or q.qtype == qtype)]

    def wait_for_query(self, name: str, count: int = 1, timeout: float = 10.0,
                       qtype: int | None = None) -> list[Query]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            seen = self.queries_for(name, qtype)
            if len(seen) >= count:
                return seen
            time.sleep(0.02)
        return self.queries_for(name, qtype)

    def query_names(self) -> list[str]:
        """Question names in arrival order (duplicates kept)."""
        with self._lock:
            return [q.name for q in self.queries]

    # ---- wire ------------------------------------------------------------
    def _observe(self, qname: str, qtype: int, qid: int,
                 proto: str) -> tuple[list[Record], int] | None:
        """Book the question and return (records, rcode); None while paused."""
        with self._lock:
            self.queries.append(Query(qname, qtype, qid, proto))
            if self.paused:
                return None
            records = list(self._zone.get(qname, []))
            rcode = self._rcode.get(qname)
        if rcode is None:
            rcode = RCODE_OK if qname in self._zone else RCODE_NXDOMAIN
        return records, rcode

    @staticmethod
    def _rr(rec: Record) -> bytes:
        """One answer RR, owner name compressed to the question at offset 12."""
        rdata = rec.rdata()
        return (b"\xC0\x0C"
                + struct.pack("!HHIH", rec.rtype, CLASS_IN, rec.ttl, len(rdata))
                + rdata)

    def _answer(self, packet: bytes, proto: str) -> bytes | None:
        if len(packet) < 12:
            return None
        qid, flags, qdcount = struct.unpack("!HHH", packet[:6])
        if qdcount < 1:
            return None
        qname, off = decode_name(packet, 12)
        qtype, qclass = struct.unpack("!HH", packet[off:off + 4])
        seen = self._observe(qname, qtype, qid, proto)
        if seen is None:
            return None
        records, rcode = seen
        answers = [self._rr(r) for r in self._matching(records, qtype)] \
            if rcode == RCODE_OK else []
        question = packet[12:off + 4] if self.spoof_qname is None else \
            encode_name(self.spoof_qname) + struct.pack("!HH", qtype, qclass)
        rflags = 0x8180 | (flags & 0x0100) | (rcode & 0xF)
        header = struct.pack("!HHHHHH", qid ^ (0x5555 if self.spoof_id else 0),
                             rflags, 1, len(answers), 0, 0)
        return header + question + b"".join(answers)

    @staticmethod
    def _of_type(records: list[Record], qtype: int) -> list[Record]:
        """The records of one type; TYPE_ANY takes them all."""
        if qtype == TYPE_ANY:
            return list(records)
        return [r for r in records if r.rtype == qtype]

    def _cname_answer(self, records: list[Record], qtype: int) -> list[Record]:
        """A/AAAA fallback: the alias RR plus what its target holds."""
        if qtype not in (TYPE_A, TYPE_AAAA):
            return []
        cnames = self._of_type(records, TYPE_CNAME)
        if not cnames:
            return []
        target = self._zone.get(norm(cnames[0].data), [])
        return cnames[:1] + self._of_type(target, qtype)

    def _matching(self, records: list[Record], qtype: int) -> list[Record]:
        """Answer RRs: direct type matches, else a CNAME chain."""
        out = self._of_type(records, qtype)
        if out:
            return out
        return self._cname_answer(records, qtype)

    # ---- transports ------------------------------------------------------
    def _serve_udp_once(self) -> None:
        """One datagram: answer it, or drop it (malformed / paused / gone)."""
        packet, peer = self._udp.recvfrom(4096)
        try:
            reply = self._answer(packet, "udp")
        except (ValueError, IndexError, struct.error):
            return
        if reply is not None:
            self._udp.sendto(reply, peer)

    def _serve_udp(self) -> None:
        assert self._udp is not None
        while not self._stop.is_set():
            try:
                self._serve_udp_once()
            except socket.timeout:
                continue
            except OSError:
                break

    def _serve_tcp_conn(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                head = conn.recv(2)
                if len(head) < 2:
                    return
                (n,) = struct.unpack("!H", head)
                packet = b""
                while len(packet) < n:
                    chunk = conn.recv(n - len(packet))
                    if not chunk:
                        return
                    packet += chunk
                reply = self._answer(packet, "tcp")
                if reply is not None:
                    conn.sendall(struct.pack("!H", len(reply)) + reply)
            except (OSError, ValueError, IndexError, struct.error):
                return

    def _serve_tcp(self) -> None:
        assert self._tcp is not None
        while not self._stop.is_set():
            try:
                conn, _peer = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_tcp_conn, args=(conn,),
                             daemon=True).start()

    def _bind(self) -> None:
        """Bind UDP and TCP on the same port; the caller retries on a clash."""
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.host, self.port))
        self._udp.settimeout(0.2)
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((self.host, self.port))
        self._tcp.listen(16)
        self._tcp.settimeout(0.2)

    def _close_sockets(self) -> None:
        for s in (self._udp, self._tcp):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        self._udp = self._tcp = None

    def start(self, attempts: int = 5) -> "DnsStub":
        """free_port() is advisory: between its probe and this bind, a worker's
        outgoing connection can take the port from the same ephemeral range, and
        UDP can succeed where TCP then fails.  On an auto-chosen port, pick
        another and retry rather than failing the test that asked for a stub.
        """
        self._stop.clear()
        for attempt in range(attempts):
            try:
                self._bind()
                break
            except OSError:
                self._close_sockets()
                if self.fixed_port or attempt == attempts - 1:
                    raise
                self.port = free_port(self.host)
        self._threads = [threading.Thread(target=self._serve_udp, daemon=True),
                         threading.Thread(target=self._serve_tcp, daemon=True)]
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads = []
        self._close_sockets()

    def __enter__(self) -> "DnsStub":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# ---- resolv.conf ---------------------------------------------------------

def write_resolv_conf(path: str | Path, nameservers, *, search=(), ndots: int = 1,
                      timeout: int = 1, attempts: int = 1, extra: str = "") -> Path:
    """Write a resolv.conf; `nameservers` are (host, port) pairs or strings.

    brix accepts the `ip:port` extension (resolver_build.c), so a stub on an
    unprivileged port is a legal nameserver."""
    lines = []
    for ns in nameservers:
        lines.append("nameserver %s" % (ns if isinstance(ns, str)
                                        else "%s:%d" % tuple(ns)))
    if search:
        lines.append("search " + " ".join(search))
    lines.append("options ndots:%d timeout:%d attempts:%d" % (ndots, timeout, attempts))
    if extra:
        lines.append(extra)
    p = Path(path)
    p.write_text("\n".join(lines) + "\n")
    return p


# ---- /metrics text format ------------------------------------------------

def _split_sample(head: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """"name{a=\"1\",b=\"2\"}" -> ("name", ((a, 1), (b, 2))); no braces -> ()."""
    if "{" not in head:
        return head, ()
    name, _, rest = head.partition("{")
    labels = tuple((k, v.strip('"')) for k, _, v in
                   (part.partition("=") for part in rest.rstrip("}").split(",")
                    if part))
    return name, labels


def _sample(line: str):
    """((name, labels), value) for one sample line; None for anything else."""
    if not line or line.startswith("#"):
        return None
    head, _, value = line.rpartition(" ")
    try:
        return _split_sample(head), float(value)
    except ValueError:
        return None


def parse_metrics(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """{(name, ((label, value), ...)): value} for every sample line."""
    samples = (_sample(line) for line in text.splitlines())
    return {key: value for key, value in (s for s in samples if s is not None)}


def metric(text: str, name: str, **labels) -> float | None:
    """One sample by name and exact label set; None when absent."""
    return parse_metrics(text).get((name, tuple(sorted(labels.items()))))


def metric_family(text: str, name: str) -> dict[tuple[tuple[str, str], ...], float]:
    """Every sample of one family keyed by its (sorted) label tuple."""
    return {tuple(sorted(labels)): v for (n, labels), v in parse_metrics(text).items()
            if n == name}
