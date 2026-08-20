"""Phase-33 P0 — reusable A/B throughput regression-gate harness.

The perf work in phase 33 landed two correctness-complete knobs whose only
residual is *measuring the throughput magnitude* — P3-B3 (`brix_socket_sndbuf`/
`brix_socket_rcvbuf`) and P5 (`brix_ktls`).  The magnitude was blocked not just
on the absence of a dedicated high-BDP perf host but on the absence of the
*regression-gate harness itself* (the "perf host + regression gate" half of P0).

This module is that harness: a self-contained, unprivileged A/B throughput
measurer that boots a single-process nginx via the lifecycle registry, streams a
page-cached file over the root:// wire with the module's own 4 MiB chunked reads,
and reports MiB/s for a knob-on vs knob-off pair.  It runs correctly on loopback
(where it validates the module's data path and guards gross regressions) and is
ready to produce the real BDP-sensitive numbers the moment it is pointed at a
perf host — that acquisition is the only remaining P0 blocker.

Design notes:
  * throughput is derived from the *minimum* transfer time across N runs (best
    MiB/s), which suppresses OS-scheduler / page-cache variance — the same
    technique `test_throughput.py` uses — so the measurement is repeatable.
  * reads use READ_CHUNK = 4 MiB to match BRIX_READ_MAX (one kXR_read response
    per request), so `_recv_response`'s length-framed read never straddles a
    kXR_oksofar continuation.
  * the file is read once as warm-up before timing so every timed run is served
    from the page cache — this measures the module's data path, not the disk.
"""
import socket
import ssl
import struct
import time

from _test_a_robustness_helpers import (
    make_open_req,
    make_read_req,
    make_close_req,
    _recv_response,
    _full_anon_login,
    _connect as _raw_connect,
    kXR_ok,
)

# 4 MiB — matches BRIX_READ_MAX (the per-vector element cap).
READ_CHUNK = 4 * 1024 * 1024

# A read the server streams across sendfile boundaries comes back as one or more
# kXR_oksofar segments terminated by a final kXR_ok — the XRootD client library
# hides this; a raw-socket reader must drain the segments itself.
kXR_oksofar = 4000


def _read_whole_file(sock, handle, size):
    """Sequentially read `size` bytes from an open handle in READ_CHUNK reads.
    Drains any kXR_oksofar continuation segments per request.  Returns the byte
    count actually served (asserts every response is ok / oksofar)."""
    off = 0
    while off < size:
        want = min(READ_CHUNK, size - off)
        sock.sendall(make_read_req(handle, off, want))
        got = 0
        while True:
            st, data = _recv_response(sock)
            assert st in (kXR_ok, kXR_oksofar), (
                f"read @ {off}+{got} failed: st={st}")
            got += len(data)
            if st == kXR_ok:
                break
        assert got, f"empty read @ {off} (want {want})"
        off += got
    return off


def _connect_login_plain(host, port):
    """Cleartext root:// connect + anonymous login; returns a logged-in socket."""
    s = _raw_connect(host, port)
    hs, pr, lg = _full_anon_login(s)
    assert hs == kXR_ok and pr == kXR_ok and lg == kXR_ok, (hs, pr, lg)
    return s


def _connect_login_tls(host, port):
    """Genuine in-protocol roots:// upgrade + anonymous login inside the tunnel.

    The initial handshake and the kXR_protocol that advertises kXR_ableTLS happen
    in cleartext; the brix_tls server then switches to a server-side TLS
    handshake, which we complete client-side (verify off — the perf leg measures
    the data path, not the PKI) before finishing kXR_login in the tunnel.  This
    is the same sequence a stock `roots://` client performs (see
    test_min_sec_level._login_tls), so brix sees `c->ssl` set exactly as it would
    for a real TLS client — the read path under test is the TLS memory path.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(15)
    raw.connect((host, port))
    # 20-byte initial handshake + 16-byte server reply.
    raw.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    raw.recv(16)
    # kXR_protocol advertising kXR_ableTLS (the byte the server keys the switch
    # on); reply consumed — the server now expects a TLS ClientHello.
    raw.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520,
                            0x02, 0x03, 0))
    hdr = raw.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        raw.recv(dlen)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=host)
    # Anonymous kXR_login inside the tunnel.
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    lhdr = s.recv(8)
    ldlen = struct.unpack(">I", lhdr[4:8])[0]
    if ldlen:
        s.recv(ldlen)
    return s


def measure_read_throughput(host, port, path, size, runs=3, warmup=1,
                            tls=False):
    """Log in anonymously, open `path`, and time `runs` full sequential reads.

    `path` is the wire path as bytes (e.g. b"/big.bin").  `tls=True` drives the
    genuine roots:// (userspace-TLS) read path instead of cleartext — the P5 leg,
    where an offload-capable NIC on a perf host makes the kTLS A/B measurable
    with no other change.  Returns a dict:
        {"best_mib_s": float, "samples_mib_s": [float, ...], "bytes": int}
    where `best_mib_s` is the max over `samples` (i.e. the minimum-time run).
    A single connection is reused for warm-up + all timed runs so the login cost
    is never inside a timed sample.
    """
    s = _connect_login_tls(host, port) if tls else _connect_login_plain(host,
                                                                         port)
    try:
        s.sendall(make_open_req(path))
        st, body = _recv_response(s)
        assert st == kXR_ok, f"open({path!r}) failed: st={st}"
        handle = body[:4]

        for _ in range(max(0, warmup)):
            got = _read_whole_file(s, handle, size)
            assert got == size, f"warmup short read: {got} != {size}"

        samples = []
        served = 0
        for _ in range(max(1, runs)):
            t0 = time.perf_counter()
            served = _read_whole_file(s, handle, size)
            dt = time.perf_counter() - t0
            assert served == size, f"short read: {served} != {size}"
            samples.append((size / (1024 * 1024)) / dt if dt > 0 else 0.0)

        s.sendall(make_close_req(handle))
        _recv_response(s)
        return {
            "best_mib_s": max(samples),
            "samples_mib_s": samples,
            "bytes": served,
        }
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# Standalone CLI — point the A/B measurer at a REMOTE brix server on a perf host.
#
# The in-repo pytest gate (test_perf_ab_gate.py) boots a local single-process
# nginx, which is only meaningful for loopback correctness.  The real B3/P5
# magnitude needs the client half aimed across a high-BDP link (or over a
# TLS-offload NIC) at an already-running brix server — that host acquisition is
# the sole remaining P0 blocker.  This entrypoint IS that client half: no boot,
# no privilege, just measure against `--host/--port`.  On a perf host, run it
# twice (server with the knob off, then on) and compare best_mib_s.
# --------------------------------------------------------------------------- #

def _main(argv=None):
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/big.bin",
                    help="wire path of a file the server already serves")
    ap.add_argument("--size-mib", type=int, required=True,
                    help="exact byte size of --path, in MiB")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--tls", action="store_true",
                    help="drive the roots:// (userspace-TLS) path — the P5 leg")
    ap.add_argument("--json", help="write the result dict to this path")
    args = ap.parse_args(argv)

    res = measure_read_throughput(
        args.host, args.port, args.path.encode(),
        args.size_mib * 1024 * 1024, runs=args.runs, warmup=args.warmup,
        tls=args.tls)
    plane = "roots://(TLS)" if args.tls else "root://"
    print(f"{plane} {args.host}:{args.port}{args.path}  "
          f"{args.size_mib} MiB  best={res['best_mib_s']:.1f} MiB/s  "
          f"samples={[round(x, 1) for x in res['samples_mib_s']]}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"host": args.host, "port": args.port, "tls": args.tls,
                       **res}, fh, indent=2)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
