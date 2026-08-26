#!/usr/bin/env python3
"""xrd_sec_probe continuation shard: concurrency probes (CC-01/CC-02),
exec'd into xrd_sec_probe.py's namespace (see the loader there) so the @probe
decorators register and the module helpers are in scope. Split for the cap."""

@probe("CC-01  16 threads × 50 pings simultaneously")
def _():
    errors = []
    threads = [threading.Thread(target=_ping_worker, args=(errors, i)) for i in range(16)]
    _run_threads(threads)
    if errors:
        return ("FINDING", "Concurrent ping errors: " + "; ".join(errors[:3]),
                "16 simultaneous connections each sending 50 pings")


def _ping_worker(errors, index):
    try:
        connection = connect()
        do_login(connection)
        for sequence in range(50):
            stream = (index * 50 + sequence) % 0xFFFE + 1
            connection.sendall(ping_req(struct.pack(">H", stream)))
        accepted = _count_ok_responses(connection, 50)
        safe_close(connection)
        if accepted < 50:
            errors.append(f"thread {index}: {accepted}/50 pings ok")
    except Exception as error:
        errors.append(f"thread {index}: {error}")


def _run_threads(threads):
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

@probe("CC-02  8 ping threads + 8 stat threads concurrently")
def _():
    errors = []
    threads = _mixed_threads(errors)
    _run_threads(threads)
    if errors:
        return ("FINDING", "; ".join(errors[:4]),
                "8 ping threads + 8 stat threads simultaneously")


def _mixed_threads(errors):
    return (
        [threading.Thread(target=_request_worker, args=(errors, "ping")) for _ in range(8)]
        + [threading.Thread(target=_request_worker, args=(errors, "stat")) for _ in range(8)]
    )


def _request_worker(errors, kind):
    try:
        connection = connect()
        do_login(connection)
        _send_request_series(connection, errors, kind)
        safe_close(connection)
    except Exception as error:
        errors.append(f"{kind}: {error}")


def _send_request_series(connection, errors, kind):
    for index in range(20):
        stream = struct.pack(">H", index + 1)
        request = ping_req(stream) if kind == "ping" else stat_req(b'/test.bin', sid=stream)
        connection.sendall(request)
        status, _ = recv_resp(connection)
        if status != kXR_ok:
            errors.append(f"{kind} {index}→{status}")

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

