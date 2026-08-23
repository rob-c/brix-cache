def _recv_http_headers(sock):
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buffer += chunk
    return buffer.split(b"\r\n\r\n", 1)


def _content_length(header):
    for line in header.split(b"\r\n")[1:]:
        if line[:15].lower() == b"content-length:":
            return int(line.split(b":", 1)[1].strip())
    return None


def _recv_http_body(sock, body, content_length):
    while len(body) < content_length:
        chunk = sock.recv(content_length - len(body))
        if not chunk:
            return False
        body += chunk
    return True


def _op_propfind_ka(s, path="/dir"):
    """Keep-alive PROPFIND: reuse a persistent connection, framing the response
    by Content-Length so the socket can serve the next request.  This removes
    the per-request TCP connect/teardown that otherwise caps HTTP throughput far
    below the rate limiter — real WebDAV clients reuse connections the same way.
    Returns the status code, or None to make the hammer re-establish the conn."""
    s.sendall((f"PROPFIND {path} HTTP/1.1\r\nHost: x\r\nDepth: 0\r\n"
               "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n").encode())
    response = _recv_http_headers(s)
    if response is None:
        return None
    head, rest = response
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    content_length = _content_length(head)
    if content_length is None:
        return None          # chunked / close-delimited — can't safely reuse
    if not _recv_http_body(s, rest, content_length):
        return None
    return status


# --------------------------------------------------------------------------- #
# Rate-paced hammer                                                            #
# --------------------------------------------------------------------------- #

def _classify_stream(st):
    if st in (kXR_ok, kXR_redirect):
        return "served"
    if st == kXR_wait:
        return "throttled"
    return "errored"          # None (dropped), 4003, or anything unexpected


def _classify_http(st):
    if st in (200, 206, 207):
        return "served"
    if st == 429:
        return "throttled"
    if st is not None and 400 <= st < 500:
        return "served"       # well-formed client-side answer (e.g. 405) — not a fall-over
    return "errored"          # None (dropped) or 5xx


def _session_or_none(make_session):
    try:
        return make_session()
    except Exception:
        return None


def _close_session_quietly(close_session, session):
    if close_session is None or session is None:
        return
    try:
        close_session(session)
    except Exception:
        pass


def _scheduled_tick(start, deadline, step, workers, worker_id, iteration):
    target = start + (worker_id + iteration * workers) * step
    now = time.perf_counter()
    if now >= deadline or target >= deadline:
        return False
    if target > now:
        time.sleep(target - now)
    return True


def _timed_operation(do_op, session):
    started = time.perf_counter()
    try:
        status = do_op(session)
    except Exception:
        status = None
    return status, time.perf_counter() - started


def _empty_hammer_result():
    return {"dispatched": 0, "served": 0, "throttled": 0, "errored": 0,
            "lat": []}


def _record_hammer_outcome(result, kind, elapsed):
    result["dispatched"] += 1
    if kind == "served":
        result["served"] += 1
        result["lat"].append(elapsed)
        return False
    if kind == "throttled":
        result["throttled"] += 1
        return False
    result["errored"] += 1
    return True


def _hammer_worker(context, worker_id):
    session = _session_or_none(context["make_session"])
    result = _empty_hammer_result()
    iteration = 0
    while _scheduled_tick(
        context["start"], context["deadline"], context["step"],
        context["workers"], worker_id, iteration,
    ):
        iteration += 1
        session = session or _session_or_none(context["make_session"])
        if session is None:
            _record_hammer_outcome(result, "errored", 0.0)
            continue
        status, elapsed = _timed_operation(context["do_op"], session)
        kind = context["classify"](status)
        if _record_hammer_outcome(result, kind, elapsed):
            _close_session_quietly(context["close_session"], session)
            session = None
    _close_session_quietly(context["close_session"], session)
    context["results"][worker_id] = result


def _run_hammer_workers(context):
    threads = [
        threading.Thread(target=_hammer_worker, args=(context, worker_id))
        for worker_id in range(context["workers"])
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _merge_hammer_results(results):
    merged = _empty_hammer_result()
    for result in results:
        if result is None:
            continue
        for key in ("dispatched", "served", "throttled", "errored"):
            merged[key] += result[key]
        merged["lat"].extend(result["lat"])
    return merged


def _paced_hammer(make_session, do_op, classify, close_session=None,
                  rate=RATE, secs=SECS, workers=WORKERS):
    """Dispatch do_op(session) at ~`rate` ops/sec (aggregate) for `secs`, spread
    over `workers` threads each owning a persistent session.

    Each worker runs its OWN interleaved schedule (worker w fires global ticks
    w, w+workers, w+2·workers, … at start + idx/rate) and accumulates into LOCAL
    counters, merged only at join.  There is no shared counter or per-op lock in
    the hot path — that is what lets the harness offer multi-thousand req/s
    without the GIL serialising every dispatch.  A worker that falls behind its
    schedule stops sleeping and fires back-to-back, so the offered rate tracks
    the server's ceiling when the server (not the schedule) is the limit.

    A session that errors is transparently re-created so one dead socket doesn't
    snowball.  Returns {dispatched, served, throttled, errored, lat:[...]}."""
    start = time.perf_counter()
    context = {
        "make_session": make_session,
        "do_op": do_op,
        "classify": classify,
        "close_session": close_session,
        "start": start,
        "deadline": start + secs,
        "step": 1.0 / rate,
        "workers": workers,
        "results": [None] * workers,
    }
    _run_hammer_workers(context)
    return _merge_hammer_results(context["results"])


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p))]


def _report(label, res):
    lat = res["lat"]
    print(f"\n[{label}] dispatched={res['dispatched']} served={res['served']} "
          f"throttled={res['throttled']} errored={res['errored']} "
          f"p50={_pct(lat,0.5)*1000:.1f}ms p95={_pct(lat,0.95)*1000:.1f}ms "
          f"p99={_pct(lat,0.99)*1000:.1f}ms", flush=True)


def _assert_no_fallover(res, label, min_dispatch_frac=0.5):
    # We actually applied meaningful load.
    assert res["dispatched"] >= RATE * SECS * min_dispatch_frac, \
        f"{label}: only dispatched {res['dispatched']} ops (hammer stalled?)"
    # Errors (dropped connections / 5xx / malformed) are the fall-over signal.
    # Tolerate a tiny number of transient socket races, not a collapse.
    tol = max(3, int(res["dispatched"] * 0.01))
    assert res["errored"] <= tol, \
        f"{label}: {res['errored']} errored responses (>{tol}) — server fell over"
    # Something must have been answered.
    assert res["served"] + res["throttled"] > 0, f"{label}: nothing answered"


def _server_healthy_stream(port):
    try:
        s = _xrd_login(HOST, port, timeout=4)
        st = _op_stat(s, "/test.txt")
        s.close()
        return st == kXR_ok
    except OSError:
        return False


# =========================================================================== #
# STANDALONE                                                                   #
# =========================================================================== #

