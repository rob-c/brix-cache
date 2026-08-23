from split_continuation import reexport as _reexport
_reexport(globals(), "_test_chaos_mixed_auth_helpers")

def test_x509_upstream_route(mesh):
    """anon -> cache-gsi -(X.509 VOMS proxy)-> gsi-origin serves byte-exact."""
    r = _cat(mesh["cache_gsi"].port)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert r.stdout == mesh["payload_gsi"], r.stdout


def test_sss_upstream_route(mesh):
    """anon -> proxy-sss -(SSS keytab)-> sss-origin serves byte-exact."""
    r = _cat(mesh["proxy_sss"].port)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert r.stdout == mesh["payload_sss"], r.stdout


def test_both_routes_stat(mesh):
    for inst in (mesh["cache_gsi"], mesh["proxy_sss"]):
        r = _stat(inst.port)
        assert r.returncode == 0 and "Size:" in r.stdout, \
            f"{inst.name}: {r.stderr}"


# ---------------------------------------------------------------------------
# negative — wrong SSS upstream key is cleanly rejected, never crashes
# ---------------------------------------------------------------------------

def test_sss_wrong_upstream_key_rejected(mesh):
    r = _cat(mesh["proxy_bad"].port, timeout=30)
    assert r.returncode != 0, "wrong-keytab proxy must NOT serve data"
    ok, why = _no_crash(mesh["proxy_bad"])
    assert ok, why
    ok, why = _no_crash(mesh["sss_origin"])
    assert ok, why


# ---------------------------------------------------------------------------
# chaos — concurrent mixed load while backends restart underneath
# ---------------------------------------------------------------------------

def test_chaos_concurrent_mixed_auth_with_restarts(mesh):
    rng = random.Random(0xC4A05)
    harness = mesh["harness"]
    fronts = [("x509", mesh["cache_gsi"].port, mesh["payload_gsi"]),
              ("sss", mesh["proxy_sss"].port, mesh["payload_sss"])]
    backends = [mesh["gsi_origin"], mesh["sss_origin"]]

    stop = threading.Event()
    results = []          # (route, ok, clean_error)
    results_lock = threading.Lock()

    _run_chaos_threads(rng, stop, fronts, backends, harness, results, results_lock)
    _restore_backends(backends, harness)
    _assert_no_crashes(mesh["insts"].values())
    _assert_clean_results(results)
    _assert_recovered(mesh)
    assert any(ok for _, ok, _ in results), "no request succeeded during the chaos window"


def _chaos_worker(worker_id, stop, fronts, results, results_lock):
    rng = random.Random(worker_id * 7919 + 1)
    for _ in range(8):
        if stop.is_set():
            break
        route, port, payload = fronts[rng.randrange(len(fronts))]
        outcome = _chaos_request(port, payload)
        with results_lock:
            results.append((route, *outcome))
        time.sleep(rng.uniform(0.0, 0.05))


def _chaos_request(port, payload):
    try:
        result = _cat(port, timeout=40)
        ok = result.returncode == 0 and result.stdout == payload
        return ok, ok or result.returncode != 0
    except subprocess.TimeoutExpired:
        return False, False


def _chaos_agent(rng, stop, backends, harness):
    for _ in range(4):
        if stop.is_set():
            break
        time.sleep(0.4)
        backend = backends[rng.randrange(len(backends))]
        harness.stop(backend.regname)
        time.sleep(rng.uniform(0.1, 0.3))
        harness.start_registered(backend.regname)


def _run_chaos_threads(rng, stop, fronts, backends, harness, results, lock):
    workers = [threading.Thread(target=_chaos_worker,
                                args=(index, stop, fronts, results, lock))
               for index in range(12)]
    agent = threading.Thread(target=_chaos_agent,
                             args=(rng, stop, backends, harness))
    for thread in workers:
        thread.start()
    agent.start()
    for thread in workers:
        thread.join(timeout=120)
    stop.set()
    agent.join(timeout=30)


def _restore_backends(backends, harness):
    for backend in backends:
        if not _wait_port(backend.port, tries=20):
            harness.start_registered(backend.regname)


def _assert_no_crashes(instances):
    for instance in instances:
        ok, reason = _no_crash(instance)
        assert ok, reason


def _assert_clean_results(results):
    assert results, "no chaos results recorded"
    clean = sum(1 for _, _, returned in results if returned)
    assert clean == len(results), (
        f"{len(results) - clean}/{len(results)} requests hung/timed out")


def _assert_recovered(mesh):
    x509 = _cat(mesh["cache_gsi"].port, timeout=40)
    assert x509.returncode == 0 and x509.stdout == mesh["payload_gsi"], (
        f"x509 route did not recover: {x509.stderr}")
    sss = _cat(mesh["proxy_sss"].port, timeout=40)
    assert sss.returncode == 0 and sss.stdout == mesh["payload_sss"], (
        f"sss route did not recover: {sss.stderr}")
