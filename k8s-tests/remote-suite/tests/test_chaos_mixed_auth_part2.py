"""Mixed-auth route assertions and chaos driver continuation."""


def test_x509_upstream_route(mesh):
    result = _cat(mesh["cache_gsi"].port)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == mesh["payload_gsi"], result.stdout


def test_sss_upstream_route(mesh):
    result = _cat(mesh["proxy_sss"].port)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == mesh["payload_sss"], result.stdout


def test_both_routes_stat(mesh):
    for instance in (mesh["cache_gsi"], mesh["proxy_sss"]):
        result = _stat(instance.port)
        assert result.returncode == 0 and "Size:" in result.stdout, (
            f"{instance.name}: {result.stderr}")


def test_sss_wrong_upstream_key_rejected(mesh):
    result = _cat(mesh["proxy_bad"].port, timeout=30)
    assert result.returncode != 0, "wrong-keytab proxy must NOT serve data"
    ok, reason = _no_crash(mesh["proxy_bad"])
    assert ok, reason
    ok, reason = _no_crash(mesh["sss_origin"])
    assert ok, reason


def test_chaos_concurrent_mixed_auth_with_restarts(mesh):
    rng = random.Random(0xC4A05)
    fronts = [("x509", mesh["cache_gsi"].port, mesh["payload_gsi"]),
              ("sss", mesh["proxy_sss"].port, mesh["payload_sss"])]
    backends = [mesh["gsi_origin"], mesh["sss_origin"]]
    stop = threading.Event()
    results = []
    results_lock = threading.Lock()
    _run_chaos_threads(rng, stop, fronts, backends, results, results_lock)
    _restore_backends(backends)
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


def _chaos_agent(rng, stop, backends):
    for _ in range(4):
        if stop.is_set():
            break
        time.sleep(0.4)
        backend = backends[rng.randrange(len(backends))]
        _stop_nginx(backend.conf)
        time.sleep(rng.uniform(0.1, 0.3))
        _start_nginx(backend.conf)
        _wait_port(backend.port)


def _run_chaos_threads(rng, stop, fronts, backends, results, lock):
    workers = [threading.Thread(target=_chaos_worker,
                                args=(index, stop, fronts, results, lock))
               for index in range(12)]
    agent = threading.Thread(target=_chaos_agent, args=(rng, stop, backends))
    for thread in workers:
        thread.start()
    agent.start()
    for thread in workers:
        thread.join(timeout=120)
    stop.set()
    agent.join(timeout=30)


def _restore_backends(backends):
    for backend in backends:
        if not _wait_port(backend.port, tries=20):
            _start_nginx(backend.conf)
            _wait_port(backend.port)


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
