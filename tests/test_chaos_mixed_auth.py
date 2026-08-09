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

    def worker(wid):
        wrng = random.Random(wid * 7919 + 1)
        for _ in range(8):
            if stop.is_set():
                break
            route, port, payload = fronts[wrng.randrange(len(fronts))]
            try:
                r = _cat(port, timeout=40)
                ok = (r.returncode == 0 and r.stdout == payload)
                # a non-zero rc is acceptable (backend may be mid-restart) as
                # long as the process returned cleanly rather than hanging.
                clean = ok or (r.returncode != 0)
            except subprocess.TimeoutExpired:
                ok, clean = False, False
            with results_lock:
                results.append((route, ok, clean))
            time.sleep(wrng.uniform(0.0, 0.05))

    def chaos_agent():
        # Restart each backend a few times while the workers run.
        for _ in range(4):
            if stop.is_set():
                break
            time.sleep(0.4)
            b = backends[rng.randrange(len(backends))]
            harness.stop(b.regname)
            time.sleep(rng.uniform(0.1, 0.3))
            harness.start_registered(b.regname)   # re-renders, launches, waits ready

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    agent = threading.Thread(target=chaos_agent)
    for t in workers:
        t.start()
    agent.start()
    for t in workers:
        t.join(timeout=120)
    stop.set()
    agent.join(timeout=30)

    # Make sure the backends are up for the final assertions.
    for b in backends:
        if not _wait_port(b.port, tries=20):
            harness.start_registered(b.regname)   # re-renders, launches, waits ready

    # 1) Nothing crashed — every instance's master is alive, no fatal signals.
    for inst in mesh["insts"].values():
        ok, why = _no_crash(inst)
        assert ok, why

    # 2) Every request returned cleanly (no hangs/timeouts).
    assert results, "no chaos results recorded"
    clean = sum(1 for _, _, c in results if c)
    assert clean == len(results), \
        f"{len(results) - clean}/{len(results)} requests hung/timed out"

    # 3) Recovery: after the dust settles, both routes serve correctly again.
    rg = _cat(mesh["cache_gsi"].port, timeout=40)
    assert rg.returncode == 0 and rg.stdout == mesh["payload_gsi"], \
        f"x509 route did not recover: {rg.stderr}"
    rs = _cat(mesh["proxy_sss"].port, timeout=40)
    assert rs.returncode == 0 and rs.stdout == mesh["payload_sss"], \
        f"sss route did not recover: {rs.stderr}"

    # 4) At least some requests succeeded during the storm (sanity).
    succeeded = sum(1 for _, ok, _ in results if ok)
    assert succeeded > 0, "no request succeeded during the chaos window"
