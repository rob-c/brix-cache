from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrddiag_remote_doctor_helpers")

def test_single_endpoint_green(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    assert "[GREEN]" in out, out
    # populated facts: connect phases, family, TCP_INFO, throughput, holders
    assert "connect: tcp" in out and "login+auth" in out, out
    assert "IPv4" in out or "IPv6" in out, out
    assert "rtt=" in out, out
    assert "MB/s" in out, out
    assert "holders=" in out, out
    assert "worst=GREEN" in out, out


def test_single_endpoint_json(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["remote_doctor"]
    assert "endpoints" in doc and "cross_endpoint_analysis" in doc, p.stdout
    ep = doc["endpoints"][0]
    assert ep["status"] == "GREEN" and ep["connected"] is True, ep
    f = ep["facts"]
    for k in ("family", "tcp_ms", "tls_ms", "auth_ms", "rtt_us", "mbps", "holders"):
        assert k in f, f
    assert f["holders"] >= 1, f


# --------------------------------------------------------------------------
# (2) multi-endpoint — both hops present + cross-endpoint analysis;
#     a contrived v4-vs-v6 pair fires the asymmetry detector
# --------------------------------------------------------------------------

def test_multi_endpoint_path(anon):
    port = anon["port"]
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:{port}//small.txt",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["remote_doctor"]
    assert len(doc["endpoints"]) == 2, doc
    assert doc["cross_endpoint_analysis"]["hops"] == 1, doc
    # a tiny second file must NOT false-positive the cwnd/low-throughput detector
    assert all(e["status"] in ("GREEN", "YELLOW") for e in doc["endpoints"]), doc


def test_v4_v6_asymmetry_detector(anon):
    if not anon["v6"]:
        pytest.skip("no IPv6 loopback on this host")
    port = anon["port"]
    if not _port_up(HOST6, port, family=socket.AF_INET6):
        pytest.skip("server not reachable over ::1")  # net-literal-allow: IPv6 loopback reachability skip message
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{url_host(HOST6)}:{port}//big.bin",
             "--metrics-port", "0", "--probe-timeout", "8000")
    # both hops connect; the family differs → the asymmetry detector must fire
    assert "address-family asymmetry" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# (3) adversarial / error — reachable + unreachable → dead hop red, no hang
# --------------------------------------------------------------------------

def test_dead_hop_red_no_hang(anon):
    port = anon["port"]
    started = time.monotonic()
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:1",            # nothing listens on port 1
             "--metrics-port", "0", "--probe-timeout", "2000", timeout=30)
    elapsed = time.monotonic() - started
    assert p.returncode != 0, f"expected nonzero on a dead hop:\n{p.stdout}"
    assert "[RED]" in p.stdout, p.stdout
    assert "connect failed" in p.stdout, p.stdout
    # bounded: the per-endpoint timeout means it can never hang the suite
    assert elapsed < 25, f"remote-doctor took too long ({elapsed:.1f}s) — not bounded"


def test_unparseable_url_clean(anon):
    p = _run("remote-doctor", "::::not-a-url::::",
             "--metrics-port", "0", "--probe-timeout", "2000")
    assert p.returncode != 0, p.stdout
    assert "[RED]" in p.stdout or "unparseable" in (p.stdout + p.stderr), \
        f"{p.stdout}\n{p.stderr}"


# --------------------------------------------------------------------------
# security-neg / PII — facts/JSON leak no path, token, or cert subject
# --------------------------------------------------------------------------

def test_remote_doctor_pii_free(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, p.stderr
    blob = p.stdout
    # the probed file path must never appear; nor any credential material.
    for leak in ("big.bin", "BEARER", "x509", "/etc/", "PRIVATE", "subject="):
        assert leak not in blob, f"PII/secret leaked: {leak} in {blob}"
    # facts carry only families / counts / hex caps (no dotted-quad beyond the
    # host the user supplied, which is the endpoint identity, not a resolved IP).
    doc = json.loads(blob)["remote_doctor"]
    f = doc["endpoints"][0]["facts"]
    assert f["family"] in ("IPv4", "IPv6", "none"), f
    assert isinstance(f["caps"], str) and f["caps"].startswith("0x"), f


# ==========================================================================
# active diagnosis — exercise subsystems, classify symptom → root cause
# ==========================================================================


def test_diagnosis_present_readonly_default(anon):
    """Read-only probes always run (no --allow-write): auth/namespace/read/
    checksum/locate present and green on a healthy server; no write probe."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    dx = _diagnosis(p.stdout)
    for probe in ("auth", "namespace", "read", "locate"):
        assert probe in dx and dx[probe]["verdict"] == "ok", dx
    # no mutation probe unless --allow-write
    assert "write" not in dx, dx


def test_diagnosis_write_path_healthy(rw_server):
    """On a writable export, --allow-write runs the write probe and it verifies."""
    port = rw_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//f.bin",
             "--allow-write", "--i-am-authorized", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    dx = _diagnosis(p.stdout)
    assert dx.get("write", {}).get("verdict") == "ok", dx
    # write probe must clean up after itself — no test artifact left behind
    leftovers = [n for n in os.listdir(rw_server["data"]) if "xrddiag" in n]
    assert leftovers == [], f"write probe left artifacts: {leftovers}"


def test_diagnosis_readonly_export_classified(anon):
    """The headline case: a read-only export's write probe pins the root cause to
    'read-only' with a remediation, escalates to RED, and exits nonzero."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--allow-write", "--i-am-authorized", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode != 0, p.stdout
    assert "[RED]" in p.stdout, p.stdout
    assert "FAIL" in p.stdout and "write" in p.stdout, p.stdout
    assert "read-only" in p.stdout.lower(), p.stdout
    assert "allow_write" in p.stdout, "remediation missing: " + p.stdout


def test_diagnosis_empty_export_warns(empty_server):
    """An empty export root is a real misconfiguration the namespace probe flags."""
    port = empty_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    # exits 0 (warn, not fail) but the namespace finding must warn 'empty'
    dx = _diagnosis(p.stdout)
    assert dx.get("namespace", {}).get("verdict") == "warn", dx
    assert "empty" in dx["namespace"]["cause"].lower(), dx["namespace"]


def test_diagnosis_dead_hop_classifies_reachability(anon):
    """An unreachable hop yields a reachability finding with a concrete cause."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:1", "--json", "--metrics-port", "0",
             "--probe-timeout", "2000")
    assert p.returncode != 0, p.stdout
    doc = json.loads(p.stdout)["remote_doctor"]
    dead = doc["endpoints"][1]
    assert dead["status"] == "RED", dead
    rch = [d for d in dead["diagnosis"] if d["probe"] == "reachability"]
    assert rch and rch[0]["verdict"] == "fail" and rch[0]["remedy"], dead


def test_diagnosis_pii_free(anon):
    """The diagnosis cause/remedy strings must carry no path, token, or secret."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--allow-write", "--i-am-authorized", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    doc = json.loads(p.stdout)["remote_doctor"]
    for d in doc["endpoints"][0]["diagnosis"]:
        joined = d["cause"] + " " + d["remedy"]
        for leak in ("big.bin", "/tmp/", "BEARER", "PRIVATE", "xrddiag-dx",
                     "subject="):
            assert leak not in joined, f"PII/secret in diagnosis: {leak} in {d}"


# ==========================================================================
# deep-recon (--deep-recon) — read-only reconnaissance panel
# ==========================================================================
#
# --deep-recon interrogates a live endpoint's control plane: it parses `query
# stats a` into a per-plane panel (link traffic, op counts, logins, tpc, oss
# capacity/inodes, http), sweeps the Qconfig keyspace counting supported keys,
# decodes the kXR_protocol capability bits, and lists the authorized roots. It is
# strictly read-only and PII-free — counts / capacities / cap-names only, never a
# path body or credential. Off unless --deep-recon is passed.


def test_deep_recon_off_by_default(anon):
    """No recon panel unless --deep-recon is passed."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    ep = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]
    assert "recon" not in ep, ep


def test_deep_recon_text_panel(anon):
    """--deep-recon emits the panel: qconfig key tally, caps, and at least one
    populated plane (a live anon server always reports link + oss)."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--deep-recon", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    assert "recon: qconfig" in out and "keys answered" in out, out
    # a live server answers a nonzero fraction of the swept keyspace
    m = re.search(r"recon: qconfig (\d+)/(\d+) keys answered", out)
    assert m and int(m.group(1)) >= 1 and int(m.group(2)) >= int(m.group(1)), out
    # capability decode present (our server advertises at least server/data role)
    assert "recon caps:" in out, out


def test_deep_recon_json_shape(anon):
    """--deep-recon --json attaches a well-formed recon object: sentinel-aware
    numeric planes, a caps string, and the roots array."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--deep-recon", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    ep = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]
    assert "recon" in ep, ep
    rec = ep["recon"]
    for k in ("caps", "cid", "cms", "cfg_probed", "cfg_supported",
              "conns_total", "ops", "logins", "tpc", "oss", "http",
              "roots", "roots_more"):
        assert k in rec, rec
    def _assert_test_deep_recon_json_shape_1():
        assert rec["cfg_probed"] >= 1 and rec["cfg_supported"] >= 1, rec
        assert isinstance(rec["roots"], list) and isinstance(rec["roots_more"], bool), rec

    _assert_test_deep_recon_json_shape_1()
    # nested planes carry the -1 sentinel or a real >=0 count, never garbage
    for plane in ("ops", "oss", "http"):
        for v in rec[plane].values():
            assert isinstance(v, int) and v >= -1, (plane, rec[plane])


def test_deep_recon_pii_free(anon):
    """The recon panel must carry no path body, token, or secret — only names,
    counts and capacities. The one namespace surface (roots) is a bare basename
    list, which must never expose the export's absolute path or the probe file."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--deep-recon", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    rec = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]["recon"]
    blob = json.dumps(rec)
    for leak in ("/tmp/", "BEARER", "PRIVATE", "subject=", "xrddiag-dx"):
        assert leak not in blob, f"PII/secret in recon panel: {leak} in {rec}"
    # roots are basenames only: no slash inside an entry, no absolute path
    for root in rec["roots"]:
        assert "/" not in root, f"root leaked a path component: {root!r}"


# ==========================================================================
# auth/permissions suite (--auth-suite) — differential authorization testing
# ==========================================================================
#
# The headline: catch a server build whose authentication/authorization is broken
# (accepts credentials it must reject, or grants access it must deny). Each probe
# asserts a CORRECT server's behavior; on a broken server the verdict flips to FAIL.
# Self-hosting: SSS server (xrdsssadmin keytab) for the anon-enforcement case; a
# token server (utils.make_token RSA issuer + JWKS) for the forged/expired/scope cases.

def test_authsuite_off_by_default(anon):
    """No authz-* findings unless --auth-suite is passed."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert not any(k.startswith("authz") for k in dx), dx


def test_authsuite_anon_by_design(anon):
    """An anon export reports 'anonymous by design', not a bypass."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--auth-suite", "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-anon"]["verdict"] == "ok", dx
    assert "design" in dx["authz-anon"]["cause"].lower(), dx


def test_authsuite_anon_bypass_denied(sss_server):
    """Headline: on an auth-required (SSS) server the suite confirms anonymous
    access is DENIED — even though the client holds no credential. A served op
    here would be the auth-bypass FAIL."""
    port = sss_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env.pop("XrdSecSSSKT", None)
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-anon"]["verdict"] == "ok", dx
    assert "denied" in dx["authz-anon"]["cause"].lower(), dx


def test_authsuite_forged_token_rejected(token_server):
    """Headline: a garbage-signature token and an alg:none token MUST be rejected.
    Acceptance would be the broken-signature-verification FAIL."""
    port = token_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.txt",
             "--auth-suite", "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-forgesig"]["verdict"] == "ok", dx
    assert dx["authz-algnone"]["verdict"] == "ok", dx
    assert "rejected" in dx["authz-forgesig"]["cause"].lower(), dx


def test_authsuite_expired_token_rejected(token_server):
    """An expired bearer token in the environment must be rejected by the server."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate_expired()
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-expired"]["verdict"] == "ok", dx
    assert "expired" in dx["authz-expired"]["cause"].lower(), dx


def test_authsuite_scope_enforced(token_server):
    """A read-only token must be DENIED a write (scope enforcement). A successful
    write would be the privilege-escalation FAIL."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate(scope="storage.read:/")
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--allow-write", "--i-am-authorized", "--json",
                        "--metrics-port", "0", "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-scope"]["verdict"] == "ok", dx
    assert "denied" in dx["authz-scope"]["cause"].lower(), dx
