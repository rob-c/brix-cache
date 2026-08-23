# --- matrix (port of tests/cvmfs/run_matrix.sh) ------------------------------


def _module_conf_body(listen_port: int, location: str, directives: str, work: Path) -> str:
    return f"""daemon on; error_log {work}/e.log warn; pid {work}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 512; }}
http {{ access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {{
    listen {BIND_HOST}:{listen_port} so_keepalive=60s:10s:6 backlog=2048;
    location {location} {{
{directives}
    }}
}} }}
"""


def _stop_pidfile(pidfile: Path) -> None:
    try:
        os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        pass


def matrix(nginx: Path | None = None) -> int:
    """The phase-68 comparison matrix: each cache implementation x each netem
    profile gets a fresh lab, a mock origin inside the impaired ns, one harness
    run, one JSON. Renders RESULTS.md rows at the end. Requires root (netem);
    squid/varnish cells are skipped when not installed."""
    _require_root_netem()
    out_dir = Path(os.environ.get("CVMFS_MATRIX_OUT", BASELINES_DIR))
    out_dir.mkdir(parents=True, exist_ok=True)
    rows_path = out_dir / "matrix_rows.tsv"
    rows_path.write_text("")
    with LiveRun("cvmfs_matrix", nginx) as run:
        if not run.nginx.exists():
            raise LiveSkip(f"nginx binary not found: {run.nginx}")
        mock_port, cache_port, proxy_port = _PORTS[3:6]  # was free_ports(3)
        netns = ["ip", "netns", "exec", NS]
        try:
            for cache in MATRIX_CACHES:
                for profile in MATRIX_PROFILES:
                    lab_down()
                    lab_up()
                    lab_profile(profile)
                    mock = _start_mock(run, netns, NS_IP, mock_port)
                    work = run.mkdir(f"w_{cache}_{profile}")
                    result_json = _matrix_cell(run, cache, profile, work, out_dir, mock_port, cache_port, proxy_port)
                    if result_json:
                        with rows_path.open("a") as rows:
                            rows.write(f"{cache}\t{profile}\t{result_json}\n")
                    mock.terminate()
        finally:
            lab_down()
        appended = _render_results(out_dir)
        print(f"appended {appended} rows to RESULTS.md")
        return 0 if appended else 1


def _module_reverse_runtime(run, work, origin, cache_port):
    config = run.write(work / "nginx.conf", _module_conf_body(cache_port, "/cvmfs/", f"""        brix_storage_backend http://{origin};
        brix_cache_store posix:{work}/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;""", work))
    (work / "cache").mkdir(exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    run.call([run.nginx, "-c", config, "-p", work])
    return f"http://{HOST}:{cache_port}", {}


def _module_proxy_runtime(run, work, origin, proxy_port):
    config = run.write(work / "nginx.conf", _module_conf_body(proxy_port, "/", f"""        brix_cache_store posix:{work}/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;
        brix_cvmfs_upstream_allow {NS_IP};""", work))
    (work / "cache").mkdir(exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    run.call([run.nginx, "-c", config, "-p", work])
    return f"http://{origin}", {"http_proxy": f"http://{HOST}:{proxy_port}"}


def _stock_runtime(run, work, origin, mock_port, cache_port, proxy_port):
    template = (REPO_ROOT / "deploy/cvmfs/nginx-proxy-cache.conf").read_text()
    config = run.write(
        work / "nginx.conf",
        template.replace("@PORT@", str(cache_port))
        .replace("@PPORT@", str(proxy_port))
        .replace("@CACHEDIR@", str(work))
        .replace("@ORIGIN@", origin)
        .replace("@ORIGINHOST@", NS_IP)
        .replace("@ORIGINPORT@", str(mock_port)),
    )
    (work / "store").mkdir(exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    run.call([run.nginx, "-c", config, "-p", work])
    return f"http://{HOST}:{cache_port}", {}


def _module_runtime(run, cache, work, origin, mock_port, cache_port, proxy_port):
    if cache == "module-reverse":
        return _module_reverse_runtime(run, work, origin, cache_port)
    if cache == "module-proxy":
        return _module_proxy_runtime(run, work, origin, proxy_port)
    if cache == "stock-nginx":
        return _stock_runtime(run, work, origin, mock_port, cache_port, proxy_port)
    raise LiveFailure(f"unknown cache implementation: {cache}")


def _baseline_matrix_cell(run, cache, profile, out_dir, cache_port, origin):
    ok, message = run_baseline(run, cache, cache_port, origin, out_dir)
    print(f"  {'ok  ' if ok else 'FAIL'} baseline {cache}/{profile}: {message}")
    if ok and not message.startswith("SKIP"):
        return str(out_dir / f"baseline_{cache}.json")
    return ""


def _run_cell_harness(run, cache, profile, out_dir, origin, cache_base,
                      harness_env, pidfile):
    result_json = out_dir / f"results_{cache}_{profile}.json"
    harness = run.call(
        [sys.executable, CVMFS_DIR / "harness.py", "--cache", cache_base,
         "--mock", f"http://{origin}", "--out", result_json],
        env=harness_env, check=False)
    _stop_pidfile(pidfile)
    if harness.returncode != 0:
        print(f"  FAIL harness {cache}/{profile}: "
              f"{(harness.stderr or harness.stdout)[-1000:]}")
        return ""
    return str(result_json)


def _matrix_cell(run: LiveRun, cache: str, profile: str, work: Path, out_dir: Path, mock_port: int, cache_port: int, proxy_port: int) -> str:
    """Run one cache x profile cell; return the result JSON path."""
    origin = f"{NS_IP}:{mock_port}"
    if cache in ("squid", "varnish"):
        return _baseline_matrix_cell(
            run, cache, profile, out_dir, cache_port, origin)
    cache_base, harness_env = _module_runtime(
        run, cache, work, origin, mock_port, cache_port, proxy_port)
    return _run_cell_harness(run, cache, profile, out_dir, origin, cache_base,
                             harness_env, work / "nginx.pid")


def _result_row(out_dir, today, cache, profile, path):
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = out_dir / path
    try:
        data = json.loads(candidate.read_text())
    except (OSError, ValueError):
        return None
    cells = [f"{value:.1f}" if isinstance(value, float) else str(value)
             for key in RESULT_KEYS for value in (data.get(key, ""),)]
    note = f"conn_failures={data.get('conn_failures', '?')}"
    return (f"| {cache} | {profile} | " + " | ".join(cells)
            + f" | {today} | {note} |")


def _render_result_rows(out_dir, today, rows):
    rendered = []
    for args in rows:
        row = _result_row(out_dir, today, *args)
        if row is not None:
            rendered.append(row)
    return rendered


def _append_result_rows(out_dir, lines):
    if not lines:
        return
    with (out_dir / "RESULTS.md").open("a") as results:
        results.write("\n".join(lines) + "\n")


def _render_results(out_dir: Path) -> int:
    rows = [line.split("\t") for line in
            (out_dir / "matrix_rows.tsv").read_text().splitlines() if line]
    today = datetime.date.today().isoformat()
    lines = _render_result_rows(out_dir, today, rows)
    _append_result_rows(out_dir, lines)
    return len(lines)


SCENARIOS = {
    "matrix": matrix,
    "cvmfs-baselines": cvmfs_baselines,
    "spike-cas-hash": spike_cas_hash,
    "netem-lab": netem_lab,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveSkip as exc:
        print(f"SKIP: {exc}")
        return 0
    except LiveFailure as exc:
        print(f"CVMFS matrix scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
