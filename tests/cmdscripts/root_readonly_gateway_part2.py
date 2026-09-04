"""Runtime checks and orchestration for :mod:`root_readonly_gateway`.

This file is executed in its parent's namespace by ``split_continuation``.
"""
# --------------------------------------------------------------------------- #
# checks                                                                       #
# --------------------------------------------------------------------------- #

def _check_table_is_covered(results: list[tuple[bool, str]]) -> None:
    """The probe set must cover every row of the C write-gated route table."""
    probed = {p.opcode for p in probes()} | {kXR_clone}
    names = {
        "kXR_write": kXR_write, "kXR_pgwrite": kXR_pgwrite, "kXR_sync": kXR_sync,
        "kXR_truncate": kXR_truncate, "kXR_mkdir": kXR_mkdir, "kXR_rm": kXR_rm,
        "kXR_writev": kXR_writev, "kXR_rmdir": kXR_rmdir, "kXR_mv": kXR_mv,
        "kXR_chmod": kXR_chmod, "kXR_chkpoint": kXR_chkpoint,
        "kXR_setattr": kXR_setattr, "kXR_symlink": kXR_symlink,
        "kXR_link": kXR_link,
    }
    try:
        table = mutating_opcodes()
    except (OSError, IndexError):
        results.append((False, "dispatch_write.c route table is parseable"))
        return
    results.append((bool(table), "dispatch_write.c route table is parseable"))
    unknown = sorted(table - set(names))
    results.append((not unknown,
                    f"every write-gated opcode has a numeric mapping here "
                    f"(unmapped: {unknown})"))
    missing = sorted(name for name in table & set(names)
                     if names[name] not in probed)
    results.append((not missing,
                    f"every write-gated opcode is probed (unprobed: {missing})"))


DOC_PAGE = REPO / "docs/03-configuration/read-only-root-gateway.md"


def _doc_nginx_blocks() -> list[str]:
    """Every ```nginx fenced block in the documentation page."""
    text = DOC_PAGE.read_text(encoding="utf-8")
    return re.findall(r"```nginx\n(.*?)```", text, re.S)


def _prepare_doc_work(base: Path) -> tuple[Path, Path, Path, bool]:
    work = base / "docparse"
    for name in ("export", "cache", "logs", "tls"):
        (work / name).mkdir(parents=True, exist_ok=True)
    crt, key = work / "tls/gw.crt", work / "tls/gw.key"
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(crt), "-days", "2", "-nodes", "-subj", "/CN=brix-doc"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return work, crt, key, result.returncode == 0


def _materialize_doc_config(block: str, index: int, work: Path,
                            crt: Path, key: Path) -> Path:
    conf = (block
            .replace("/var/lib/brix/export", str(work / "export"))
            .replace("/var/cache/brix", str(work / "cache"))
            .replace("/etc/brix/tls/gateway.crt", str(crt))
            .replace("/etc/brix/tls/gateway.key", str(key)))
    if "events" not in conf:
        conf = "events { worker_connections 64; }\n" + conf
    path = work / f"block{index}.conf"
    path.write_text(f"error_log {work / 'logs/e.log'} info;\n"
                    f"pid {work / 'nginx.pid'};\n" + conf, encoding="utf-8")
    return path


def _check_doc_block(block: str, index: int, work: Path, crt: Path,
                     key: Path, have_tls: bool, nginx_bin: str,
                     results: list[tuple[bool, str]]) -> None:
    if "brix_root" not in block:
        return
    if "brix_certificate" in block and not have_tls:
        results.append((True, f"doc config block {index}: skipped "
                              f"(openssl unavailable for the TLS block)"))
        return
    path = _materialize_doc_config(block, index, work, crt, key)
    result = run([nginx_bin, "-p", str(work), "-c", str(path), "-t"])
    output = (result.stderr or "") + (result.stdout or "")
    results.append(("syntax is ok" in output,
                    f"doc config block {index} passes nginx -t "
                    f"({output.strip()[-300:]})"))


def _check_doc_configs_parse(base: Path, nginx_bin: str,
                             results: list[tuple[bool, str]]) -> None:
    """The published example configs must survive ``nginx -t``.

    The page is the deliverable; a directive that has been renamed or that never
    existed has to fail HERE rather than in an operator's terminal.  Paths and
    the listen port are rewritten to the scratch tree; a self-signed pair backs
    the TLS block.
    """
    blocks = _doc_nginx_blocks()
    results.append((len(blocks) >= 2,
                    f"documentation page publishes nginx config blocks "
                    f"(found {len(blocks)})"))
    work, crt, key, have_tls = _prepare_doc_work(base)
    for index, block in enumerate(blocks):
        _check_doc_block(block, index, work, crt, key, have_tls,
                         nginx_bin, results)


def _probe_request(s: socket.socket, probe: Probe,
                   writable: bool) -> tuple[bytes, bytes]:
    body, payload = probe.body, probe.payload
    if not probe.wants_write_handle or not writable:
        return body, payload
    status, response = _send(
        s, kXR_open,
        struct.pack(">HH12x", 0o644, kXR_open_updt | kXR_new | kXR_delete),
        b"/ro_handle.dat")
    if status != kXR_ok:
        return body, payload
    handle = response[:4]
    body = handle + body[4:]
    if probe.opcode == kXR_writev:
        payload = struct.pack(">4siq", handle, 8, 0)
    return body, payload


def _run_probe(port: int, writable: bool,
               probe: Probe) -> tuple[Probe, int, bytes]:
    session = _session(port)
    try:
        body, payload = _probe_request(session, probe, writable)
        status, response = _send(
            session, probe.opcode, body, payload, probe.trailer)
        return probe, status, response
    finally:
        session.close()


def _run_probes(port: int, writable: bool) -> list[tuple[Probe, int, bytes]]:
    """Fire the whole table at one server. Each probe gets a fresh session so a
    refusal (or a state change) never leaks into the next one."""
    return [_run_probe(port, writable, probe) for probe in probes()]


def _check_read_only_surface(port: int, label: str,
                             results: list[tuple[bool, str]]) -> None:
    refused = []
    for probe, status, body in _run_probes(port, writable=False):
        ok = status == kXR_error and _errnum(body) == kXR_fsReadOnly
        if ok:
            refused.append(probe.name)
        results.append((ok, f"{label}: {probe.name} -> kXR_fsReadOnly "
                            f"(got status={status} err={_errnum(body)} "
                            f"{_errmsg(body)!r})"))
    results.append((len(refused) == len(probes()),
                    f"{label}: all {len(probes())} mutating probes refused"))


def _check_clone_refused(port: int, label: str,
                         results: list[tuple[bool, str]]) -> None:
    """kXR_clone is gated by brix_validate_write_handle, not by the write gate:
    its refusal is DERIVED from the fact that no writable handle can be opened.
    Probe it with a genuine READ handle as the clone destination, otherwise a
    kXR_FileNotOpen on an unopened handle would prove nothing."""
    s = _session(port)
    try:
        fh = _open_read(s, PUBLIC_FILE.encode())
        status, body = _send(s, kXR_clone, fh + b"\x00" * 12,
                             struct.pack(">4s4xQQQ", fh, 0, 8, 0))
        results.append((status == kXR_error and _errnum(body) == kXR_NotAuthorized,
                        f"{label}: clone onto an open READ handle -> "
                        f"kXR_NotAuthorized ({_errmsg(body)!r})"))
    finally:
        s.close()


def _check_reads_work(port: int, label: str,
                      results: list[tuple[bool, str]]) -> None:
    """A read-only gateway must still be a fully functional read gateway."""
    s = _session(port)
    try:
        st, body = _send(s, kXR_open,
                         struct.pack(">HH12x", 0, kXR_open_read),
                         PUBLIC_FILE.encode())
        results.append((st == kXR_ok, f"{label}: read-open succeeds"))
        if st == kXR_ok:
            st, data = _send(s, kXR_read,
                             body[:4] + struct.pack(">qi", 0, len(PUBLIC_PAYLOAD)))
            results.append((st == kXR_ok and data == PUBLIC_PAYLOAD,
                            f"{label}: read returns the origin bytes"))
        # NB: the stat `flags` field is derived from POSIX mode bits against the
        # server's effective uid (brix_stat_flags_from_stat), NOT from
        # brix_read_only — a client must not infer the posture from it.
        st, body = _send(s, kXR_stat, b"\x00" * 16, PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok, f"{label}: stat succeeds"))
        st, _ = _send(s, kXR_dirlist, b"\x00" * 16, b"/\x00")
        results.append((st == kXR_ok, f"{label}: dirlist succeeds"))
        st, body = _send(s, kXR_fattr, _fattr_body(kXR_fattrList, 0),
                         PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok, f"{label}: fattr list (read side) succeeds"))
        # Phase 107 deliberately treats a stage hint as a mutation.  Reject it
        # at the typed VFS policy gate before it can enqueue backend work.
        st, body = _send(s, kXR_prepare,
                         struct.pack(">BBH12x", kXR_stage, 0, 0),
                         PUBLIC_FILE.encode() + b"\n")
        results.append((st == kXR_error and _errnum(body) == kXR_fsReadOnly,
                        f"{label}: prepare stage is refused as read-only "
                        f"(status={st} {_errmsg(body)!r})"))
    finally:
        s.close()


def _check_control_is_not_refusing(port: int,
                                   results: list[tuple[bool, str]]) -> None:
    """Security-negative control: the identical frames against a WRITABLE server
    must never draw kXR_fsReadOnly, and the core mutations must actually land —
    so the refusals above are the gate, not a malformed probe."""
    misrefused, failed = [], []
    for probe, status, body in _run_probes(port, writable=True):
        if status == kXR_error and _errnum(body) == kXR_fsReadOnly:
            misrefused.append(probe.name)
        if probe.must_succeed_when_writable and status != kXR_ok:
            failed.append(f"{probe.name}({status}/{_errnum(body)}"
                          f":{_errmsg(body)})")
    results.append((not misrefused,
                    f"control: no probe draws kXR_fsReadOnly on a writable "
                    f"server (drew: {misrefused})"))
    results.append((not failed,
                    f"control: every well-formed mutation succeeds when writes "
                    f"are allowed (failed: {failed})"))


def _check_origin_untouched(origin_root: Path, before: set[str],
                            results: list[tuple[bool, str]]) -> None:
    after = tree_snapshot(origin_root)
    added = sorted(after - before)
    removed = sorted(before - after)
    results.append((not added and not removed,
                    f"origin tree is byte-for-byte unchanged after the whole "
                    f"probe run (added={added} removed={removed})"))
    public = origin_root / PUBLIC_FILE.lstrip("/")
    results.append((public.read_bytes() == PUBLIC_PAYLOAD,
                    "origin public file content is unchanged"))


# --------------------------------------------------------------------------- #
# runner                                                                       #
# --------------------------------------------------------------------------- #

def _wait(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@dataclass
class _Rig:
    """Everything started by run_checks, so teardown is one call."""
    nginx_prefixes: list[Path] = field(default_factory=list)
    procs: list[subprocess.Popen] = field(default_factory=list)
    tmpdirs: list[Path] = field(default_factory=list)

    def close(self) -> None:
        for prefix in reversed(self.nginx_prefixes):
            stop_nginx(prefix)
        for proc in self.procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for path in self.tmpdirs:
            shutil.rmtree(path, ignore_errors=True)


def _start_origin(base: Path, port: int, rig: _Rig) -> tuple[Path, str]:
    """Prefer the stock XRootD server — that is the documented deployment. Fall
    back to a writable brix root:// export where xrootd is not installed."""
    prefix = base / "origin"
    if XROOTD_BIN:
        conf, data, admin = write_xrootd_config(prefix, port)
        rig.tmpdirs.append(admin)
        seed_tree(data)
        proc = subprocess.Popen(
            [XROOTD_BIN, "-c", str(conf), "-l", str(prefix / "xrootd.log")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        rig.procs.append(proc)
        if _wait(port):
            return data, "stock xrootd"
        rig.procs.remove(proc)
        proc.terminate()
    conf, data = write_brix_origin_config(prefix, port)
    seed_tree(data)
    result = run([NGINX_BIN, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        raise RuntimeError(f"brix origin start failed: "
                           f"{(result.stderr or result.stdout)[-2000:]}")
    rig.nginx_prefixes.append(prefix)
    if not _wait(port):
        raise RuntimeError("brix origin never accepted a connection")
    return data, "brix root:// export"


def _start_gateway(base: Path, name: str, port: int, knobs: str,
                   origin_port: int | None, nginx_bin: str,
                   rig: _Rig) -> tuple[Path, Path]:
    """Start one gateway posture. Returns (prefix, export) — the prefix carries
    nginx.pid, which the reload-persistence check needs."""
    prefix = base / name
    conf = write_gateway_config(prefix, port, knobs, origin_port)
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        raise RuntimeError(f"{name} gateway start failed: "
                           f"{(result.stderr or result.stdout)[-2000:]}")
    rig.nginx_prefixes.append(prefix)
    if not _wait(port):
        raise RuntimeError(f"{name} gateway never accepted a connection")
    return prefix, prefix / "export"


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    # The deep families import this module for its wire helpers and probe table,
    # so the import lives here rather than at module scope (plain cycle break).
    from cmdscripts.root_readonly_gateway_deep import (check_override_is_logged,
                                                       run_deep_checks)

    (origin_port, ro_port, ov_port, ctl_port,
     sub_port, pub_port) = cmdscript_ports("root_readonly_gateway", 6)
    rig = _Rig()
    results: list[tuple[bool, str]] = []
    try:
        origin_root, origin_kind = _start_origin(base, origin_port, rig)
        results.append((True, f"origin is {origin_kind} on :{origin_port}"))

        # brix_sitename: gives the plain gateway a served deployment-identity
        # value, so the public posture's withheld-key differential (sitename
        # echoes there) measures the DIRECTIVE and not an unset knob.
        ro_prefix, ro_export = _start_gateway(
            base, "ro", ro_port,
            "    brix_read_only on;\n"
            "    brix_sitename BriX-RO-Gateway;\n",
            origin_port, nginx_bin, rig)
        ov_prefix, _ = _start_gateway(
            base, "override", ov_port,
            "    brix_allow_write on;\n    brix_read_only on;\n",
            origin_port, nginx_bin, rig)
        _, control_export = _start_gateway(base, "control", ctl_port,
                                           "    brix_allow_write on;\n",
                                           None, nginx_bin, rig)
        seed_tree(control_export)
        # brix_data_substreams merges to ON, so the documented gateway above
        # already accepts a kXR_bind secondary — the one route by which a bare
        # kXR_write reaches the gate without an open on the same connection.
        # This instance is the opposite posture: substreams explicitly off, so
        # the narrower surface is asserted too.
        _start_gateway(base, "substreams", sub_port,
                       "    brix_read_only on;\n"
                       "    brix_data_substreams off;\n",
                       origin_port, nginx_bin, rig)
        # brix_read_only_public: the same read-only guarantee PLUS the
        # introspection restrictions.  A separate instance because the whole
        # point is that the two postures differ on the kXR_query surface and
        # NOWHERE else — the mutation battery must produce identical results.
        pub_prefix, pub_export = _start_gateway(
            base, "public", pub_port, "    brix_read_only_public on;\n",
            origin_port, nginx_bin, rig)

        before = tree_snapshot(origin_root)
        _check_doc_configs_parse(base, nginx_bin, results)
        _check_table_is_covered(results)
        for port, label in ((ro_port, "read_only"),
                            (ov_port, "read_only+allow_write"),
                            (pub_port, "read_only_public")):
            _check_read_only_surface(port, label, results)
            _check_clone_refused(port, label, results)
            _check_reads_work(port, label, results)
        _check_control_is_not_refusing(ctl_port, results)
        check_override_is_logged(nginx_bin, ov_prefix,
                                 ov_prefix / "nginx.conf", results, run)
        run_deep_checks(ro_port=ro_port, ro_prefix=ro_prefix, sub_port=sub_port,
                        pub_port=pub_port, pub_export=pub_export,
                        pub_prefix=pub_prefix, nginx_bin=nginx_bin,
                        base=base, origin_root=origin_root,
                        export_root=ro_export, results=results)
        _check_origin_untouched(origin_root, before, results)
        return results
    except Exception as exc:                          # rig failure -> one row
        results.append((False, f"rig failure: {exc}"))
        return results
    finally:
        rig.close()


def _report_results(results: list[tuple[bool, str]]) -> int:
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_root_readonly_gateway: ALL PASS")
        return 0
    print("run_root_readonly_gateway: FAILURES")
    return 1


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    with tempfile.TemporaryDirectory(prefix="root_readonly_gateway.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return _report_results(results)


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
