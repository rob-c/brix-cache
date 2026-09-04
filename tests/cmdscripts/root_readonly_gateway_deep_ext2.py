# root_readonly_gateway_deep_ext2.py — continuation shard split off from root_readonly_gateway_deep.py for the 600
# logical-line cap; exec'd into its namespace by split_continuation.load so the
# module's import API is unchanged.

def _bind_secondary(port: int, sessid: bytes) -> tuple[socket.socket, int, bytes]:
    s = socket.create_connection((HOST, port), timeout=8)
    s.settimeout(8)
    s.sendall(H.HANDSHAKE + H.make_protocol_req())
    H._recv_response(s)
    H._recv_response(s)
    status, resp = _send(s, kXR_bind, sessid[:16])
    return s, status, resp


def _record_disabled_bind(
    status: int, resp: bytes, label: str, results: list[tuple[bool, str]]
) -> None:
    refused = status == kXR_error and _errnum(resp) == kXR_Unsupported
    results.append(
        (
            refused,
            f"{label}: kXR_bind refused when data substreams "
            f"are off ({status}/{_errnum(resp)} "
            f"{_errmsg(resp)!r})",
        )
    )


def _probe_bound_write(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_write, b"\x00" * 4 + struct.pack(">q4x", 0), b"X" * 8
    )
    refused = status == kXR_error and _errnum(resp) == kXR_fsReadOnly
    results.append(
        (
            refused,
            f"{label}: bound-stream kXR_write -> kXR_fsReadOnly "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_bound_mkdir(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/bound_mkdir"
    )
    refused = status == kXR_error and _errnum(resp) in (
        kXR_NotAuthorized,
        kXR_fsReadOnly,
    )
    results.append(
        (
            refused,
            f"{label}: bound-stream kXR_mkdir refused "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_bound_open(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_open, struct.pack(">HH12x", 0o644, 0x0028), b"/bound_open.dat"
    )
    refused = status == kXR_error and _errnum(resp) in (
        kXR_NotAuthorized,
        kXR_fsReadOnly,
    )
    results.append(
        (
            refused,
            f"{label}: bound-stream write-open refused "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_enabled_bound_stream(
    secondary: socket.socket,
    status: int,
    resp: bytes,
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    results.append(
        (
            status == kXR_ok,
            f"{label}: kXR_bind accepted with substreams on "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )
    if status != kXR_ok:
        return
    _probe_bound_write(secondary, label, results)
    _probe_bound_mkdir(secondary, label, results)
    _probe_bound_open(secondary, label, results)


def _probe_bound_stream_mode(
    secondary: socket.socket,
    status: int,
    resp: bytes,
    substreams: bool,
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    if not substreams:
        _record_disabled_bind(status, resp, label, results)
        return
    _probe_enabled_bound_stream(secondary, status, resp, label, results)


def check_bound_stream(
    port: int, label: str, *, substreams: bool, results: list[tuple[bool, str]]
) -> None:
    """kXR_bind is the one path a bare kXR_write may travel without an open on
    the same connection (policy.c lets a bound secondary carry kXR_write, and
    only kXR_write).  It must still hit the read-only gate.

    With brix_data_substreams off the bind itself is refused — a narrower
    surface, asserted separately so a posture flip cannot pass unnoticed.
    """
    primary = socket.create_connection((HOST, port), timeout=8)
    primary.settimeout(8)
    try:
        hs, proto, login, body = H._full_anon_login_body(primary)
        if login != kXR_ok or len(body) < 16:
            results.append(
                (
                    False,
                    f"{label}: primary login for bind failed ({hs}/{proto}/{login})",
                )
            )
            return
        sessid = body[:16]
        secondary, status, resp = _bind_secondary(port, sessid)
        try:
            _probe_bound_stream_mode(
                secondary, status, resp, substreams, label, results
            )
        finally:
            secondary.close()
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: bound-stream probe failed: {exc}"))
    finally:
        primary.close()


# --------------------------------------------------------------------------- #
# 5. signing envelope                                                          #
# --------------------------------------------------------------------------- #


def check_signed_mutation(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """A kXR_sigver envelope announces "the next request is signed". It must not
    become a way to carry a mutation past the read-only gate."""
    s = _session(port)
    try:
        # sigver body: expectrid[2] version[1] flags[1] seqno[8] crypto[1] rsvd[3].
        # A well-formed envelope draws NO response — it is a request PREFIX, and
        # the single response belongs to the signed request that follows
        # (session/signing.c) — so the envelope is sent without reading.
        body = struct.pack(">HBBqB3x", kXR_mkdir, 0, 0, 1, 0)
        s.sendall(H.make_request(b"\x00\x07", kXR_sigver, body, b"\x00" * 32))
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/signed_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation inside a kXR_sigver envelope is "
                f"still refused ({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: signed-mutation probe failed: {exc}"))
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 6. path shapes                                                               #
# --------------------------------------------------------------------------- #

PATH_SHAPES = (
    ("traversal", b"/../escape_mkdir"),
    ("deep traversal", b"/a/../../../../tmp/escape_mkdir"),
    ("doubled separators", b"//ro_shape//dir"),
    ("trailing slash", b"/ro_shape_slash/"),
    ("dot segment", b"/./ro_shape_dot"),
    ("opaque suffix", b"/ro_shape_opq?oss.asize=1"),
    ("embedded NUL", b"/ro_shape_nul\x00/extra"),
    ("relative", b"ro_shape_rel"),
    ("root", b"/"),
    ("empty", b""),
)


def check_path_shapes(port: int, label: str, results: list[tuple[bool, str]]) -> None:
    """No spelling of a mutating path may be accepted — and none may escape the
    export either, which the integrity bracket around this family proves."""
    accepted = []
    for name, path in PATH_SHAPES:
        status, resp = _try(
            port, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), path, b""
        )
        err = _errnum(resp) if status == kXR_error else None
        ok = status != kXR_ok
        if not ok:
            accepted.append(name)
        results.append(
            (
                ok,
                f"{label}: mkdir with a {name} path is not accepted "
                f"({status}/{err} {_errmsg(resp)!r})",
            )
        )
    results.append(
        (not accepted, f"{label}: no path shape was accepted (accepted: {accepted})")
    )


# --------------------------------------------------------------------------- #
# 6b. kXR_query subcodes                                                       #
# --------------------------------------------------------------------------- #


def check_query_subcodes(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """kXR_query is read-routed, but it is really thirteen operations behind one
    opcode — including the two "implementation-defined" escape hatches
    (kXR_Qopaquf / kXR_Qopaqug) that stock XRootD uses to pass commands to the
    filesystem, and kXR_Qckscan, which walks a tree.  The opcode sweep can only
    fire one infotype; this fires them all.

    The mutation assertion is the digest bracket around the family — including
    the gateway's OWN export, so a query that materialises a cache artefact
    where a public read-only gateway should have none is caught too.
    """
    answered = []
    for name, infotype in sorted(query_subcodes().items(), key=lambda kv: kv[1]):
        body = struct.pack(">HH4s8x", infotype, 0, b"\x00" * 4)
        status, resp = _try(port, kXR_query, body, PUBLIC_FILE.encode() + b"\x00", b"")
        err = _errnum(resp) if status == kXR_error else None
        answered.append(status is not None)
        results.append(
            (
                status is not None,
                f"{label}: query {name}({infotype}) answered "
                f"{status}/{err} {_errmsg(resp)!r}",
            )
        )
    results.append(
        (
            all(answered) and len(answered) >= 13,
            f"{label}: every kXR_query infotype in opcodes.h was "
            f"exercised ({len(answered)})",
        )
    )


# --------------------------------------------------------------------------- #
# 6c. session opcodes cannot lift the gate                                     #
# --------------------------------------------------------------------------- #


def check_session_ops_cannot_lift_the_gate(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """kXR_set is login-gated but NOT write-gated (dispatch_session.c), so it is
    the one server-configuration opcode a public client can reach.  Prove it
    cannot move the posture: run the session opcodes on a connection, then
    mutate on that same connection and require the same refusal.
    """
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"{label}: session for the set probe failed: {exc}"))
        return
    try:
        # kXR_set body: modifier(1) reserved(15) — appid and clttl are the two
        # modifiers the server names (query/set.c).
        for modifier, what in ((0x00, "appid"), (0x01, "clttl")):
            st, resp = _send(
                s, kXR_set, struct.pack(">B15x", modifier), b"brix-readonly-probe\n"
            )
            results.append(
                (
                    st in (kXR_ok, kXR_error),
                    f"{label}: kXR_set {what} answered {st}/{_errnum(resp)}",
                )
            )
        st, resp = _send(
            s, kXR_set, struct.pack(">B15x", 0x00), b"cms.space 1000000 999999\n"
        )
        results.append(
            (
                st in (kXR_ok, kXR_error),
                f"{label}: kXR_set cms.space answered {st}/{_errnum(resp)}",
            )
        )
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/after_set_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation after kXR_set is still refused "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
        # A second login on a live session must not re-negotiate the posture.
        s.sendall(H.make_login_req())
        st, resp = H._recv_response(s)
        results.append(
            (True, f"{label}: re-login on a live session answered {st}/{_errnum(resp)}")
        )
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/after_relogin_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation after a re-login is still refused "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: session-opcode probe failed: {exc}"))
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 7. concurrency storm                                                         #
# --------------------------------------------------------------------------- #


def _mutation_worker(
    port: int,
    table: list[Probe],
    stride: int,
    index: int,
    outcomes: list[tuple[str, int | None, int | None]],
    lock: threading.Lock,
) -> None:
    local = []
    for probe in table[index::stride]:
        status, resp = _try(
            port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        local.append((probe.name, status, err))
    with lock:
        outcomes.extend(local)


def _run_mutation_workers(
    port: int, table: list[Probe], thread_count: int
) -> list[tuple[str, int | None, int | None]]:
    outcomes: list[tuple[str, int | None, int | None]] = []
    lock = threading.Lock()
    workers = [
        threading.Thread(
            target=_mutation_worker,
            args=(port, table, thread_count, index, outcomes, lock),
            daemon=True,
        )
        for index in range(thread_count)
    ]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=120)
    return outcomes


def check_mutation_storm(
    port: int, label: str, results: list[tuple[bool, str]], *, threads: int = 8
) -> None:
    """Prove the per-request gate holds under concurrent mutation attempts."""
    table = probes()
    outcomes = _run_mutation_workers(port, table, threads)

    escaped = [f"{n}({s}/{e})" for n, s, e in outcomes if e != kXR_fsReadOnly]
    results.append(
        (
            len(outcomes) == len(table),
            f"{label}: storm ran every probe concurrently "
            f"({len(outcomes)}/{len(table)} across {threads} threads)",
        )
    )
    results.append(
        (
            not escaped,
            f"{label}: every concurrent mutation refused as read-only "
            f"(escaped: {escaped})",
        )
    )


# --------------------------------------------------------------------------- #
# 8. reload persistence                                                        #
# --------------------------------------------------------------------------- #


def check_reload_persistence(
    prefix: Path, port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """SIGHUP re-runs the config merge in a new worker. brix_read_only must come
    back on: an operator reloading for an unrelated reason must not silently
    open the gateway for writes."""
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGHUP)
    except (OSError, ValueError) as exc:
        results.append((False, f"{label}: could not SIGHUP the gateway: {exc}"))
        return
    time.sleep(1.0)
    results.append((_wait(port), f"{label}: gateway accepts connections after SIGHUP"))
    survived = []
    for probe in probes():
        status, resp = _try(
            port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            survived.append(f"{probe.name}({status}/{err})")
    results.append(
        (
            not survived,
            f"{label}: every mutation still refused after a reload "
            f"(escaped: {survived})",
        )
    )


# --------------------------------------------------------------------------- #
# 9. reads keep working under every posture                                    #
# --------------------------------------------------------------------------- #


def check_read_surface_intact(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """After the whole expansive run, the gateway must still be a gateway."""
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"{label}: session after the sweep failed: {exc}"))
        return
    try:
        st, resp = _send(
            s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
        )
        results.append(
            (
                st == kXR_ok,
                f"{label}: read-open still succeeds after the full sweep "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
        if st == kXR_ok:
            handle = resp[:4]
            st, data = _send(s, kXR_read, handle + struct.pack(">qi", 0, 64))
            results.append(
                (
                    st == kXR_ok and data,
                    f"{label}: read still returns bytes after the sweep",
                )
            )
            _send(s, kXR_close, handle + b"\x00" * 12)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 10. the manager/read-only role conflict is fatal                             #
# --------------------------------------------------------------------------- #


def _try_manager_conf(
    work: Path, nginx_bin: str, name: str, knobs: str
) -> tuple[int, str]:
    conf = work / f"{name}.conf"
    conf.write_text(
        "daemon off;\n"
        f"error_log {work / 'logs' / (name + '.log')} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        # ``nginx -t`` never serves this listener.  Keep the address relative
        # to the supplied prefix so xdist's deeply nested tmp directory cannot
        # overflow sockaddr_un.sun_path before the role-conflict merge runs.
        f"    listen unix:{name[:12]}.sock;\n"
        "    brix_root on;\n"
        f"    brix_export {work / 'export'};\n"
        "    brix_auth none;\n"
        f"{knobs}"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    process = subprocess.run(
        [nginx_bin, "-p", str(work), "-c", str(conf), "-t"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = (process.stderr or "") + (process.stdout or "")
    return process.returncode, output


def _record_manager_conflict(
    name: str, rc: int, output: str, results: list[tuple[bool, str]]
) -> None:
    named = all(
        fragment in output
        for fragment in ("brix_manager_mode", "brix_read_only", "mutually exclusive")
    )
    results.append(
        (
            rc != 0 and named,
            f"config: manager + brix_{name} is refused by nginx -t, "
            f"naming both directives "
            f"(rc={rc} {output.strip()[-240:]!r})",
        )
    )
    results.append(
        ("[emerg]" in output, f"config: manager + brix_{name} refusal is EMERG")
    )


def check_manager_mode_is_refused_at_config_time(
    base: Path, nginx_bin: str, results: list[tuple[bool, str]]
) -> None:
    """Reject manager/read-only role conflicts while accepting plain managers."""
    work = base / "rolecheck"
    (work / "export").mkdir(parents=True, exist_ok=True)
    (work / "logs").mkdir(parents=True, exist_ok=True)

    for name, knobs in (
        ("read_only", "    brix_read_only on;\n    brix_manager_mode on;\n"),
        (
            "read_only_public",
            "    brix_read_only_public on;\n    brix_manager_mode on;\n",
        ),
    ):
        rc, output = _try_manager_conf(work, nginx_bin, f"manager_{name}", knobs)
        _record_manager_conflict(name, rc, output, results)

    rc, output = _try_manager_conf(
        work, nginx_bin, "manager_alone", "    brix_manager_mode on;\n"
    )
    results.append(
        (
            rc == 0,
            f"config: brix_manager_mode WITHOUT read_only still parses — "
            f"plain manager nodes are unaffected "
            f"(rc={rc} {output.strip()[-160:]!r})",
        )
    )


# --------------------------------------------------------------------------- #
# 11. brix_read_only_public — the introspection surface                        #
# --------------------------------------------------------------------------- #

#: kXR_query infotypes that describe the SERVER rather than a path.  Mirrors
#: brix_query_is_server_introspection() in src/protocols/root/query/dispatch.c;
#: the check below parses that function so the two cannot drift apart.
QUERY_DISPATCH_C = REPO / "src/protocols/root/query/dispatch.c"


def public_restricted_infotypes() -> set[str]:
    """The server-introspection set, read out of the C gate function."""
    text = QUERY_DISPATCH_C.read_text(encoding="utf-8")
    body = text.split("brix_query_is_server_introspection(uint16_t infotype)", 1)[1]
    body = body.split("}", 1)[0]
    return set(re.findall(r"infotype\s*==\s*(kXR_Q\w+)", body))


def _is_not_authorized(status: int | None, response: bytes) -> bool:
    return status == kXR_error and _errnum(response) == kXR_NotAuthorized


def _append_failed_case(failures: list[str], passed: bool, detail: str) -> None:
    if not passed:
        failures.append(detail)


def _record_restricted_query(
    name: str,
    infotype: int,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    leaked: list[str],
    unchanged: list[str],
    results: list[tuple[bool, str]],
) -> None:
    refused = _is_not_authorized(pub_status, pub_response)
    pub_error = _errnum(pub_response) if pub_status == kXR_error else None
    _append_failed_case(leaked, refused, f"{name}({pub_status}/{pub_error})")
    results.append(
        (
            refused,
            f"read_only_public: query {name}({infotype}) is refused "
            f"kXR_NotAuthorized ({pub_status}/{pub_error} "
            f"{_errmsg(pub_response)[:60]!r})",
        )
    )
    changed = not _is_not_authorized(ro_status, ro_response)
    _append_failed_case(unchanged, changed, name)
    ro_error = _errnum(ro_response) if ro_status == kXR_error else None
    results.append(
        (
            changed,
            f"read_only_public: query {name}({infotype}) was not "
            f"already refused on plain read-only (ro={ro_status}/"
            f"{ro_error})",
        )
    )


def _response_outcome(
    status: int | None, response: bytes
) -> tuple[int | None, int | None]:
    error = _errnum(response) if status == kXR_error else None
    return status, error


def _record_path_query(
    name: str,
    infotype: int,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    over_refused: list[str],
    results: list[tuple[bool, str]],
) -> None:
    same = _response_outcome(pub_status, pub_response) == _response_outcome(
        ro_status, ro_response
    )
    refused = _is_not_authorized(pub_status, pub_response)
    _append_failed_case(over_refused, not refused, name)
    pub_error = _errnum(pub_response) if pub_status == kXR_error else None
    results.append(
        (
            same,
            f"read_only_public: query {name}({infotype}) is unchanged "
            f"from the plain read-only gateway (ro={ro_status} "
            f"public={pub_status}/"
            f"{pub_error})",
        )
    )
