# root_readonly_gateway_deep_ext.py — continuation shard split off from root_readonly_gateway_deep.py for the 600
# logical-line cap; exec'd into its namespace by split_continuation.load so the
# module's import API is unchanged.

def _check_public_query(
    name: str,
    infotype: int,
    restricted: set[str],
    pub_port: int,
    ro_port: int,
    leaked: list[str],
    over_refused: list[str],
    unchanged: list[str],
    results: list[tuple[bool, str]],
) -> None:
    body = struct.pack(">HH4s8x", infotype, 0, b"\x00" * 4)
    payload = PUBLIC_FILE.encode() + b"\x00"
    ro_status, ro_response = _try(ro_port, kXR_query, body, payload, b"")
    pub_status, pub_response = _try(pub_port, kXR_query, body, payload, b"")
    if name in restricted:
        _record_restricted_query(
            name,
            infotype,
            ro_status,
            ro_response,
            pub_status,
            pub_response,
            leaked,
            unchanged,
            results,
        )
        return
    _record_path_query(
        name,
        infotype,
        ro_status,
        ro_response,
        pub_status,
        pub_response,
        over_refused,
        results,
    )


def check_public_mode_restricts_introspection(
    pub_port: int, ro_port: int, results: list[tuple[bool, str]]
) -> None:
    """Every kXR_query infotype, fired at BOTH postures and compared.

    The claim has two halves and one test has to carry both, because either half
    alone is satisfiable by a broken build: a server that refused every query
    would pass "introspection is restricted", and a server that refused none
    would pass "reads still work".  So each infotype is fired at the plain
    read-only gateway AND at the public one, and the ONLY permitted difference
    is that the restricted set flips from answered to kXR_NotAuthorized.
    """
    restricted = public_restricted_infotypes()
    results.append(
        (
            len(restricted) >= 4 and "kXR_Qconfig" not in restricted,
            f"read_only_public: the C names {len(restricted)} "
            f"server-introspection infotypes {sorted(restricted)}, and "
            f"kXR_Qconfig is filtered per key rather than refused",
        )
    )

    leaked, over_refused, unchanged = [], [], []
    ordered = sorted(query_subcodes().items(), key=lambda item: item[1])
    for name, infotype in ordered:
        _check_public_query(
            name,
            infotype,
            restricted,
            pub_port,
            ro_port,
            leaked,
            over_refused,
            unchanged,
            results,
        )

    results.append(
        (
            not leaked,
            f"read_only_public: no server-introspection query answered "
            f"(leaked: {leaked})",
        )
    )
    results.append(
        (
            not over_refused,
            f"read_only_public: no path-scoped query was collaterally "
            f"refused (over-refused: {over_refused})",
        )
    )
    results.append(
        (
            not unchanged,
            f"read_only_public: every restricted infotype was answerable "
            f"only because of the directive (already-refused: {unchanged})",
        )
    )


#: The kXR_Qconfig descriptor table, with its public_safe column.  Parsed out of
#: the C so a key added there — safe or withheld — lands in this check on its own.
QUERY_CONFIG_C = REPO / "src/protocols/root/query/config.c"


def qconfig_keys() -> dict[str, bool]:
    """{key: public_safe} straight from brix_qconfig_table[].

    Each row is now 4-column — ``{ "key", <fixed-response-line|NULL>,
    <emitter|NULL>, <public_safe> }`` — after the qconfig table was reshaped
    (9ab5c3f5) so a key that emits a constant line carries the string as data
    with a NULL emitter, instead of every key needing its own emitter function.
    The key is the first quoted token and public_safe is the trailing 0/1; the
    two middle columns (a possibly multi-line string literal, NULL, or an
    ``brix_qconfig_emit_*`` name) are skipped non-greedily so both fixed-line and
    emitter rows are read.  The old regex pinned an emitter immediately after the
    key and so matched zero rows against the reshaped table."""
    text = QUERY_CONFIG_C.read_text(encoding="utf-8")
    body = text.split("brix_qconfig_table[] = {", 1)[1].split("\n};", 1)[0]
    return {
        key: value == "1"
        for key, value in re.findall(
            r'\{\s*"([^"]+)"\s*,.*?,\s*([01])\s*\}', body, re.DOTALL
        )
    }


def _qconfig(port: int, key: str) -> tuple[int | None, bytes]:
    return _try(
        port, kXR_query, struct.pack(">HH4s8x", 7, 0, b"\x00" * 4), key.encode(), b""
    )


def _record_safe_qconfig(
    key: str,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    differed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    same = pub_status == ro_status and pub_response == ro_response
    _append_failed_case(differed, same, key)
    results.append(
        (
            same and pub_status == kXR_ok,
            f"read_only_public: qconfig capability key {key!r} answers "
            f"identically to the plain read-only gateway "
            f"({pub_status} {pub_response[:48]!r})",
        )
    )


def _record_withheld_qconfig(
    key: str,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    leaked: list[str],
    results: list[tuple[bool, str]],
) -> None:
    encoded_key = key.encode()
    plain_value = ro_response.rstrip(b"\x00").strip()
    plain_served = ro_status == kXR_ok and plain_value != encoded_key
    results.append(
        (
            plain_served,
            f"read_only_public: qconfig key {key!r} IS served on the plain "
            f"read-only gateway ({ro_response[:48]!r})",
        )
    )
    echoed = pub_response.rstrip(b"\x00").strip() == encoded_key
    _append_failed_case(leaked, echoed, f"{key}={pub_response[:32]!r}")
    results.append(
        (
            pub_status == kXR_ok and echoed,
            f"read_only_public: qconfig deployment key {key!r} is withheld — "
            f"echoed like an unknown key "
            f"({pub_status} {pub_response[:48]!r})",
        )
    )
    value_hidden = plain_value not in pub_response or plain_value == encoded_key
    results.append(
        (
            value_hidden,
            f"read_only_public: withheld {key!r} value "
            f"{plain_value[:32]!r} appears nowhere in the public answer",
        )
    )


def _check_qconfig_key(
    key: str,
    public_safe: bool,
    pub_port: int,
    ro_port: int,
    leaked: list[str],
    differed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    ro_status, ro_response = _qconfig(ro_port, key)
    pub_status, pub_response = _qconfig(pub_port, key)
    if public_safe:
        _record_safe_qconfig(
            key, ro_status, ro_response, pub_status, pub_response, differed, results
        )
        return
    _record_withheld_qconfig(
        key, ro_status, ro_response, pub_status, pub_response, leaked, results
    )


def check_public_mode_qconfig_is_filtered_per_key(
    pub_port: int, ro_port: int, results: list[tuple[bool, str]]
) -> None:
    """kXR_Qconfig answers PROTOCOL capability and withholds DEPLOYMENT identity.

    Refusing the whole infotype would hide nothing an anonymous client cannot
    establish by trying, and would cost it the vector-read geometry — XrdCl that
    cannot read readv_ior_max/readv_iov_max falls back to conservative defaults
    and issues many more, much smaller readv elements against the very endpoint
    that exists to stream bulk data.  So each key is fired at BOTH postures:

      * public_safe keys must answer byte-identically to the plain read-only
        gateway (a capability that silently changed value under the directive
        would be its own bug),
      * withheld keys must answer exactly like an UNKNOWN key — the reference
        do_Qconf default branch echoes the key name — so a restricted key is
        indistinguishable from one this build never supported,
      * and the withheld VALUE must not appear anywhere in the response.
    """
    keys = qconfig_keys()
    withheld = sorted(key for key, safe in keys.items() if not safe)
    results.append(
        (
            len(keys) >= 15 and bool(withheld),
            f"read_only_public: the C table names {len(keys)} kXR_Qconfig keys, "
            f"withheld: {withheld}",
        )
    )

    leaked, differed = [], []
    for key, public_safe in sorted(keys.items()):
        _check_qconfig_key(
            key, public_safe, pub_port, ro_port, leaked, differed, results
        )

    results.append(
        (
            not leaked,
            f"read_only_public: no deployment-identity qconfig key was "
            f"served (leaked: {leaked})",
        )
    )
    results.append(
        (
            not differed,
            f"read_only_public: no capability qconfig key changed value "
            f"under the directive (differed: {differed})",
        )
    )


def _collect_readv_limits(
    pub_port: int, results: list[tuple[bool, str]]
) -> dict[str, int]:
    limits = {}
    for key in ("readv_ior_max", "readv_iov_max", "pio_max", "bind_max"):
        status, response = _qconfig(pub_port, key)
        text = response.rstrip(b"\x00").strip().decode("latin-1")
        valid = status == kXR_ok and text.isdigit() and int(text) > 0
        if valid:
            limits[key] = int(text)
        results.append(
            (
                valid,
                f"read_only_public: qconfig {key} answers a bare "
                f"positive integer for atoi() ({status} {text!r})",
            )
        )
    return limits


def _record_readv_capabilities(pub_port: int, results: list[tuple[bool, str]]) -> None:
    status, response = _qconfig(pub_port, "readv")
    results.append(
        (
            status == kXR_ok and b"readv=1" in response,
            f"read_only_public: qconfig advertises readv support "
            f"({status} {response[:32]!r})",
        )
    )
    status, response = _qconfig(pub_port, "chksum")
    results.append(
        (
            status == kXR_ok and b"adler32" in response,
            f"read_only_public: qconfig advertises the checksum list "
            f"xrdcp negotiates with "
            f"({status} {response[:48]!r})",
        )
    )


def _run_readv_probe(
    session: socket.socket, segment_limit: int, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
    )
    if status != kXR_ok:
        results.append((False, f"read_only_public: readv open failed ({status})"))
        return
    handle = response[:4]
    segments = min(4, segment_limit)
    body = b"".join(
        handle + struct.pack(">qi", index * 4, 4) for index in range(segments)
    )
    status, data = _send(session, kXR_readv, b"\x00" * 16, body)
    results.append(
        (
            status == kXR_ok and len(data) > 0,
            f"read_only_public: a kXR_readv of {segments} elements "
            f"sized from the advertised limits is served "
            f"({status}, {len(data)} B)",
        )
    )
    _send(session, kXR_close, handle + b"\x00" * 12)


def _probe_readv_geometry(
    pub_port: int, segment_limit: int, results: list[tuple[bool, str]]
) -> None:
    try:
        session = _session(pub_port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"read_only_public: readv session failed: {exc}"))
        return
    try:
        _run_readv_probe(session, segment_limit, results)
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: readv probe failed: {exc}"))
    finally:
        session.close()


def check_public_mode_readv_tuning_survives(
    pub_port: int, results: list[tuple[bool, str]]
) -> None:
    """Verify public qconfig tuning values drive a real vector read."""
    limits = _collect_readv_limits(pub_port, results)
    _record_readv_capabilities(pub_port, results)
    if "readv_iov_max" not in limits:
        results.append((False, "read_only_public: no readv geometry to exercise"))
        return
    _probe_readv_geometry(pub_port, limits["readv_iov_max"], results)


def _record_public_namespace_reads(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(session, kXR_dirlist, b"\x00" * 16, b"/\x00")
    listed = PUBLIC_FILE.strip("/").encode() in response
    results.append(
        (
            status == kXR_ok and listed,
            f"read_only_public: dirlist still lists the namespace "
            f"({status} {response[:60]!r})",
        )
    )
    status, _response = _send(
        session, kXR_stat, b"\x00" * 16, PUBLIC_FILE.encode() + b"\x00"
    )
    results.append(
        (status == kXR_ok, f"read_only_public: stat still answers ({status})")
    )


def _read_public_chunks(session: socket.socket, handle: bytes) -> tuple[int, bytes]:
    streamed = b""
    status = kXR_ok
    for offset in (0, 8, 16):
        status, data = _send(session, kXR_read, handle + struct.pack(">qi", offset, 8))
        if status != kXR_ok:
            break
        streamed += data
    return status, streamed


def _record_public_stream(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
    )
    results.append(
        (status == kXR_ok, f"read_only_public: read-open still succeeds ({status})")
    )
    if status != kXR_ok:
        return
    handle = response[:4]
    status, streamed = _read_public_chunks(session, handle)
    results.append(
        (
            status == kXR_ok and len(streamed) > 8,
            f"read_only_public: a multi-chunk streamed read returns bytes "
            f"({status}, {len(streamed)} B)",
        )
    )
    _send(session, kXR_close, handle + b"\x00" * 12)


def _record_public_checksum(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session,
        kXR_query,
        struct.pack(">HH4s8x", 3, 0, b"\x00" * 4),
        PUBLIC_FILE.encode() + b"\x00",
    )
    results.append(
        (
            status == kXR_ok,
            f"read_only_public: per-path checksum still answers "
            f"({status} {_errmsg(response)[:40]!r})",
        )
    )


def _run_public_read_surface(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    _record_public_namespace_reads(session, results)
    _record_public_stream(session, results)
    _record_public_checksum(session, results)


def check_public_mode_still_serves_data(
    port: int, results: list[tuple[bool, str]]
) -> None:
    """The directive must not cost the gateway its job.

    "Restricts introspection while still allowing data to be listed and
    read/streamed" is the requirement, so the read surface is exercised end to
    end on the public instance: dirlist, stat, open, a multi-chunk streamed
    read, and the per-path checksum xrdcp uses to verify a transfer.
    """
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"read_only_public: session failed: {exc}"))
        return
    try:
        _run_public_read_surface(s, results)
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: read-surface probe failed: {exc}"))
    finally:
        s.close()


def check_public_mode_is_still_read_only(
    pub_port: int, results: list[tuple[bool, str]]
) -> None:
    """brix_read_only_public IMPLIES brix_read_only — assert it on the wire.

    The implication is applied in brix_shared_apply_read_only(), i.e. in the
    config finaliser rather than in any handler, so the only way to know it
    reached the write gates is to fire the mutation battery at a server that
    was configured with the public directive ALONE.
    """
    escaped = []
    for probe in probes():
        status, resp = _try(
            pub_port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            escaped.append(f"{probe.name}({status}/{err})")
    results.append(
        (
            not escaped,
            f"read_only_public: every mutation refused as read-only "
            f"WITHOUT an explicit brix_read_only (escaped: {escaped})",
        )
    )


def _read_log_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _collect_startup_output(result, prefix: Path) -> str:
    output = (result.stderr or "") + (result.stdout or "")
    logs = sorted((prefix / "logs").glob("*.log"))
    return output + "".join(_read_log_text(path) for path in logs)


def check_override_is_logged(
    nginx_bin: str, prefix: Path, conf: Path, results: list[tuple[bool, str]], run
) -> None:
    """brix_read_only silently overriding brix_allow_write would be a nasty
    surprise in the other direction too: the server must SAY so.

    The NOTICE is emitted during the config merge, so it lands in the error log
    the config itself names (not on the -t stderr); both are inspected.
    """
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf), "-t"])
    output = _collect_startup_output(result, prefix)
    hit = [line for line in output.splitlines() if "overrides allow_write" in line]
    results.append(
        (
            bool(hit),
            f"read_only+allow_write: startup announces that read_only "
            f"overrides allow_write ({hit[:1]})",
        )
    )


# --------------------------------------------------------------------------- #
# entry point used by the main rig                                             #
# --------------------------------------------------------------------------- #


def run_deep_checks(
    *,
    ro_port: int,
    ro_prefix: Path,
    sub_port: int,
    pub_port: int,
    pub_prefix: Path,
    pub_export: Path,
    nginx_bin: str,
    base: Path,
    origin_root: Path,
    export_root: Path,
    results: list[tuple[bool, str]],
) -> None:
    """Every expansive family, each bracketed by a content-hash integrity check
    of both the origin tree and the gateway's own export."""
    families = (
        ("opcode space", lambda: check_opcode_space(ro_port, "read_only", results)),
        (
            "open options",
            lambda: check_open_option_space(ro_port, "read_only", results),
        ),
        (
            "unauthenticated",
            lambda: check_unauthenticated_mutations(ro_port, "read_only", results),
        ),
        # brix_data_substreams merges to ON, so the DOCUMENTED gateway is the
        # one that accepts a secondary channel; the extra posture is the
        # explicit off.
        (
            "bound stream (default)",
            lambda: check_bound_stream(
                ro_port, "read_only", substreams=True, results=results
            ),
        ),
        (
            "bound stream (substreams off)",
            lambda: check_bound_stream(
                sub_port, "read_only+substreams off", substreams=False, results=results
            ),
        ),
        (
            "signed mutation",
            lambda: check_signed_mutation(ro_port, "read_only", results),
        ),
        ("query subcodes", lambda: check_query_subcodes(ro_port, "read_only", results)),
        (
            "session opcodes",
            lambda: check_session_ops_cannot_lift_the_gate(
                ro_port, "read_only", results
            ),
        ),
        ("path shapes", lambda: check_path_shapes(ro_port, "read_only", results)),
        ("mutation storm", lambda: check_mutation_storm(ro_port, "read_only", results)),
        (
            "reload",
            lambda: check_reload_persistence(ro_prefix, ro_port, "read_only", results),
        ),
    )
    for name, family in families:
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(export_root)
        family()
        check_integrity(
            f"read_only: origin after {name}", origin_root, origin_before, results
        )
        check_integrity(
            f"read_only: gateway export after {name}",
            export_root,
            export_before,
            results,
            allow_server_owned=True,
        )

    # The public posture gets the mutation battery too, bracketed against ITS
    # own export: brix_read_only_public reaches the write gates only through the
    # implication applied in the config finaliser, so it has to be proven on the
    # wire and not assumed from the plain read-only instance's result rows.
    for name, family in (
        (
            "public introspection",
            lambda: check_public_mode_restricts_introspection(
                pub_port, ro_port, results
            ),
        ),
        (
            "public read surface",
            lambda: check_public_mode_still_serves_data(pub_port, results),
        ),
        (
            "public qconfig filtering",
            lambda: check_public_mode_qconfig_is_filtered_per_key(
                pub_port, ro_port, results
            ),
        ),
        (
            "public readv tuning",
            lambda: check_public_mode_readv_tuning_survives(pub_port, results),
        ),
        (
            "public mutations",
            lambda: check_public_mode_is_still_read_only(pub_port, results),
        ),
    ):
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(pub_export)
        family()
        check_integrity(
            f"read_only_public: origin after {name}",
            origin_root,
            origin_before,
            results,
        )
        check_integrity(
            f"read_only_public: gateway export after {name}",
            pub_export,
            export_before,
            results,
            allow_server_owned=True,
        )

    check_manager_mode_is_refused_at_config_time(base, nginx_bin, results)
    check_read_surface_intact(ro_port, "read_only", results)
    check_read_surface_intact(pub_port, "read_only_public", results)
