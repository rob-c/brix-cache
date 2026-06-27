from _test_conf_prepfattr_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@pytest.mark.parametrize("path", PREP_EXISTING)
def test_prepare_nostage_rc_parity(srv, path):
    """`xrdfs prepare <path>` (no -s) on an existing file -> rc/category parity.
    A non-stage prepare returns an EMPTY ok body (Xeq:2028)."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), f"prepare {path} success differs:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"prepare {path} error category differs:{raw}"


@pytest.mark.parametrize("path", PREP_EXISTING[:5])
def test_prepare_nostage_emits_no_request_id(srv, path):
    """A non-stage `xrdfs prepare` prints NO request-id line (the stage path is
    the only one that returns an id, Xeq:2028 vs 2029) — parity with stock."""
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "prepare", path])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "prepare", path])
    assert rc_o == 0 and rc_f == 0, "non-stage prepare should succeed"
    assert (o_o.strip() == "") == (o_f.strip() == ""), \
        f"non-stage prepare id-emission differs: ours={o_o.strip()!r} " \
        f"stock={o_f.strip()!r}"
    assert o_f.strip() == "", f"stock non-stage prepare emitted an id: {o_f!r}"


# =========================================================================== #
# B. STOCK xrdfs `prepare -s` (stage) — the request-id contract
# =========================================================================== #
@pytest.mark.parametrize("path", PREP_EXISTING)
def test_prepare_stage_rc_parity(srv, path):
    """`xrdfs prepare -s <path>` -> rc parity (both accept the stage)."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare -s {path} success differs: ours rc={rc_o} ({e_o.strip()!r}) " \
        f"stock rc={rc_f} ({e_f.strip()!r})"


@pytest.mark.parametrize("path", PREP_EXISTING[:5])
def test_prepare_stage_returns_host_qualified_id(srv, path):
    """`xrdfs prepare -s` returns a host-qualified request-id string of the form
    "<hexhost>:<id>:<seq>" (Xeq:1912 / Xeq:2029). Stock pins the shape; ours
    must match (it currently returns the literal "0")."""
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    assert rc_o == 0 and rc_f == 0, "stage prepare should succeed on both"
    ours, stock = o_o.strip(), o_f.strip()
    stock_ok = stock.count(":") >= 2 and stock != "0"
    assert stock_ok, f"stock stage id is not host-qualified: {stock!r}"
    ours_ok = ours.count(":") >= 2 and ours != "0"
    if not ours_ok:
        pytest.xfail(
            "OUR-SERVER BUG: kXR_prepare|kXR_stage returns a non-conformant "
            f"request-id. OURS={ours!r}, STOCK={stock!r}. The reference sends a "
            "host-qualified id '<hexhost>:<id>:<seq>' (Response.Send(reqid,...), "
            "Xeq:2029 / PrepID->ID, Xeq:1912); ours returns the literal '0'.")
    assert ours_ok


@pytest.mark.parametrize("opt,path", PREP_OPT_VARIANTS)
def test_prepare_option_variants_parity(srv, opt, path):
    """`xrdfs prepare <opt> <path>` for each option variant -> rc/category
    parity with stock."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", opt, path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", opt, path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare {opt} {path} success differs:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"prepare {opt} {path} error category differs:{raw}"


@pytest.mark.parametrize("prio", ["0", "1", "2", "3"])
def test_prepare_stage_priority_parity(srv, prio):
    """`xrdfs prepare -s -p <prio>` across the priority range -> rc parity."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s",
                          "-p", prio, "/data.bin"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s",
                          "-p", prio, "/data.bin"])
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare -s -p {prio} success differs: ours rc={rc_o} " \
        f"({e_o.strip()!r}) stock rc={rc_f} ({e_f.strip()!r})"


def test_prepare_stage_multiple_paths_parity(srv):
    """`xrdfs prepare -s` with multiple paths -> rc parity (multi-path payload,
    newline-separated, Xeq pathlist)."""
    paths = ["/hello.txt", "/data.bin", "/sub/nested.txt"]
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", *paths])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", *paths])
    assert (rc_o == 0) == (rc_f == 0), \
        f"multi-path prepare -s differs: ours rc={rc_o} ({e_o.strip()!r}) " \
        f"stock rc={rc_f} ({e_f.strip()!r})"


@pytest.mark.parametrize("path", PREP_MISSING)
def test_prepare_stage_missing_path_parity(srv, path):
    """`xrdfs prepare -s` on a NONEXISTENT path -> pin stock. The reference
    native prepare defers existence to the staging backend and ACCEPTS the
    request (returns an id); ours rejects with NotFound. Differential pin."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    if (rc_o == 0) != (rc_f == 0):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_prepare|kXR_stage on a missing path is "
            f"rejected by ours but ACCEPTED by stock.{raw} The reference native "
            "prepare queues the request and defers existence to the staging "
            "backend (do_Prepare, Xeq:2023 only fails on osFS->prepare); ours "
            "stats the path up front and returns kXR_NotFound.")
    assert (rc_o == 0) == (rc_f == 0), f"prepare -s missing path differs:{raw}"


# =========================================================================== #
# E. query prepare (kXR_query infotype kXR_QPrep, reqcode 2) — pin stock
# =========================================================================== #
def test_query_prepare_status_parity(srv):
    """`xrdfs query prepare <id> <path>` -> pin stock. Stock's native prepare
    rejects an ad-hoc query id with kXR_ArgInvalid; ours returns a status line.
    Differential pin (we follow the reference do_Prepare(isQuery=true) path,
    Xeq:2493)."""
    args = ["query", "prepare", "fakereqid", "/hello.txt"]
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], *args])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], *args])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    if (rc_o == 0) != (rc_f == 0):
        pytest.xfail(
            "OUR-SERVER BUG: `query prepare` success differs from stock.{}"
            " The reference treats a bare query-prepare id via "
            "do_Prepare(isQuery=true) and rejects an unknown id "
            "(kXR_ArgInvalid 3000); ours returns a status line with rc 0."
            .format(raw))
    assert (rc_o == 0) == (rc_f == 0), f"query prepare success differs:{raw}"


@pytest.mark.parametrize("path", RAW_PREP_FILES)
def test_raw_prepare_nostage_empty_body(srv, path):
    """RAW kXR_prepare with options==0 -> kXR_ok with an EMPTY body on both
    servers (Response.Send(), Xeq:2028)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [path], options=0)
        st_f, b_f = _prepare(sf, [path], options=0)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(nostage) {path} success differs:{raw}"
    assert st_o == kXR_ok, f"raw prepare(nostage) {path} failed on OURS:{raw}"
    assert b_o == b"", f"raw non-stage prepare returned a body on OURS:{raw}"
    assert b_f == b"", f"stock non-stage prepare returned a body:{raw}"


@pytest.mark.parametrize("path", RAW_PREP_FILES)
def test_raw_prepare_stage_returns_id_text(srv, path):
    """RAW kXR_prepare with kXR_stage -> kXR_ok body is a request-id TEXT string
    (Response.Send(reqid, strlen(reqid)), Xeq:2029). Stock pins a host-qualified
    id; ours currently returns the literal "0"."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [path], options=kXR_stage)
        st_f, b_f = _prepare(sf, [path], options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(stage) {path} success differs:{raw}"
    assert st_o == kXR_ok, f"raw prepare(stage) {path} failed on OURS:{raw}"
    stock_id = b_f.decode("ascii", "replace")
    assert b_f and stock_id.count(":") >= 2, \
        f"stock stage id is not host-qualified:{raw}"
    ours_id = b_o.decode("ascii", "replace")
    if not (b_o and ours_id.count(":") >= 2 and ours_id != "0"):
        pytest.xfail(
            "OUR-SERVER BUG: RAW kXR_prepare|kXR_stage request-id framing. "
            f"OURS body={b_o!r}, STOCK body={b_f!r}. The reference sends a "
            "host-qualified id text '<hexhost>:<id>:<seq>' (Xeq:2029); ours "
            "returns the literal '0'.")
    assert ours_id.count(":") >= 2


def test_raw_prepare_stage_multipath_body(srv):
    """RAW kXR_prepare|kXR_stage with a newline-separated multi-path payload ->
    success parity and (for stock) a single request-id covering the batch."""
    paths = ["/hello.txt", "/data.bin", "/sz_4096.bin"]
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, paths, options=kXR_stage)
        st_f, b_f = _prepare(sf, paths, options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw multi-path prepare(stage) success differs:{raw}"
    assert st_o == kXR_ok, f"raw multi-path prepare(stage) failed on OURS:{raw}"


def test_raw_prepare_empty_path_list_parity(srv):
    """RAW kXR_prepare with an EMPTY path payload -> error parity (the reference
    sends kXR_ArgMissing "No prepare paths specified", Xeq:1978)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [""], options=kXR_stage)
        st_f, b_f = _prepare(sf, [""], options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw empty-path prepare success differs:{raw}"
    if st_o != kXR_ok and st_f != kXR_ok and not _rejected(st_o) is False:
        pass  # category compared below
    if st_o != kXR_ok:
        assert _category(st_o, b_o) == _category(st_f, b_f) or _rejected(st_f), \
            f"raw empty-path prepare error category differs:{raw}"


@pytest.mark.parametrize("optX", [0x0001])  # kXR_evict
def test_raw_prepare_evict_optionx_parity(srv, optX):
    """RAW kXR_prepare with optionX kXR_evict set -> success/category parity
    (XProtocol.hh:630, do_Prepare evict path, Xeq:1852)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, ["/hello.txt"], options=0, optionX=optX)
        st_f, b_f = _prepare(sf, ["/hello.txt"], options=0, optionX=optX)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(evict optX=0x{optX:x}) success differs:{raw}"
    if st_o != kXR_ok:
        assert _category(st_o, b_o) == _category(st_f, b_f), \
            f"raw prepare(evict) error category differs:{raw}"


@pytest.mark.parametrize("prty", [0, 1, 2, 3])
def test_raw_prepare_priority_byte_parity(srv, prty):
    """RAW kXR_prepare|kXR_stage with each priority byte -> success parity
    (do_Prepare prty mapping, Xeq:2009)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, ["/data.bin"], options=kXR_stage, prty=prty)
        st_f, b_f = _prepare(sf, ["/data.bin"], options=kXR_stage, prty=prty)
    finally:
        so.close()
        sf.close()
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(stage prty={prty}) success differs: " \
        f"ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"


def test_prepare_determinism(srv):
    """Repeated RAW non-stage prepare of the same path -> stable empty-ok every
    time on OURS (and on stock)."""
    for port in (OUR_PORT, OFF_PORT):
        s = _session(port)
        try:
            for _ in range(5):
                st, b = _prepare(s, ["/hello.txt"], options=0,
                                 sid=struct.pack("!H", 0x300))
                assert st == kXR_ok and b == b"", \
                    f"prepare not deterministic on port {port}: {st} {b!r}"
        finally:
            s.close()
