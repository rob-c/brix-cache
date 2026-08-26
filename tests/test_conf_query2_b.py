from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_query2_helpers")

pytestmark = pytest.mark.xdist_group("conf_query2_b")

def test_qxattr_raw_parity(srv):
    """Raw Qxattr (infotype=4) on /data.bin: OUR ok-category must match stock."""
    so, bo = raw_query(srv["our"], kXR_Qxattr, "/data.bin")
    sf, bf = raw_query(srv["off"], kXR_Qxattr, "/data.bin")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qxattr ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


def test_qxattr_not_arginvalid(srv):
    """Qxattr is a recognised reqcode (do_Query -> do_Qxattr); OUR server must
    not reject it as an invalid query type."""
    status, body = raw_query(srv["our"], kXR_Qxattr, "/data.bin")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qxattr as an invalid reqcode (BUG): {body!r}")


# =========================================================================== #
# 7. QUERY OPAQUE (Qopaque, infotype=16) — parity vs stock.                   #
# =========================================================================== #
def test_qopaque_raw_parity(srv):
    """Raw Qopaque (infotype=16): OUR ok/err-category must match stock (with no
    plugin both typically reject; do_Qopaque routes to FSctl PLUGIO)."""
    so, bo = raw_query(srv["our"], kXR_Qopaque, "anything")
    sf, bf = raw_query(srv["off"], kXR_Qopaque, "anything")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qopaque ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


# =========================================================================== #
# 8. QUERY PREPARE (Qprep, infotype=2) — do_Query -> do_Prepare(true).        #
# =========================================================================== #
def test_qprep_unknown_reqid_reference(srv):
    """Qprep (infotype=2) is a prepare-STATUS query -> do_Query routes it to
    do_Prepare(true). The reference (core XRootD, no plugin involved) tracks
    prepare request-ids and REJECTS a status query for a reqid it never issued
    ("Prepare requestid owned by an unknown server"). We pin OUR server to that
    reference: an unknown reqid must NOT be silently accepted as ok."""
    sf, bf = raw_query(srv["off"], kXR_QPrep, "reqid-0001")
    assert sf == kXR_error, (
        f"oracle: stock unexpectedly accepted an unknown prepare reqid: {bf!r}")
    so, bo = raw_query(srv["our"], kXR_QPrep, "reqid-0001")
    assert so == kXR_error, (
        f"OUR server accepted a Qprep status query for a reqid it never issued "
        f"(reference rejects it): status={so} {bo!r}")


def test_qprep_not_arginvalid(srv):
    """Qprep is a recognised reqcode; OUR server must not reject it as an
    invalid query TYPE (a content/arg error is acceptable, a type error is not)."""
    status, body = raw_query(srv["our"], kXR_QPrep, "reqid-xyz")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qprep as an invalid reqcode (BUG): {body!r}")


# =========================================================================== #
# 9. QUERY VISA (Qvisa, infotype=8) — do_Query has NO case for kXR_Qvisa, so   #
#    the reference falls through to the default and rejects it with kXR_error  #
#    "Invalid information query type code". Pin OUR server to that + diff.     #
# =========================================================================== #
def test_qvisa_rejected_as_invalid_type(srv):
    """do_Query() has no kXR_Qvisa case (it is commented out) -> the default
    branch returns kXR_error "Invalid information query type code". OUR server
    must likewise reject Qvisa as an invalid query type."""
    status, body = raw_query(srv["our"], kXR_Qvisa, b"")
    assert status == kXR_error, \
        f"OUR Qvisa not rejected (reference rejects it): status={status} {body!r}"


def test_qvisa_parity_with_stock(srv):
    """Differential: Qvisa rejection category must match stock (both kXR_error)."""
    so, _ = raw_query(srv["our"], kXR_Qvisa, b"")
    sf, _ = raw_query(srv["off"], kXR_Qvisa, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"Qvisa rejection category differs: our_err={so == kXR_error} "
        f"stock_err={sf == kXR_error}")


# =========================================================================== #
# 10. UNKNOWN REQCODE — an infotype with no do_Query case must be rejected     #
#     with kXR_error "Invalid information query type code" (do_Query default).  #
# =========================================================================== #
@pytest.mark.parametrize("bad", [0, 99, 1000, 0x7fff])
def test_unknown_reqcode_rejected(srv, bad):
    """An unrecognised infotype must be kXR_error on OUR server (do_Query
    default branch). 0/99/1000/0x7fff are not in the XQueryType enum."""
    status, body = raw_query(srv["our"], bad, b"")
    assert status == kXR_error, (
        f"OUR accepted unknown query reqcode {bad} (BUG): status={status} "
        f"{body!r}")


@pytest.mark.parametrize("bad", [0, 99, 1000])
def test_unknown_reqcode_parity(srv, bad):
    """Differential: an unknown reqcode is rejected on BOTH servers."""
    so, _ = raw_query(srv["our"], bad, b"")
    sf, _ = raw_query(srv["off"], bad, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"unknown reqcode {bad} rejection category differs: "
        f"our_err={so == kXR_error} stock_err={sf == kXR_error}")


# =========================================================================== #
# 11. EMPTY PAYLOAD — a query with dlen==0 on selected reqcodes.              #
#     Qconfig with no arg -> kXR_ArgMissing (an error) per do_Qconf; Qstats   #
#     with no arg defaults to "a" and succeeds (do_Query). Pin + diff.        #
# =========================================================================== #
def test_qconfig_empty_payload_rejected(srv):
    """do_Qconf rejects a missing argument (kXR_ArgMissing -> kXR_error). OUR
    server must reject an empty-payload Qconfig too."""
    status, body = raw_query(srv["our"], kXR_Qconfig, b"")
    assert status == kXR_error, (
        f"OUR Qconfig with empty payload not rejected (reference sends "
        f"kXR_ArgMissing): status={status} {body!r}")


def test_qconfig_empty_payload_parity(srv):
    """Differential: empty-payload Qconfig rejected on BOTH servers."""
    so, _ = raw_query(srv["our"], kXR_Qconfig, b"")
    sf, _ = raw_query(srv["off"], kXR_Qconfig, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"empty Qconfig rejection differs: our_err={so == kXR_error} "
        f"stock_err={sf == kXR_error}")


def test_qstats_empty_payload_defaults_to_all(srv):
    """do_Query passes "a" when dlen==0 for kXR_QStats; an empty-payload Qstats
    must therefore SUCCEED with a non-empty body on OUR server."""
    status, body = raw_query(srv["our"], kXR_QStats, b"")
    assert status == kXR_ok, (
        f"OUR empty-payload Qstats not ok (reference defaults to 'a'): "
        f"status={status} {body!r}")
    assert body.rstrip(b"\x00").strip() != b"", "OUR empty Qstats body empty"


def test_qcksum_empty_payload_parity(srv):
    """Differential: empty-payload Qcksum (no path) — OUR ok-category must match
    stock (both should reject a checksum with no path)."""
    so, _ = raw_query(srv["our"], kXR_Qcksum, b"")
    sf, _ = raw_query(srv["off"], kXR_Qcksum, b"")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"empty Qcksum ok-category differs: our_ok={so == kXR_ok} "
        f"stock_ok={sf == kXR_ok}")


# =========================================================================== #
# 12. DETERMINISM across reqcodes — the same raw query twice is byte-identical #
#     for the deterministic reqcodes (Qconfig value, Qcksum hex).             #
# =========================================================================== #
def test_determinism_qconfig_raw(srv):
    """Two identical raw Qconfig requests return byte-identical bodies."""
    _, b1 = raw_query(srv["our"], kXR_Qconfig, "bind_max version readv_iov_max")
    _, b2 = raw_query(srv["our"], kXR_Qconfig, "bind_max version readv_iov_max")
    assert b1 == b2, f"non-deterministic Qconfig body: {b1!r} then {b2!r}"


def test_determinism_qcksum_raw(srv):
    """Two identical raw Qcksum requests return the same checksum body."""
    _, b1 = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    _, b2 = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    h1 = b1.rstrip(b"\x00").split()[-1] if b1.split() else b""
    h2 = b2.rstrip(b"\x00").split()[-1] if b2.split() else b""
    assert h1 == h2 and h1 != b"", \
        f"non-deterministic raw Qcksum hex: {h1!r} then {h2!r}"


# =========================================================================== #
# 13. STREAMID ECHO — kXR_query response must echo the request streamid        #
#     verbatim (XrdXrootdResponse): a query reply is still a normal response.  #
# =========================================================================== #
def test_query_streamid_echoed_verbatim(srv):
    """The streamid in a kXR_query response is echoed verbatim (not swapped)."""
    sid = b"\xab\xcd"
    s = _session(srv["our"])
    try:
        arg = b"version"
        s.sendall(struct.pack("!2sHH14sI", sid, kXR_query, kXR_Qconfig,
                              b"\x00" * 14, len(arg)) + arg)
        rsid, status, _ = _resp(s)
        assert rsid == sid, f"query streamid not echoed verbatim: {rsid!r}"
        assert status == kXR_ok, f"query version not ok: {status}"
    finally:
        s.close()
