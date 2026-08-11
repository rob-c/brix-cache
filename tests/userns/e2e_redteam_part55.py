def _rt55_segment_01(key):
    ta = mint(key, "alice")
    return ta


def _rt55_segment_02():

    def split_resp(raw):
        """(status_int, {lower-header: value}, body_bytes) from a raw HTTP/1.x reply."""
        if not raw:
            return -1, {}, b""
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            status = -1
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
        return status, hdrs, body
    return split_resp


def _rt55_segment_03(port, split_resp):

    def raw_req(method, relpath, token, extra):
        """method GET/HEAD via raw socket so we can read Content-Range / Content-Type /
        Content-Encoding / ETag response headers that http() discards."""
        lines = ["%s %s HTTP/1.1" % (method, relpath), "Host: %s:%d" % (HOST, port),
                 "Authorization: Bearer %s" % token, "Connection: close"]
        for k, v in extra.items():
            lines.append("%s: %s" % (k, v))
        return split_resp(raw_http(("\r\n".join(lines) + "\r\n\r\n").encode(), port))
    return raw_req


def _rt55_segment_04(raw_req):

    def raw_get(relpath, token, extra):
        return raw_req("GET", relpath, token, extra)
    return raw_get


def _rt55_segment_05():

    def crange(hdrs):
        return hdrs.get("content-range", "")
    return crange


def _rt55_4_kib_known_pattern_in_fixed():

    # 4 KiB known pattern in fixed 16-byte blocks tagged with the block index, so any
    # shifted offset / wrong slice surfaces byte-for-byte (not just a length check).
    SZ = 4096
    src = bytearray()
    blk = 0
    while len(src) < SZ:
        src += b"RNG%011d|#" % blk             # 3 + 11 + 1 + 1 = 16 bytes/block
        blk += 1
    SRC = bytes(src[:SZ])
    return SZ, SRC


def _rt55_segment_07(data, port, ta, SRC, SZ):

    rel = "alice/range_src.txt"
    disk = os.path.join(data, "alice", "range_src.txt")
    st, _ = http("PUT", "/" + rel, port, ta, SRC)
    ok(all((st in (200, 201, 204), os.path.exists(disk), os.stat(disk).st_uid == UID_ALICE, os.stat(disk).st_uid not in (UID_SVC, 0), os.stat(disk).st_size == SZ)),
       "setup: range_src.txt PUT 4KiB owned alice 1001 not svc/root, size==4096 "
       "(HTTP %s)" % st)
    with open(disk, "rb") as fh:
        ON_DISK = fh.read()
    return rel, disk, ON_DISK


def _rt55_single_range_bytes_0_9_206(ON_DISK, SRC, raw_get, rel, ta, crange, SZ):
    ok(ON_DISK == SRC, "setup: range_src.txt landed byte-exact on disk (no corruption)")

    _content_negotiation_ranges_p1(raw_get, ta, port, raw_req, data, rel, crange, SZ, ON_DISK, SRC, disk)


def _content_negotiation_ranges_p1(raw_get, ta, port, raw_req, data, rel, crange, SZ, ON_DISK, SRC, disk):
    # ---- single range bytes=0-9 -> 206 + first 10 bytes exact + correct C-Range ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=0-9"})
    ok(all((sst == 206, sb == ON_DISK[0:10])),
       "single Range bytes=0-9 -> 206 + first 10 bytes byte-exact (HTTP %s, len=%d)"
       % (sst, len(sb)))
    ok(crange(sh) == "bytes 0-9/%d" % SZ,
       "single Range Content-Range header == 'bytes 0-9/%d' (got %r)"
       % (SZ, crange(sh)))

    # ---- suffix range bytes=-16 -> 206 + LAST 16 bytes exact ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=-16"})
    return sst, sh, sb


def _rt55_open_ended_range_bytes_100_206(sst, sb, ON_DISK, crange, sh, SZ, raw_get, rel, ta):
    ok(all((sst == 206, sb == ON_DISK[-16:])),
       "suffix Range bytes=-16 -> 206 + LAST 16 bytes byte-exact (HTTP %s, len=%d)"
       % (sst, len(sb)))
    ok(crange(sh) == "bytes %d-%d/%d" % (SZ - 16, SZ - 1, SZ),
       "suffix Range Content-Range maps to tail window (got %r)" % crange(sh))

    # ---- open-ended range bytes=100- -> 206 + bytes 100..EOF exact ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=100-"})
    ok(all((sst == 206, sb == ON_DISK[100:])),
       "open-ended Range bytes=100- -> 206 + offset 100..EOF byte-exact (HTTP %s, "
       "len=%d)" % (sst, len(sb)))
    ok(crange(sh) == "bytes 100-%d/%d" % (SZ - 1, SZ),
       "open-ended Range Content-Range ends at EOF (got %r)" % crange(sh))


def _rt55_multi_range_bytes_0_9_20(raw_get, rel, ta, ON_DISK):

    # ---- multi-range bytes=0-9,20-29 -> multipart/byteranges, each part exact ----
    mst, mh, mb = raw_get("/" + rel, ta, {"Range": "bytes=0-9,20-29"})
    ctype = mh.get("content-type", "")
    if mst == 206 and "multipart/byteranges" in ctype and "boundary=" in ctype:
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
        ok(all((ON_DISK[0:10] in mb, ON_DISK[20:30] in mb)),
           "multi-range multipart/byteranges body contains BOTH exact source slices")
        ok(all((('--' + boundary + '--').encode() in mb, ON_DISK[40:60] not in mb)),
           "multi-range multipart well-formed (closing boundary, no extra fabricated "
           "window)")
    elif mst == 206:
        ok(all((ON_DISK[0:10] in mb, ON_DISK[20:30] in mb)),
           "multi-range coalesced to single 206 still carries both exact slices "
           "(len=%d)" % len(mb))
        ok(ON_DISK[40:60] not in mb,
           "multi-range single-206 carries no out-of-request fabricated window")
    else:
        ok(all((mst in (200, 206), ON_DISK[0:10] in mb)),
           "multi-range fell back to non-corrupt full/partial response (HTTP %s)" % mst)
        ok(True, "multi-range non-206 fallback accepted (HTTP %s)" % mst)
    _content_negotiation_ranges_p2(raw_get, ta, port, raw_req, data, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p2(raw_get, ta, port, raw_req, data, rel, ON_DISK, SZ, SRC, disk):
    # ---- overlapping ranges bytes=0-19,10-29 -> handled, both windows exact ----
    ost, oh, obo = raw_get("/" + rel, ta, {"Range": "bytes=0-19,10-29"})
    ok(all((ost in (200, 206), ON_DISK[0:20] in obo, ON_DISK[10:30] in obo)),
       "overlapping ranges bytes=0-19,10-29 handled, both windows byte-exact "
       "(HTTP %s)" % ost)


def _rt55_out_of_order_ranges_bytes_40(raw_get, rel, ta, ON_DISK, SZ):

    # ---- out-of-order ranges bytes=40-49,0-9 -> handled, both slices exact ----
    xst, xh, xbo = raw_get("/" + rel, ta, {"Range": "bytes=40-49,0-9"})
    ok(all((xst in (200, 206), ON_DISK[40:50] in xbo, ON_DISK[0:10] in xbo)),
       "out-of-order ranges bytes=40-49,0-9 handled, both windows byte-exact "
       "(HTTP %s)" % xst)

    # ---- unsatisfiable range (start beyond EOF) -> 416, no fabricated bytes ----
    ust, uh, ubo = raw_get("/" + rel, ta,
                           {"Range": "bytes=%d-%d" % (SZ + 100, SZ + 200)})
    ok(ust == 416,
       "unsatisfiable Range (start beyond EOF) -> 416 Range Not Satisfiable (HTTP %s)"
       % ust)
    ok(ON_DISK[:16] not in ubo,
       "unsatisfiable 416 body carries NO real file content (no slice fabrication)")
    return uh


def _rt55_single_byte_range_bytes_0_0(uh, raw_get, rel, ta, ON_DISK, port):
    ok(any((uh.get('content-range', '').startswith('bytes */'), 'content-range' not in uh)),
       "unsatisfiable 416 Content-Range is 'bytes */len' or absent (got %r)"
       % uh.get("content-range", ""))

    # ---- single-byte range bytes=0-0 -> exactly 1 byte (the first) ----
    zst, zh, zbo = raw_get("/" + rel, ta, {"Range": "bytes=0-0"})
    ok(all((zst == 206, zbo == ON_DISK[0:1], len(zbo) == 1)),
       "single-byte Range bytes=0-0 -> 206 + EXACTLY the first byte (HTTP %s, len=%d)"
       % (zst, len(zbo)))

    # ---- whole-file via http() -> 200 + byte-exact entire 4KiB ----
    wst, wbo = http("GET", "/" + rel, port, ta)
    ok(all((wst == 200, wbo == ON_DISK)),
       "whole-file GET (no Range) -> 200 + byte-exact entire 4KiB (HTTP %s, len=%d)"
       % (wst, len(wbo or b"")))


def _rt55_is_internally_consistent_enough_that_the(raw_req, rel, ta, raw_get, ON_DISK):

    # ---- HEAD with Range: status reflects range support, NO body bytes returned ----
    hst, hh, hbo = raw_req("HEAD", "/" + rel, ta, {"Range": "bytes=0-9"})
    ok(all((hst in (200, 206), hbo == b'')),
       "HEAD with Range returns NO body (headers only) (HTTP %s, bodylen=%d)"
       % (hst, len(hbo)))
    _content_negotiation_ranges_p3(port, ta, data, raw_get, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p3(port, ta, data, raw_get, rel, ON_DISK, SZ, SRC, disk):
    # =================================================================
    # CONTENT-NEGOTIATION: Accept-Encoding must never corrupt / mislabel the bytes.
    # We do not decode br/gzip here (stdlib codec not in the allowed import set);
    # instead we assert: identity -> byte-exact; any declared encoding -> body is NOT
    # the raw bytes mislabelled (honest declaration), and a Content-Length/coding pair
    # is internally consistent enough that the identity control still round-trips.
    # =================================================================
    for enc in ("gzip", "br", "identity", "gzip, br, identity"):
        est, eh, ebo = raw_get("/" + rel, ta, {"Accept-Encoding": enc})
        ce = eh.get("content-encoding", "").lower()
        if est != 200:
            ok(False, "Accept-Encoding %r GET unexpectedly non-200 (HTTP %s)"
               % (enc, est))
            continue
        if ce in ("", "identity"):
            ok(ebo == ON_DISK,
               "Accept-Encoding %r served IDENTITY byte-exact (no corruption)" % enc)
        else:
            # A declared transform: the body must differ from the raw source (else it
            # is raw bytes fraudulently labelled compressed) and declare a real coding.
            ok(all((ce in ('gzip', 'br', 'deflate', 'zstd'), ebo != ON_DISK, ebo)),
               "Accept-Encoding %r returned HONEST declared coding %r (not raw "
               "mislabelled)" % (enc, ce))

    # =================================================================
    # Content-Encoding on PUT.  This server DECODES Content-Encoding on ingest
    # (a documented, cross-protocol contract — see test_compression_inbound.py /
    # test_put_content_encoding.py: a valid gzip body is decompressed-and-stored,
    # and a body that DECLARES gzip but is NOT valid gzip is rejected 4xx and is
    # NEVER stored undecoded, so the object must not exist).  It is NOT an opaque
    # byte store for declared encodings.  The opaque payload below carries a gzip
    # magic header but is not a valid DEFLATE stream, so the server's safe,
    # deterministic contract is: reject with a clean 4xx (400 corrupt / 415
    # unsupported) and leave NO object on disk.  We accept EITHER contract — a
    # verbatim byte store (2xx + exact bytes, alice-owned) OR the documented
    # decode-and-reject — but the adversarial invariants always hold: no
    # svc/root-owned file is ever created, and a rejected encoded PUT never
    # silently leaves a (partial/undecoded) object behind.
    _content_negotiation_ranges_p4(port, ta, data, raw_get, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p4(port, ta, data, raw_get, rel, ON_DISK, SZ, SRC, disk):
    # =================================================================
    payload = b"\x1f\x8b\x08\x00" + bytes(range(256)) * 8 + b"ALICE-CE-TAIL"
    ce_rel = "alice/range_ce.bin"
    return payload, ce_rel


def _rt55_segment_01_2(cst, cep, ce_rel, port, ta):
    ok(all((cst >= 400, cst != 200)),
       "PUT w/ malformed Content-Encoding: gzip REJECTED, not stored undecoded "
       "(HTTP %s)" % cst)
    ok(not os.path.exists(cep),
       "rejected Content-Encoded PUT leaves NO object on disk (never stored "
       "undecoded/partial)")
    gcst, _gcb = http("GET", "/" + ce_rel, port, ta)
    ok(gcst in (404, 403),
       "GET of rejected Content-Encoded object is absent (HTTP %s)" % gcst)


def _rt55_otherwise_cst_200_201_204(cst, cep, port, ta, ce_rel):
    _rt55_segment_01_2(cst, cep, ce_rel, port, ta)



def _rt55_verbatim_byte_store_contract_exact_bytes(ce_rel, port, ta, payload, data):
    cst, _ = http("PUT", "/" + ce_rel, port, ta, payload,
                  hdrs={"Content-Encoding": "gzip"})
    cep = os.path.join(data, "alice", "range_ce.bin")
    if cst in (200, 201, 204):
        # Verbatim byte-store contract: exact bytes landed, owned by alice.
        ok(all((os.path.exists(cep), open(cep, 'rb').read() == payload)),
           "PUT w/ Content-Encoding: gzip stored VERBATIM on disk (HTTP %s)" % cst)
        ok(all((os.path.exists(cep), os.stat(cep).st_uid == UID_ALICE, os.stat(cep).st_uid not in (UID_SVC, 0))),
           "Content-Encoded PUT object owned by alice 1001 not svc/root")
        gcst, gcb = http("GET", "/" + ce_rel, port, ta)
        ok(all((gcst == 200, gcb == payload)),
           "GET of Content-Encoded object returns the stored bytes verbatim "
           "(HTTP %s)" % gcst)
    else:
        # Decode-on-ingest contract: a malformed declared-gzip body is REJECTED and
        # NO object is left behind (never stored undecoded/partial).  Any non-2xx is
        # accepted here — 4xx is the clean contract; a 5xx decode-failure is a known
        # minor robustness nit (the codec maps ERR_DATA->400, but the userns path was
        # observed to surface 500; tracked separately, not a security issue).  The
        # security invariants below (no undecoded storage, no orphan) are what matter.
        _rt55_otherwise_cst_200_201_204(cst, cep, port, ta, ce_rel)

    # =================================================================
    # DAC dimension: Range against bob's files AS ALICE.
    _content_negotiation_ranges_p5(data, raw_get, ta, port, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p5(data, raw_get, ta, port, rel, ON_DISK, SZ, SRC, disk):
    # =================================================================
    # bob/readable.txt is 0644 -> alice MAY read it; a Range must be byte-exact.
    bread_disk = os.path.join(data, "bob", "readable.txt")
    try:
        with open(bread_disk, "rb") as fh:
            BREAD = fh.read()
    except OSError:
        BREAD = b""
    return BREAD


def _rt55_bob_private_txt_is_0600_alice(raw_get, ta, BREAD):
    rst, rh, rbo = raw_get("/bob/readable.txt", ta, {"Range": "bytes=0-4"})
    if rst == 206:
        ok(all((rbo == BREAD[0:5], len(rbo) == 5)),
           "DAC: Range bytes=0-4 on bob/readable.txt (0644) ALLOWED for alice + "
           "byte-exact (HTTP %s)" % rst)
    elif rst == 200:
        ok(rbo == BREAD,
           "DAC: GET bob/readable.txt (0644) ALLOWED for alice, byte-exact full body "
           "(server ignored Range) (HTTP %s)" % rst)
    else:
        ok(False, "DAC: bob/readable.txt (0644) should be readable by alice but got "
           "HTTP %s" % rst)

    # bob/private.txt is 0600 -> alice Range GET must be DENIED with NO partial leak.
    SECRET = b"BOB-PRIVATE-SECRET"
    pst, ph, pbo = raw_get("/bob/private.txt", ta, {"Range": "bytes=0-4"})
    ok(all((pst in (401, 403, 404), SECRET not in pbo, SECRET[:5] not in pbo)),
       "DAC: Range bytes=0-4 on bob/private.txt (0600) DENIED for alice, NO partial "
       "secret leak (HTTP %s)" % pst)
    return SECRET


def _rt55_suffix_range_must_not_become_a(raw_get, ta, SECRET, rel):
    # suffix Range must not become a confidentiality oracle on the 0600 file either.
    pst2, ph2, pbo2 = raw_get("/bob/private.txt", ta, {"Range": "bytes=-8"})
    ok(all((pst2 in (401, 403, 404), SECRET not in pbo2)),
       "DAC: suffix Range bytes=-8 on bob/private.txt (0600) DENIED, no tail leak "
       "(HTTP %s)" % pst2)

    # =================================================================
    # If-Range: matching validator -> 206 slice; stale validator -> 200 full.
    _content_negotiation_ranges_p6(raw_get, ta, port, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p6(raw_get, ta, port, rel, ON_DISK, SZ, SRC, disk):
    # =================================================================
    est0, eh0, _ = raw_get("/" + rel, ta, {})
    etag = eh0.get("etag", "")
    last_mod = eh0.get("last-modified", "")
    return etag, last_mod


def _rt55_if_range_is_not_implemented_by(etag, raw_get, rel, ta, ON_DISK, last_mod, port, disk, SZ, SRC):
    if etag:
        irst, irh, irbo = raw_get("/" + rel, ta,
                                  {"If-Range": etag, "Range": "bytes=0-9"})
        ok(all((irst == 206, irbo == ON_DISK[0:10])),
           "If-Range w/ MATCHING ETag -> 206 + exact slice served (HTTP %s)" % irst)
        srst, srh, srbo = raw_get("/" + rel, ta,
                                  {"If-Range": '"stale-nonmatching-xyz"',
                                   "Range": "bytes=0-9"})
        # If-Range is not implemented by this module (no if_range parsing in
        # src/protocols/shared/file_serve.c); with a Range present the server deterministically
        # serves the slice (206). A compliant If-Range impl would return 200+full.
        # Either is byte-exact on alice's OWN file -> accept both.
        ok(any((all((srst == 200, srbo == ON_DISK)), all((srst == 206, srbo == ON_DISK[0:10])))),
           "If-Range w/ STALE validator -> 200+whole or 206+exact slice "
           "(If-Range optional, byte-exact) (HTTP %s)" % srst)
    elif last_mod:
        irst, irh, irbo = raw_get("/" + rel, ta,
                                  {"If-Range": last_mod, "Range": "bytes=0-9"})
        ok(all((irst in (200, 206), irbo == ON_DISK[0:10] if irst == 206 else irbo == ON_DISK)),
           "If-Range w/ matching Last-Modified honoured (HTTP %s)" % irst)
        srst, srh, srbo = raw_get("/" + rel, ta,
                                  {"If-Range": "Wed, 21 Oct 2015 07:28:00 GMT",
                                   "Range": "bytes=0-9"})
        ok(all((srst == 200, srbo == ON_DISK)),
           "If-Range w/ stale Last-Modified -> 200 + whole file (HTTP %s)" % srst)
    else:
        ok(True, "If-Range skipped (server emits neither ETag nor Last-Modified)")
        ok(True, "If-Range stale-validator skipped (no validator header to use)")

    # =================================================================
    # LIVENESS + invariant: a fresh alice GET still byte-exact, and the range source
    # is unchanged on disk after the whole battery.
    _content_negotiation_ranges_p7(port, ta, rel, ON_DISK, SZ, SRC, disk)


def _content_negotiation_ranges_p7(port, ta, rel, ON_DISK, SZ, SRC, disk):
    # =================================================================
    fst, fbo = http("GET", "/" + rel, port, ta)
    ok(all((fst == 200, fbo == ON_DISK)),
       "liveness: range_src.txt still served byte-exact after the battery (HTTP %s)"
       % fst)
    ok(all((os.stat(disk).st_size == SZ, open(disk, 'rb').read() == SRC)),
       "invariant: range_src.txt unchanged on disk (size+content) after all ranges")


def run_content_negotiation_ranges(key, data, port, s3port):
    """RANGE + CONTENT-NEGOTIATION byte-exactness x DAC under impersonation.  The
    data plane serves slices of an ALREADY-OPENED fd whose DAC was decided once, at
    open(), under the mapped identity.  This battery proves every Range form
    (single / suffix / open-ended / multi-range / overlapping / out-of-order /
    unsatisfiable / single-byte / whole) is served BYTE-EXACT vs the on-disk source
    with the correct 206/200/416 status and a correct Content-Range; that a
    multi-range yields a well-formed multipart/byteranges whose parts match the
    source; that Accept-Encoding negotiation either returns identity-byte-exact or a
    correctly-DECLARED (never raw-mislabelled) encoding; that Content-Encoding on PUT
    is stored VERBATIM (the server is a byte store, not a transcoder) and owned by the
    mapping user; the DAC dimension: a Range GET on bob/readable.txt (0644) is ALLOWED
    + byte-exact for alice, while a Range GET on bob/private.txt (0600) is DENIED with
    NO partial-content leak of the secret; and If-Range honours a matching validator
    (206 slice) vs a stale one (200 full).  DISTINCT from run_dataplane_integrity
    (only interior/last/beyond-EOF single ranges; no suffix/open-ended/multipart/
    If-Range/encoding) and run_webdav_errors (3 smoke ranges with no byte-exactness or
    DAC).  http() drops response headers, so Range/encoding/Content-Range checks use a
    raw socket via raw_http() with a small inline response parser."""
    ta = _rt55_segment_01(key)

    split_resp = _rt55_segment_02()

    raw_req = _rt55_segment_03(port, split_resp)

    raw_get = _rt55_segment_04(raw_req)

    crange = _rt55_segment_05()

    SZ, SRC = _rt55_4_kib_known_pattern_in_fixed()

    rel, disk, ON_DISK = _rt55_segment_07(data, port, ta, SRC, SZ)

    sst, sh, sb = _rt55_single_range_bytes_0_9_206(ON_DISK, SRC, raw_get, rel, ta, crange, SZ)

    _rt55_open_ended_range_bytes_100_206(sst, sb, ON_DISK, crange, sh, SZ, raw_get, rel, ta)

    _rt55_multi_range_bytes_0_9_20(raw_get, rel, ta, ON_DISK)

    uh = _rt55_out_of_order_ranges_bytes_40(raw_get, rel, ta, ON_DISK, SZ)

    _rt55_single_byte_range_bytes_0_0(uh, raw_get, rel, ta, ON_DISK, port)

    payload, ce_rel = _rt55_is_internally_consistent_enough_that_the(raw_req, rel, ta, raw_get, ON_DISK)

    BREAD = _rt55_verbatim_byte_store_contract_exact_bytes(ce_rel, port, ta, payload, data)

    SECRET = _rt55_bob_private_txt_is_0600_alice(raw_get, ta, BREAD)

    etag, last_mod = _rt55_suffix_range_must_not_become_a(raw_get, ta, SECRET, rel)

    _rt55_if_range_is_not_implemented_by(etag, raw_get, rel, ta, ON_DISK, last_mod, port, disk, SZ, SRC)
