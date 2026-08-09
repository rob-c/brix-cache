from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cns_http_helpers")

def test_webdav_put_lands_in_manager_inventory(http_cluster):
    """success — a WebDAV PUT is reported with the size the server committed."""
    c = http_cluster
    key = _key()
    payload = b"webdav-put-payload-0123456789"

    r = requests.put(c.dav_url(f"/{key}"), data=payload, timeout=TIMEOUT)
    assert r.status_code in (200, 201, 204), (r.status_code, r.text[:200])

    # The size is the one the server PROBED after committing the staged temp,
    # not the Content-Length the client asserted.
    assert _poll_manager_size(c.mgr, f"/{key}", len(payload)) == len(payload)


def test_webdav_delete_retracts_from_manager(http_cluster):
    """success — a WebDAV DELETE evicts the entry the PUT created."""
    c = http_cluster
    key = _key()

    assert requests.put(c.dav_url(f"/{key}"), data=b"x",
                        timeout=TIMEOUT).status_code in (200, 201, 204)
    assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok

    assert requests.delete(c.dav_url(f"/{key}"),
                           timeout=TIMEOUT).status_code in (200, 204)
    assert _poll_manager(c.mgr, f"/{key}", want_ok=False) != kXR_ok


def test_webdav_mkcol_and_collection_delete(http_cluster):
    """success — MKCOL reports a DIRECTORY entry; deleting it retracts."""
    c = http_cluster
    key = _key()

    r = requests.request("MKCOL", c.dav_url(f"/{key}"), timeout=TIMEOUT)
    assert r.status_code == 201, (r.status_code, r.text[:200])
    assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok

    assert requests.delete(c.dav_url(f"/{key}"),
                           timeout=TIMEOUT).status_code in (200, 204)
    assert _poll_manager(c.mgr, f"/{key}", want_ok=False) != kXR_ok


def test_webdav_move_carries_the_entry(http_cluster):
    """success — MOVE emits ONE rename event: destination gains the observed
    size and the source goes in the same event, never a DEL/ADD pair that could
    arrive out of order."""
    c = http_cluster
    src, dst = _key(), _key()
    payload = b"webdav-move-payload-abcdefghij"

    assert requests.put(c.dav_url(f"/{src}"), data=payload,
                        timeout=TIMEOUT).status_code in (200, 201, 204)
    assert _poll_manager(c.mgr, f"/{src}", want_ok=True) == kXR_ok

    r = requests.request("MOVE", c.dav_url(f"/{src}"),
                         headers={"Destination": c.dav_url(f"/{dst}")},
                         timeout=TIMEOUT)
    assert r.status_code in (201, 204), (r.status_code, r.text[:200])

    assert _poll_manager_size(c.mgr, f"/{dst}", len(payload)) == len(payload)
    assert _poll_manager(c.mgr, f"/{src}", want_ok=False) != kXR_ok


def test_webdav_copy_adds_destination_and_keeps_source(http_cluster):
    """success — a COPY publishes a NEW object, so the manager gains the
    destination while the untouched source keeps its entry."""
    c = http_cluster
    src, dst = _key(), _key()
    payload = b"webdav-copy-payload-9876543210"

    assert requests.put(c.dav_url(f"/{src}"), data=payload,
                        timeout=TIMEOUT).status_code in (200, 201, 204)
    assert _poll_manager(c.mgr, f"/{src}", want_ok=True) == kXR_ok

    r = requests.request("COPY", c.dav_url(f"/{src}"),
                         headers={"Destination": c.dav_url(f"/{dst}")},
                         timeout=TIMEOUT)
    assert r.status_code in (201, 204), (r.status_code, r.text[:200])

    assert _poll_manager_size(c.mgr, f"/{dst}", len(payload)) == len(payload)
    assert _stat(c.mgr, f"/{src}")[0] == kXR_ok, "COPY must not retract the source"


def test_webdav_failed_delete_does_not_retract(http_cluster):
    """error — a DELETE the server REFUSES must not evict a live entry.

    The emit sits on the success path only; if it were unconditional, a 404
    against a live object's sibling name would be enough to make the manager
    forget a file that is still there."""
    c = http_cluster
    key = _key()

    assert requests.put(c.dav_url(f"/{key}"), data=b"still-here",
                        timeout=TIMEOUT).status_code in (200, 201, 204)
    assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok

    # DELETE a path that does not exist: refused, and nothing may move.
    missing = requests.delete(c.dav_url(f"/{key}-absent"), timeout=TIMEOUT)
    assert missing.status_code >= 400, missing.status_code

    assert _stat(c.mgr, f"/{key}")[0] == kXR_ok, \
        "a failed DELETE retracted a live entry"


def test_webdav_failed_mkcol_seeds_nothing(http_cluster):
    """error — MKCOL onto an existing name is refused and must seed no entry
    under the name it failed to create."""
    c = http_cluster
    key = _key()

    assert requests.request("MKCOL", c.dav_url(f"/{key}"),
                            timeout=TIMEOUT).status_code == 201
    assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok

    # Second MKCOL fails (405 Method Not Allowed per RFC 4918) — a refusal.
    again = requests.request("MKCOL", c.dav_url(f"/{key}"), timeout=TIMEOUT)
    assert again.status_code >= 400, again.status_code

    # A child of it was never created, so it must never be stat-able.
    assert _stat(c.mgr, f"/{key}/child-never-made")[0] != kXR_ok


def test_webdav_traversal_put_reports_nothing(http_cluster):
    """security-negative — a PUT aimed OUT of the export is stopped by path
    confinement and reports nothing.

    A vector that merely normalises back inside the export is not a test: the
    entry it produces is legitimate. These aim at a real sibling directory, so
    an entry for it in the manager would mean an unauthenticated client had
    taught the federation about a path outside every export — the manager would
    then redirect readers at a location no data server serves."""
    c = http_cluster
    loot = "dav-loot.dat"

    for attempt in (f"/../outside/{loot}",
                    f"/%2e%2e/outside/{loot}",
                    f"/a/../../outside/{loot}",
                    f"/..%2foutside/{loot}"):
        status = _raw_http(c.dav, "PUT", attempt, b"poison")
        # Refused, or normalised back inside the export — either is fine. A 5xx
        # would mean the confinement layer crashed rather than declined.
        assert status < 500, (attempt, status)

    _assert_export_not_escaped(c, loot, f"/outside/{loot}")


# --------------------------------------------------------------------------- #
# S3 plane
# --------------------------------------------------------------------------- #

def test_s3_put_object_lands_in_manager_inventory(http_cluster):
    """success — PutObject reports at the bucket-stripped logical path, i.e. the
    same "/key" a root:// or WebDAV write of that name would use.  Divergent
    naming here would give the manager two entries for one object."""
    c = http_cluster
    key = _key()
    payload = b"s3-put-payload-0123456789abcdef"

    r = requests.put(c.s3_url(key), data=payload, timeout=TIMEOUT)
    assert r.status_code == 200, (r.status_code, r.text[:200])

    assert _poll_manager_size(c.mgr, f"/{key}", len(payload)) == len(payload)


def test_s3_delete_object_retracts(http_cluster):
    """success — DeleteObject evicts the entry."""
    c = http_cluster
    key = _key()

    assert requests.put(c.s3_url(key), data=b"y", timeout=TIMEOUT).status_code == 200
    assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok

    assert requests.delete(c.s3_url(key), timeout=TIMEOUT).status_code in (200, 204)
    assert _poll_manager(c.mgr, f"/{key}", want_ok=False) != kXR_ok


def test_s3_copy_object_adds_destination(http_cluster):
    """success — CopyObject publishes a new object at the destination and leaves
    the source's entry alone."""
    c = http_cluster
    src, dst = _key(), _key()
    payload = b"s3-copy-payload-abcdefghijklmno"

    assert requests.put(c.s3_url(src), data=payload,
                        timeout=TIMEOUT).status_code == 200
    assert _poll_manager(c.mgr, f"/{src}", want_ok=True) == kXR_ok

    r = requests.put(c.s3_url(dst), data=b"",
                     headers={"x-amz-copy-source": f"/{S3_BUCKET}/{src}"},
                     timeout=TIMEOUT)
    assert r.status_code == 200, (r.status_code, r.text[:200])

    assert _poll_manager_size(c.mgr, f"/{dst}", len(payload)) == len(payload)
    assert _stat(c.mgr, f"/{src}")[0] == kXR_ok


def test_s3_delete_of_absent_key_seeds_nothing(http_cluster):
    """error — S3 DELETE is idempotent, so an absent key still answers 2xx.  That
    is a reply about nothing having happened, and it must not be reported: the
    inventory-remove would be harmless, but reporting a mutation that did not
    occur is the same class of bug that makes a failed DELETE evict a live
    entry."""
    c = http_cluster
    key = _key()

    assert requests.delete(c.s3_url(key),
                           timeout=TIMEOUT).status_code in (200, 204)
    assert _stat(c.mgr, f"/{key}")[0] != kXR_ok


def test_s3_traversal_key_reports_nothing(http_cluster):
    """security-negative — a key aimed out of the export is stopped by
    s3_resolve_key() confinement and must report nothing."""
    c = http_cluster
    loot = "s3-loot.dat"

    for attempt in (f"/{S3_BUCKET}/../outside/{loot}",
                    f"/{S3_BUCKET}/%2e%2e/outside/{loot}",
                    f"/{S3_BUCKET}/..%2foutside/{loot}"):
        status = _raw_http(c.s3, "PUT", attempt, b"poison")
        assert status < 500, (attempt, status)

    _assert_export_not_escaped(c, loot, f"/outside/{loot}")


# --------------------------------------------------------------------------- #
# gridftp plane
# --------------------------------------------------------------------------- #


def test_gridftp_stor_lands_in_manager_inventory(http_cluster):
    """success — a committed STOR is reported at the observed size.  All four
    transfer shapes (stream/MODE E, active/passive) funnel through one
    completion, so this covers the emit for every one of them."""
    c = http_cluster
    key = _key()
    payload = b"gridftp-stor-payload-0123456789"

    f = _ftp(c)
    try:
        f.storbinary(f"STOR /{key}", io.BytesIO(payload))
    finally:
        f.quit()

    assert _poll_manager_size(c.mgr, f"/{key}", len(payload)) == len(payload)


def test_gridftp_dele_retracts(http_cluster):
    """success — DELE evicts the entry."""
    c = http_cluster
    key = _key()

    f = _ftp(c)
    try:
        f.storbinary(f"STOR /{key}", io.BytesIO(b"z"))
        assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok
        f.delete(f"/{key}")
    finally:
        f.quit()

    assert _poll_manager(c.mgr, f"/{key}", want_ok=False) != kXR_ok


def test_gridftp_mkd_and_rmd(http_cluster):
    """success — MKD then RMD round-trips the directory entry."""
    c = http_cluster
    key = _key()

    f = _ftp(c)
    try:
        f.mkd(f"/{key}")
        assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok
        f.rmd(f"/{key}")
    finally:
        f.quit()

    assert _poll_manager(c.mgr, f"/{key}", want_ok=False) != kXR_ok


def test_gridftp_rename_carries_the_entry(http_cluster):
    """success — RNFR/RNTO emits one rename event, matching the root:// and
    WebDAV rename semantics rather than a DEL+ADD pair."""
    c = http_cluster
    src, dst = _key(), _key()
    payload = b"gridftp-rename-payload-abcdefgh"

    f = _ftp(c)
    try:
        f.storbinary(f"STOR /{src}", io.BytesIO(payload))
        assert _poll_manager(c.mgr, f"/{src}", want_ok=True) == kXR_ok
        f.rename(f"/{src}", f"/{dst}")
    finally:
        f.quit()

    assert _poll_manager_size(c.mgr, f"/{dst}", len(payload)) == len(payload)
    assert _poll_manager(c.mgr, f"/{src}", want_ok=False) != kXR_ok


def test_gridftp_failed_dele_does_not_retract(http_cluster):
    """error — a DELE the server refuses must not evict a live entry."""
    c = http_cluster
    key = _key()

    f = _ftp(c)
    try:
        f.storbinary(f"STOR /{key}", io.BytesIO(b"still-here"))
        assert _poll_manager(c.mgr, f"/{key}", want_ok=True) == kXR_ok
        with pytest.raises(ftplib.error_perm):
            f.delete(f"/{key}-absent")
    finally:
        f.quit()

    assert _stat(c.mgr, f"/{key}")[0] == kXR_ok, \
        "a failed DELE retracted a live entry"


def test_gridftp_traversal_stor_reports_nothing(http_cluster):
    """security-negative — a STOR aimed out of the export is stopped by
    brix_ftp_ev_resolve() confinement and must report nothing.

    Unlike the HTTP planes there is no URI normaliser in front of this, so the
    `..` reaches the resolver exactly as sent — refusal is the expected outcome,
    but a server that instead clamped it back inside the export would also be
    acceptable. What is asserted is the outcome, not the mechanism."""
    c = http_cluster
    loot = "ftp-loot.dat"

    f = _ftp(c)
    try:
        for attempt in (f"/../outside/{loot}", f"/a/../../outside/{loot}"):
            try:
                f.storbinary(f"STOR {attempt}", io.BytesIO(b"poison"))
            except ftplib.all_errors:
                pass                       # refused — the expected path
    finally:
        try:
            f.quit()
        except ftplib.all_errors:
            pass

    _assert_export_not_escaped(c, loot, f"/outside/{loot}")


# --------------------------------------------------------------------------- #
# Cross-plane convergence
# --------------------------------------------------------------------------- #

def test_all_planes_converge_on_one_inventory(http_cluster):
    """The point of the whole phase-97 §5 change: four protocols mutating one
    export produce ONE consistent inventory, addressed by the same logical
    paths.  A per-plane naming or gating divergence shows up here even when each
    plane's own test passes."""
    c = http_cluster
    keys = {plane: _key() for plane in ("root", "dav", "s3", "ftp")}
    payload = b"converge-payload-0123456789abcd"

    from test_cns import _write_file
    _write_file(c.root, f"/{keys['root']}", payload)

    assert requests.put(c.dav_url(f"/{keys['dav']}"), data=payload,
                        timeout=TIMEOUT).status_code in (200, 201, 204)
    assert requests.put(c.s3_url(keys["s3"]), data=payload,
                        timeout=TIMEOUT).status_code == 200

    f = _ftp(c)
    try:
        f.storbinary(f"STOR /{keys['ftp']}", io.BytesIO(payload))
    finally:
        f.quit()

    for plane, key in keys.items():
        assert _poll_manager_size(c.mgr, f"/{key}", len(payload)) == len(payload), \
            f"{plane} plane did not converge in the manager inventory"
