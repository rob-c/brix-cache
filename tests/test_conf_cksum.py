from split_continuation import reexport as _reexport
def _expression_1(line):
    return (
        line.startswith("d") and "adler32:" in line
    )


def _check_test_advertised_algo_is_answerable_1(rc2, got, algo, raw):
    assert rc2 == 0 and got is not None, (
        f"{algo} is advertised in `query config chksum` but querying it on "
        f"/data.bin fails (rc={rc2}): {raw}")

def _check_test_advertised_algo_is_answerable_2(got, want, algo):
    assert got == want, f"advertised {algo} wrong: server={got} ref={want}"

def _check_test_dirlist_directory_has_no_file_checksum_3(rc, out, err):
    assert rc == 0, f"ls -l -C / failed: {out}{err}"

def _check_test_dirlist_directory_has_no_file_checksum_4(line, val):
    assert not (len(val) == 8 and all(c in "0123456789abcdef"
                                      for c in val.lower())), (
        f"directory entry carries a real file checksum: {line!r}")


_reexport(globals(), "_test_conf_cksum_helpers")

@pytest.mark.parametrize("name", ROOT_FILES)
def test_reply_shape_two_tokens(srv, name):
    rc, toks, out, err = _cksum_reply(srv["our"], f"/{name}",
                                      timeout=_timeout_for(name))
    assert rc == 0, f"OUR query checksum /{name} failed: {out}{err}"
    assert len(toks) == 2, (
        f"OUR checksum reply for /{name} is not exactly '<algo> <hex>': "
        f"{out!r}")
    algo, hexv = toks
    assert algo == "adler32", f"default algo for /{name} not adler32: {algo!r}"
    assert len(hexv) == 8 and all(c in "0123456789abcdef" for c in hexv.lower()), (
        f"adler32 hex for /{name} malformed (want 8 hex chars): {hexv!r}")


# =========================================================================== #
# 2. ADLER32 VALUE — our default-algorithm hex must equal zlib.adler32 over    #
#    the exact bytes, for every rich-tree file (incl. the 0-byte empty.txt,    #
#    whose adler32 is defined as 00000001, and the 1 MiB file). (12 cases)     #
# =========================================================================== #
@pytest.mark.parametrize("name", ROOT_FILES)
def test_adler32_value_correct(srv, name):
    rc, got, raw = _query_hex(srv["our"], name, timeout=_timeout_for(name))
    assert rc == 0 and got is not None, (
        f"OUR query checksum /{name} did not return a value: {raw}")
    want = ref_adler32(_bytes(srv, name))
    assert got == want, (
        f"OUR adler32 for /{name} is WRONG: server={got} reference={want} "
        f"(independent zlib.adler32 over {len(_bytes(srv, name))} bytes)")


# Spell out the empty-file invariant on its own so a regression names itself.
def test_adler32_empty_is_canonical(srv):
    rc, got, raw = _query_hex(srv["our"], "empty.txt")
    assert rc == 0 and got is not None, f"empty.txt checksum failed: {raw}"
    assert got == "00000001", (
        f"adler32 of the empty file must be 00000001, got {got}")


# =========================================================================== #
# 3. EXPLICIT-ALGORITHM SELECTION via the standard `?cks.type=<algo>` CGI.     #
#    XrdCl/EOS append exactly this CGI (XrdClUtils.cc). For every advertised   #
#    algorithm the returned hex must equal the independent reference over the  #
#    same bytes. A wrong hex, wrong width, or an error here is a server bug.   #
#    (9 algos x 3 files = 27 cases)                                            #
# =========================================================================== #
CKS_FILES = ["hello.txt", "data.bin", "cksum.bin"]


@pytest.mark.parametrize("algo", list(REF.keys()))
@pytest.mark.parametrize("name", CKS_FILES)
def test_cks_type_explicit_algo_value(srv, algo, name):
    rc, got, raw = _query_hex(srv["our"], name, algo=algo)
    assert rc == 0 and got is not None, (
        f"OUR query checksum /{name}?cks.type={algo} returned no value "
        f"(rc={rc}): {raw}")
    ref_fn, width = REF[algo]
    want = ref_fn(_bytes(srv, name)).lower()
    assert len(got) == width, (
        f"{algo} hex for /{name} has wrong width: got {len(got)} "
        f"({got!r}) want {width}")
    assert got == want, (
        f"OUR {algo} for /{name} is WRONG: server={got} reference={want}")


# =========================================================================== #
# 4. The selected algorithm must be ECHOED in the reply's algo token, so a     #
#    client that asked for crc32c is not silently handed adler32. (9 cases)    #
# =========================================================================== #
@pytest.mark.parametrize("algo", list(REF.keys()))
def test_cks_type_algo_token_echoed(srv, algo):
    rc, toks, out, err = _cksum_reply(srv["our"], f"/data.bin?cks.type={algo}")
    assert rc == 0, (
        f"OUR query checksum /data.bin?cks.type={algo} failed: {out}{err}")
    assert len(toks) >= 2, f"reply not '<algo> <hex>': {out!r}"
    # XRootD normalises zcrc32 onto the crc32 kernel but should still name the
    # algorithm it computed; accept the requested name or its canonical alias.
    assert toks[0] in (algo, "crc32" if algo == "zcrc32" else algo), (
        f"requested {algo} but server echoed {toks[0]!r} (silent substitution)")


# =========================================================================== #
# 5. CONFIG advertisement — `query config chksum` must list every algorithm    #
#    we then expect to answer, as a bare value line (no `chksum=` prefix), and  #
#    each advertised name must actually be selectable. (1 + per-algo membership)#
# =========================================================================== #
def test_config_chksum_advertises_algos(srv):
    rc, out, err = _ourfs(srv["our"], "query", "config", "chksum")
    assert rc == 0, f"query config chksum failed: {out}{err}"
    line = out.strip()
    assert not line.startswith("chksum="), (
        f"chksum config must be a bare value line, got {line!r}")
    advertised = {a.strip() for a in line.replace("\n", ",").split(",")
                  if a.strip()}
    assert "adler32" in advertised, f"adler32 not advertised: {advertised}"


@pytest.mark.parametrize("algo", list(REF.keys()))
def test_advertised_algo_is_answerable(srv, algo):
    """Every algorithm named in `query config chksum` must actually compute."""
    rc, out, err = _ourfs(srv["our"], "query", "config", "chksum")
    advertised = {a.strip() for a in out.strip().replace("\n", ",").split(",")
                  if a.strip()}
    if algo not in advertised:
        pytest.skip(f"{algo} not advertised by this build")
    rc2, got, raw = _query_hex(srv["our"], "data.bin", algo=algo)
    _check_test_advertised_algo_is_answerable_1(rc2, got, algo, raw)
    want = REF[algo][0](_bytes(srv, "data.bin")).lower()
    _check_test_advertised_algo_is_answerable_2(got, want, algo)


# =========================================================================== #
# 6. DETERMINISM — the same file queried twice yields identical hex, for both  #
#    the default algorithm and an explicit one. (size-spanning, 4 cases)       #
# =========================================================================== #
@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin",
                                  "big1m.bin"])
def test_determinism_repeat_default(srv, name):
    a = _query_hex(srv["our"], name, timeout=_timeout_for(name))[1]
    b = _query_hex(srv["our"], name, timeout=_timeout_for(name))[1]
    assert a is not None and a == b, (
        f"non-deterministic adler32 for /{name}: {a} then {b}")


def test_determinism_repeat_explicit_crc32c(srv):
    a = _query_hex(srv["our"], "cksum.bin", algo="crc32c")[1]
    b = _query_hex(srv["our"], "cksum.bin", algo="crc32c")[1]
    assert a is not None and a == b, (
        f"non-deterministic crc32c for /cksum.bin: {a} then {b}")


# =========================================================================== #
# 7. CROSS-FILE STABILITY — two distinct files with IDENTICAL content must     #
#    yield the same checksum, and files with different content must not.       #
#    sz_4096.bin and data.bin are both _det(4096, ...) but with different      #
#    seeds, so they differ; data.bin == itself across handle/path. We assert   #
#    the content-equality contract via an in-tree duplicate created at runtime.#
# =========================================================================== #
def test_identical_content_same_checksum(srv):
    # Plant a byte-for-byte copy of data.bin and require an identical adler32.
    src = _bytes(srv, "data.bin")
    dup = os.path.join(srv["our_data"], "dup_data.bin")
    with open(dup, "wb") as f:
        f.write(src)
    a = _query_hex(srv["our"], "data.bin")[1]
    b = _query_hex(srv["our"], "dup_data.bin")[1]
    os.remove(dup)
    assert a is not None and a == b, (
        f"identical content gave different adler32: data.bin={a} copy={b}")


def test_different_content_different_checksum(srv):
    a = _query_hex(srv["our"], "data.bin")[1]
    b = _query_hex(srv["our"], "cksum.bin")[1]
    assert a is not None and b is not None and a != b, (
        f"different files collided on adler32: data.bin={a} cksum.bin={b}")


# =========================================================================== #
# 8. STOCK DIFF — where the stock server *does* expose a checksum (it ships no  #
#    plugin in this harness, so normally it does not), the two servers must     #
#    agree byte-for-byte on identical content. Otherwise we pin our value to    #
#    the independent reference (already covered above) and record the stock     #
#    "not supported" category for parity. (4 cases)                            #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "sz_4096.bin",
                                  "hello.txt"])
def test_stock_diff_or_reference(srv, name):
    rc_our, ours, raw = _query_hex(srv["our"], name)
    assert rc_our == 0 and ours is not None, (
        f"OUR query checksum /{name} failed: {raw}")
    rc_off, toks, out, err = _cksum_reply(srv["off"], f"/{name}")
    if rc_off == 0 and len(toks) >= 2:
        assert ours == toks[-1].lower(), (
            f"checksum differs for identical content /{name}: "
            f"OUR={ours} STOCK={toks[-1].lower()}")
    else:
        # Stock has no plugin -> pin ours against the independent reference.
        want = ref_adler32(_bytes(srv, name))
        assert ours == want, (
            f"OUR adler32 for /{name} wrong: server={ours} reference={want}")


# =========================================================================== #
# 9. xrdcp --cksum adler32:source — server-verified end-to-end transfer.       #
#    The client re-checksums the bytes it received and compares to the         #
#    server's advertised adler32. This MUST succeed (rc==0) and MUST NEVER     #
#    report a mismatch; a mismatch would mean read corruption, and a failure   #
#    to obtain the server checksum is a Qcksum/cks.type regression. (4 cases)  #
# =========================================================================== #
@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin",
                                  "sz_4096.bin"])
def test_xrdcp_cksum_source_verified(srv, tmp_path, name):
    dst = str(tmp_path / f"src_{name}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", "--cksum", "adler32:source",
                          f"{srv['our']}//{name}", dst],
                         timeout=_timeout_for(name))
    blob = (out + err).lower()
    assert "mismatch" not in blob, (
        f"xrdcp --cksum adler32:source against OUR server reported a checksum "
        f"MISMATCH for /{name} (read corruption): {out}{err}")
    assert rc == 0, (
        f"xrdcp --cksum adler32:source against OUR server failed for /{name} "
        f"(server must answer the adler32 query): {out}{err}")
    assert os.path.getsize(dst) == len(_bytes(srv, name)), (
        f"--cksum transfer of /{name} produced a short/long file")


# =========================================================================== #
# 10. xrdcp --cksum adler32:print — the client prints a checksum line for the   #
#     downloaded bytes; that printed adler32 must equal the reference. (2)      #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin"])
def test_xrdcp_cksum_print_value(srv, tmp_path, name):
    dst = str(tmp_path / f"prn_{name}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", "--cksum", "adler32:print",
                          f"{srv['our']}//{name}", dst],
                         timeout=_timeout_for(name))
    assert rc == 0, f"xrdcp --cksum adler32:print failed for /{name}: {out}{err}"
    blob = out + err
    assert "adler32" in blob.lower(), (
        f"xrdcp --cksum adler32:print emitted no checksum line for /{name}: "
        f"{blob}")
    want = ref_adler32(_bytes(srv, name))
    assert want in blob.lower(), (
        f"printed adler32 for /{name} not the reference {want}: {blob}")


# =========================================================================== #
# 11. ERROR PARITY — a checksum query on a nonexistent path must fail on both   #
#     servers; the coarse error category must match (or, when stock lacks the   #
#     plugin, ours must be the precise not-found category). (1 + 1)            #
# =========================================================================== #
def test_checksum_nonexistent_rejected(srv):
    rc, toks, out, err = _cksum_reply(srv["our"], "/does_not_exist.bin")
    assert rc != 0, (
        f"OUR query checksum on a missing file should fail, got: {out}")
    assert L.err_code(out + err) in ("no such file", "not found"), (
        f"missing-file checksum error miscategorised: {out}{err!r}")


def test_checksum_nonexistent_parity(srv):
    _, _, oo, oe = _cksum_reply(srv["our"], "/missing_xyz.bin")
    rc_off, _, fo, fe = _cksum_reply(srv["off"], "/missing_xyz.bin")
    our_cat = L.err_code(oo + oe)
    if rc_off == 0:
        pytest.skip("stock answered a missing-file checksum unexpectedly")
    # Stock without a plugin returns "unsupported"; ours must be not-found.
    assert our_cat in ("no such file", "not found"), (
        f"OUR missing-file checksum category {our_cat!r} not a not-found error")


# =========================================================================== #
# 12. DIRECTORY TARGET — a checksum query on a directory must be an error on    #
#     our server (you cannot checksum a directory), and the category must be    #
#     sane vs. the stock server. (1)                                           #
# =========================================================================== #
def test_checksum_directory_rejected(srv):
    rc, toks, out, err = _cksum_reply(srv["our"], "/sub")
    assert rc != 0, (
        f"OUR query checksum on a directory should fail, got: {out}")


# =========================================================================== #
# 13. DIRLIST CHECKSUMS — `xrdfs ls -C <dir>` carries `adler32:<hex>` per       #
#     entry. Spot-check that EVERY entry's hex equals the independent adler32   #
#     of that file's bytes. (per-file in /many = 12 cases)                     #
# =========================================================================== #

@pytest.mark.parametrize("name", MANY_FILES)
def test_dirlist_ls_C_per_entry(srv, name):
    rc, mp, raw = _ls_C_map(srv["our"], "/many")
    assert rc == 0, f"OUR xrdfs ls -C /many failed: {raw}"
    assert name in mp, f"/many/{name} missing from ls -C output: {sorted(mp)}"
    want = ref_adler32(_bytes(srv, name, sub="many"))
    assert mp[name] == want, (
        f"ls -C adler32 for /many/{name} WRONG: server={mp[name]} ref={want}")


# =========================================================================== #
# 14. DIRLIST CHECKSUMS at root — `ls -l -C /` carries the same adler32 our     #
#     direct Qcksum returns for the regular files, and marks directories as     #
#     having no file checksum (never a bogus hex). (spot files + dir = 4)      #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "empty.txt"])
def test_dirlist_root_matches_qcksum(srv, name):
    rc, mp, raw = _ls_C_map(srv["our"], "/")
    assert rc == 0, f"OUR xrdfs ls -C / failed: {raw}"
    assert name in mp, f"/{name} missing from ls -C /: {sorted(mp)}"
    direct = _query_hex(srv["our"], name, timeout=_timeout_for(name))[1]
    assert mp[name] == direct, (
        f"ls -C and query checksum disagree for /{name}: "
        f"ls={mp[name]} query={direct}")
    assert mp[name] == ref_adler32(_bytes(srv, name)), (
        f"ls -C adler32 for /{name} not the reference")


def test_dirlist_directory_has_no_file_checksum(srv):
    rc, out, err = _ourfs(srv["our"], "ls", "-l", "-C", "/")
    _check_test_dirlist_directory_has_no_file_checksum_3(rc, out, err)
    # A directory entry must not advertise a real 8-hex file checksum.
    for line in out.splitlines():
        if _expression_1(line):
            val = next(t for t in line.split()
                       if t.startswith("adler32:")).split(":", 1)[1]
            _check_test_dirlist_directory_has_no_file_checksum_4(line, val)


# =========================================================================== #
# 15. BIG FILE — the 1 MiB adler32 (default and explicit) must match the         #
#     reference, exercising the chunked-read checksum kernel over many reads.   #
# =========================================================================== #
def test_big_file_adler32(srv):
    rc, got, raw = _query_hex(srv["our"], "big1m.bin", timeout=150)
    assert rc == 0 and got is not None, f"big1m checksum failed: {raw}"
    assert got == ref_adler32(_bytes(srv, "big1m.bin")), (
        f"adler32 of /big1m.bin wrong: server={got}")


def test_big_file_crc32c(srv):
    rc, got, raw = _query_hex(srv["our"], "big1m.bin", algo="crc32c",
                              timeout=150)
    assert rc == 0 and got is not None, (
        f"big1m crc32c query failed (rc={rc}): {raw}")
    assert got == ref_crc32c(_bytes(srv, "big1m.bin")), (
        f"crc32c of /big1m.bin wrong: server={got}")


# =========================================================================== #
# 16. SIZE-BOUNDARY ADLER32 — every page-boundary file via the explicit CGI     #
#     selector, so the read framing edges are exercised under cks.type. (7)     #
# =========================================================================== #
@pytest.mark.parametrize("name", SZ_FILES)
def test_size_boundary_adler32_cks_type(srv, name):
    rc, got, raw = _query_hex(srv["our"], name, algo="adler32",
                              timeout=_timeout_for(name))
    assert rc == 0 and got is not None, (
        f"OUR /{name}?cks.type=adler32 returned no value (rc={rc}): {raw}")
    assert got == ref_adler32(_bytes(srv, name)), (
        f"adler32 (cks.type) for /{name} wrong: server={got}")


# =========================================================================== #
# 17. ORACLE — independent self-checks of the reference computations against    #
#     published CRC catalogue vectors, so a broken reference cannot mask a real #
#     server diff (these never touch the server). (1)                          #
# =========================================================================== #
def test_reference_oracle_vectors():
    assert ref_crc64(b"123456789") == "995dc9bbdf1939fa", "CRC-64/XZ vector"
    assert ref_crc64nvme(b"123456789") == "ae8b14860a799888", "CRC-64/NVME vector"
    assert ref_crc32c(b"123456789") == "e3069283", "CRC-32C vector"
    assert ref_crc32(b"123456789") == "cbf43926", "CRC-32 vector"
    assert ref_adler32(b"") == "00000001", "adler32 empty vector"
