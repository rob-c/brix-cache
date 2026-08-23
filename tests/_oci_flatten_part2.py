# ---- eStargz-shaped layers ----------------------------------------------
# An eStargz layer is an ordinary tar in a chain of gzip members, plus three
# entries of the format's own: the TOC and the two prefetch landmarks. A lazy
# snapshotter consumes those; a publisher that materializes the whole rootfs
# must drop them, or the published tree differs from the original image's.

_STARGZ_META = ("stargz.index.json", ".prefetch.landmark",
                ".no.prefetch.landmark")


def _estargz(path, build, meta=_STARGZ_META):
    """The same layer an eStargz converter would emit: content, then the
    format's own entries, packed as a chain of gzip members."""
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as tf:
        build(tf)
        for name in meta:
            _add(tf, name, b'{"version":1}' if name.endswith(".json") else b"")
    blob = plain.getvalue()
    step = ((len(blob) // 3) // 512) * 512 or 512
    with open(str(path), "wb") as fh:
        for i in range(0, len(blob), step):
            co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
            fh.write(co.compress(blob[i:i + step]) + co.flush())
    return path


def test_estargz_layer_flattens_like_its_original(flatten_ut, tmp_path):
    def content(tf):
        _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "usr/bin", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "usr/bin/tool", b"#!/bin/sh\nexec true\n", mode=0o755)
        _add(tf, "etc/conf", b"key = value\n")
        _add(tf, "usr/bin/alias", typ=tarfile.SYMTYPE, link="tool")

    plain = _layer(tmp_path / "plain.tar", content)
    st = _stats(_apply(flatten_ut, tmp_path / "want", plain))
    assert st["toc"] == 0

    lay = _estargz(tmp_path / "estargz.tar.gz", content)
    st = _stats(_apply(flatten_ut, tmp_path / "got", lay))
    assert st["toc"] == len(_STARGZ_META)
    assert st["files"] == 2 and st["links"] == 1   # meta counted as none

    want, _, _ = _shape_from_tree(tmp_path / "want")
    got, _, _ = _shape_from_tree(tmp_path / "got")
    assert got == want, (got, want)


def test_stargz_meta_is_dropped_before_it_can_plant_anything(flatten_ut,
                                                             tmp_path):
    """Security-negative: the reserved names are matched at the archive ROOT
    and dropped before any syscall, so a layer cannot use one to plant a
    symlink — and cannot use one deeper in the tree to make real content
    disappear from the published rootfs either."""
    def hostile(tf):
        _add(tf, "stargz.index.json", typ=tarfile.SYMTYPE, link="/etc/passwd")
        _add(tf, ".prefetch.landmark", typ=tarfile.SYMTYPE, link="../../root")
        _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "usr/stargz.index.json", b"ordinary content")

    lay = _layer(tmp_path / "hostile.tar", hostile)
    upper = tmp_path / "upper"
    st = _stats(_apply(flatten_ut, upper, lay))
    assert st["toc"] == 2 and st["links"] == 0
    assert not (upper / "stargz.index.json").exists(follow_symlinks=False)
    assert not (upper / ".prefetch.landmark").exists(follow_symlinks=False)
    assert (upper / "usr" / "stargz.index.json").read_bytes() == \
        b"ordinary content"


def test_special_files_counted_when_not_strict(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "dev.tar", lambda tf: (
        _add(tf, "dev", typ=tarfile.DIRTYPE, mode=0o755),
        _add(tf, "dev/null", typ=tarfile.CHRTYPE, mode=0o666,
             devmajor=1, devminor=3)))
    st = _stats(_apply(flatten_ut, tmp_path / "upper", lay))
    assert st["skip"] == 1
    assert not (tmp_path / "upper" / "dev" / "null").exists()


# ---- error ---------------------------------------------------------------

def test_strict_refuses_device(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "dev.tar", lambda tf: _add(
        tf, "dev/null", typ=tarfile.CHRTYPE, mode=0o666,
        devmajor=1, devminor=3))
    _refused(_apply(flatten_ut, tmp_path / "upper", lay,
                    flags=("--strict",)), "--strict")

def test_byte_budget_enforced(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "big.tar", lambda tf: _add(
        tf, "big.bin", b"A" * 10240))
    _refused(_apply(flatten_ut, tmp_path / "upper", lay,
                    flags=("--max-bytes", "1024")), "byte budget")

def test_entry_budget_enforced(flatten_ut, tmp_path):
    def five(tf):
        for i in range(5):
            _add(tf, "f%d" % i, b"x")
    lay = _layer(tmp_path / "many.tar", five)
    _refused(_apply(flatten_ut, tmp_path / "upper", lay,
                    flags=("--max-entries", "3")), "entry budget")


# ---- security-negative ---------------------------------------------------

def test_dotdot_member_refused(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "dd.tar", lambda tf: _add(
        tf, "a/../../evil", b"pwn"))
    _refused(_apply(flatten_ut, tmp_path / "upper", lay), "'..'")
    assert not (tmp_path / "evil").exists()

def test_absolute_path_confined_to_upper(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "abs.tar", lambda tf: _add(
        tf, "/abs/x", b"contained"))
    st = _stats(_apply(flatten_ut, tmp_path / "upper", lay))
    assert st["files"] == 1
    assert (tmp_path / "upper" / "abs" / "x").read_bytes() == b"contained"

def test_marker_smuggling_refused(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "smug.tar", lambda tf: _add(
        tf, "d/.brix.wh.x", b""))
    _refused(_apply(flatten_ut, tmp_path / "upper", lay), "smuggles")

def test_symlink_escape_refused_at_component(flatten_ut, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    l1 = _layer(tmp_path / "plant.tar", lambda tf: _add(
        tf, "esc", typ=tarfile.SYMTYPE, link="../outside"))
    l2 = _layer(tmp_path / "write.tar", lambda tf: _add(
        tf, "esc/pwn", b"gotcha"))
    upper = tmp_path / "upper"
    assert _apply(flatten_ut, upper, l1).returncode == 0
    _refused(_apply(flatten_ut, upper, l2), "containment")
    assert os.listdir(outside) == []

def test_whiteout_of_dotdot_refused(flatten_ut, tmp_path):
    lay = _layer(tmp_path / "wdd.tar", lambda tf: _add(
        tf, "d/.wh...", b""))
    _refused(_apply(flatten_ut, tmp_path / "upper", lay),
             "refusing whiteout")
