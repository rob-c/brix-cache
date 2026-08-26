from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_read_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_read")

def test_corrupt_after_warm_read_serves_cached_plaintext(warmrepo):
    ref = blob("warm-then-corrupt", 20000)
    with mounted(warmrepo) as mnt:
        assert (mnt / "warmfile").read_bytes() == ref          # warm the cache
        warmrepo.forge.flip_byte(cas_key(ref), 42)             # corrupt origin copy
        # cache-first (fetch.c:63-65): the verified plaintext already in the
        # local CAS cache serves; the corrupted origin copy is never consulted.
        with rdfd(mnt / "warmfile") as fd:
            assert os.pread(fd, len(ref), 0) == ref


# --------------------------------------------------------------------------- #
# Concurrency through the single-threaded mount
# --------------------------------------------------------------------------- #
_READER = ("import sys,hashlib;"
           "d=open(sys.argv[1],'rb').read();"
           "print(len(d), hashlib.sha1(d).hexdigest())")



@pytest.mark.timeout(60)
def test_two_processes_read_different_files_concurrently(plain):
    a = _spawn_reader(plain.mnt / "sz1000003")
    b = _spawn_reader(plain.mnt / "sz65536")
    _expect(a, PLAIN["sz1000003"])
    _expect(b, PLAIN["sz65536"])


@pytest.mark.timeout(60)
def test_two_processes_read_same_file_concurrently(plain):
    a = _spawn_reader(plain.mnt / "sz1000003")
    b = _spawn_reader(plain.mnt / "sz1000003")
    _expect(a, PLAIN["sz1000003"])
    _expect(b, PLAIN["sz1000003"])
