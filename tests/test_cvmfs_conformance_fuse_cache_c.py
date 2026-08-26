from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_cache_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_cache")

@pytest.mark.timeout(240)
def test_kill9_then_remount_warm_over_same_cache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, proc):
        first = read_tree(mnt)
        proc.send_signal(signal.SIGKILL)
        proc.wait(10)
        deadline = time.monotonic() + 10            # auto_unmount reaps the mount
        while os.path.ismount(str(mnt)) and time.monotonic() < deadline:
            time.sleep(0.2)
        _unmount(mnt)                               # belt-and-braces
        assert not os.path.ismount(str(mnt))
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "cache filled before SIGKILL was not reused"
    forge.close()


@pytest.mark.timeout(240)
def test_cold_cache_mount_with_dead_origin_fails_cleanly(tmp_path):
    # Nothing listens on the port: the trust chain cannot be fetched raw and the
    # mount must fail with a clean error after its bounded retry/backoff (~15s).
    forge, web, pub = _forge(tmp_path, _std_tree())
    dead = next(_PORTS)
    url = f"http://{HOST}:{dead}/cvmfs/{REPO}"
    mnt = tmp_path / "m"
    mnt.mkdir()
    with own_mount(REPO, url, pub, mnt=mnt, cache_env=tmp_path / "cache",
                   extra_args=_FAST, timeout=1, bringup_retries=1) as (mnt2, proc):
        rc = proc.wait(timeout=60)
        assert rc is not None and rc > 0, "expected a clean nonzero exit"
        assert not os.path.ismount(str(mnt2))
    forge.close()
