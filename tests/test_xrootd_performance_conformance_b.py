from _test_xrootd_performance_conformance_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_empty_file_open_stat_read_latency_tracks_reference(perf_env):
    """Zero-length file open/stat/read latency stays near reference."""
    nginx_times = [
        _time_empty_file_loop(perf_env["nginx_url"], perf_env["empty"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_empty_file_loop(perf_env["ref_url"], perf_env["empty"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  empty file open/stat/read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="empty file open/stat/read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_random_small_read_latency_tracks_reference(perf_env):
    """Random 4 KiB reads from one open handle stay near reference."""
    nginx_times = [
        _time_random_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_random_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  random small-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RANDOM_READ_ITERS}"
    )
    _assert_within_reference(
        label="random small read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_handle_stat_latency_tracks_reference(perf_env):
    """Handle-based File.stat() latency stays near the official reference."""
    nginx_times = [
        _time_handle_stat_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_handle_stat_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  handle stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={HANDLE_STAT_ITERS}"
    )
    _assert_within_reference(
        label="handle stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_sync_write_latency_tracks_reference(perf_env):
    """Write+sync latency stays in the reference envelope."""
    nginx_times = [
        _time_sync_write_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_sync_write_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  sync write best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SYNC_ITERS}"
    )
    _assert_within_reference(
        label="sync write",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_chmod_latency_tracks_reference(perf_env):
    """chmod metadata mutation latency stays near the official reference."""
    nginx_times = [
        _time_chmod_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_chmod_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  chmod best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={CHMOD_ITERS}"
    )
    _assert_within_reference(
        label="chmod",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_mkdir_makepath_latency_tracks_reference(perf_env):
    """Recursive mkdir creation/removal stays near the official reference."""
    nginx_times = [
        _time_mkdir_makepath_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_mkdir_makepath_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  mkdir -p best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={MAKEPATH_ITERS}"
    )
    _assert_within_reference(
        label="mkdir -p",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_handle_truncate_latency_tracks_reference(perf_env):
    """Handle-based truncate extend/shrink latency stays near reference."""
    nginx_times = [
        _time_handle_truncate_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_handle_truncate_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  handle truncate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={TRUNCATE_ITERS}"
    )
    _assert_within_reference(
        label="handle truncate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_namespace_mutation_latency_tracks_reference(perf_env):
    """mkdir/create/mv/truncate/rm/rmdir loop stays near reference."""
    nginx_times = [
        _time_fs_mutation_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_fs_mutation_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  namespace mutation best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={FS_MUTATION_ITERS}"
    )
    _assert_within_reference(
        label="namespace mutation",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_small_open_read_close_latency_tracks_reference(perf_env):
    """Small-object success path: repeated open/read/close stays near reference."""
    nginx_times = [
        _time_small_open_read_close_loop(
            perf_env["nginx_url"], perf_env["small"], perf_env["small_content"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_small_open_read_close_loop(
            perf_env["ref_url"], perf_env["small"], perf_env["small_content"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  small open/read/close best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SMALL_ITERS}"
    )
    _assert_within_reference(
        label="small open/read/close",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_readv_latency_tracks_reference(perf_env):
    """Vector-read success path: scatter/gather reads stay in reference envelope."""
    if PAYLOAD_SIZE < 7 * 1024 * 1024:
        pytest.skip("readv performance check needs at least a 7 MiB payload")

    nginx_times = [
        _time_readv_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_readv_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  readv best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={READV_ITERS}"
    )
    _assert_within_reference(
        label="readv",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=READ_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_write_throughput_tracks_reference(perf_env):
    """Write success path: client-visible write time stays near reference."""
    nginx_times = []
    ref_times = []
    expected_md5 = None
    for run in range(READ_RUNS):
        nginx_remote = _remote(f"{PREFIX}nginx_write_{os.getpid()}_{run}.bin")
        ref_remote = _remote(f"{PREFIX}ref_write_{os.getpid()}_{run}.bin")
        if run % 2:
            ref_elapsed, ref_md5 = _write_chunked(
                perf_env["ref_url"], ref_remote, WRITE_SIZE
            )
            nginx_elapsed, nginx_md5 = _write_chunked(
                perf_env["nginx_url"], nginx_remote, WRITE_SIZE
            )
        else:
            nginx_elapsed, nginx_md5 = _write_chunked(
                perf_env["nginx_url"], nginx_remote, WRITE_SIZE
            )
            ref_elapsed, ref_md5 = _write_chunked(
                perf_env["ref_url"], ref_remote, WRITE_SIZE
            )
        assert nginx_md5 == ref_md5
        expected_md5 = nginx_md5
        nginx_times.append(nginx_elapsed)
        ref_times.append(ref_elapsed)

        assert (
            _remote_md5(perf_env["nginx_url"], nginx_remote, WRITE_SIZE)
            == expected_md5
        )
        assert _remote_md5(perf_env["ref_url"], ref_remote, WRITE_SIZE) == expected_md5

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  write best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={WRITE_MIB}MiB"
    )
    _assert_within_reference(
        label="write",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_concurrent_bulk_read_throughput_tracks_reference(perf_env):
    """Concurrent success path: aggregate read behavior stays near reference."""
    if CONCURRENT_WORKERS < 2:
        pytest.skip("concurrent read conformance needs at least two workers")

    # Warm both backends before timing thread-pool fanout.
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_seconds = _time_concurrent_reads(
        perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
    )
    ref_seconds = _time_concurrent_reads(
        perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
    )
    print(
        "\n  concurrent bulk-read: "
        f"nginx={nginx_seconds:.4f}s ref={ref_seconds:.4f}s "
        f"workers={CONCURRENT_WORKERS} size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="concurrent bulk read",
        nginx_seconds=nginx_seconds,
        ref_seconds=ref_seconds,
        ratio_limit=CONCURRENT_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_missing_file_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file stats fail within the reference envelope."""
    missing = _remote(f"{PREFIX}missing_{os.getpid()}.dat")
    nginx_times = [
        _time_status_loop(perf_env["nginx_url"], missing, META_ITERS)
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_status_loop(perf_env["ref_url"], missing, META_ITERS)
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_open_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file opens fail within the reference envelope."""
    nginx_times = [
        _time_missing_open_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_open_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-open best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file open",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_locate_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file locates fail within the reference envelope."""
    nginx_times = [
        _time_missing_locate_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_locate_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-locate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={LOCATE_ITERS}"
    )
    _assert_within_reference(
        label="missing-file locate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_rm_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file rm calls fail within the reference envelope."""
    nginx_times = [
        _time_missing_rm_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_rm_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-rm best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file rm",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_nonempty_rmdir_error_latency_tracks_reference(perf_env):
    """Error path: non-empty directory rmdir fails within the reference envelope."""
    nginx_times = [
        _time_nonempty_rmdir_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_nonempty_rmdir_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  nonempty-rmdir best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="nonempty rmdir",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


@pytest.mark.parametrize(
    "probe",
    [
        "/../etc/passwd",
        "/../../../../etc/shadow",
        "/%2e%2e/%2e%2e/etc/passwd",
    ],
)
def test_traversal_probe_is_not_a_fast_success_path(perf_env, probe):
    """Security negative: traversal-like probes must not become successful stats."""
    nginx_status, _ = client.FileSystem(perf_env["nginx_url"]).stat(probe)
    ref_status, _ = client.FileSystem(perf_env["ref_url"]).stat(probe)

    assert not nginx_status.ok, (
        f"nginx unexpectedly accepted traversal probe {probe!r}: "
        f"{nginx_status.message}"
    )
    assert not ref_status.ok, (
        "reference xrootd unexpectedly accepted the traversal probe; "
        "the localroot/path-confinement behavior is the reference contract "
        f"for this test fixture: {probe!r}"
    )
