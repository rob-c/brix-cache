from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrootd_performance_conformance_helpers")

def test_bulk_read_throughput_tracks_reference(perf_env):
    """Success path: nginx bulk-read throughput stays in the reference envelope."""
    # Warm the shared page cache and client paths before timing.
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        if run % 2:
            ref_times.append(
                _read_chunked(
                    perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
            nginx_times.append(
                _read_chunked(
                    perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
        else:
            nginx_times.append(
                _read_chunked(
                    perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
            ref_times.append(
                _read_chunked(
                    perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  bulk-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="bulk read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=READ_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_copyprocess_download_throughput_tracks_reference(perf_env, tmp_path):
    """Client copy path: CopyProcess download throughput stays near reference."""
    # Warm file data and the XRootD client machinery before timing CopyProcess.
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        nginx_dest = tmp_path / f"nginx-copy-{run}.bin"
        ref_dest = tmp_path / f"ref-copy-{run}.bin"
        if run % 2:
            ref_times.append(
                _copy_process(
                    perf_env["ref_url"], perf_env["payload"], ref_dest,
                    perf_env["payload_md5"],
                )
            )
            nginx_times.append(
                _copy_process(
                    perf_env["nginx_url"], perf_env["payload"], nginx_dest,
                    perf_env["payload_md5"],
                )
            )
        else:
            nginx_times.append(
                _copy_process(
                    perf_env["nginx_url"], perf_env["payload"], nginx_dest,
                    perf_env["payload_md5"],
                )
            )
            ref_times.append(
                _copy_process(
                    perf_env["ref_url"], perf_env["payload"], ref_dest,
                    perf_env["payload_md5"],
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  CopyProcess download best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="CopyProcess download",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=COPY_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_copyprocess_upload_throughput_tracks_reference(perf_env, tmp_path):
    """Client copy upload path stays near the official XRootD reference."""
    local = tmp_path / "copyprocess-upload.bin"
    expected_md5 = _write_deterministic(local, WRITE_SIZE)

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        nginx_remote = _remote(f"{PREFIX}nginx_cp_upload_{os.getpid()}_{run}.bin")
        ref_remote = _remote(f"{PREFIX}ref_cp_upload_{os.getpid()}_{run}.bin")
        if run % 2:
            ref_times.append(
                _copy_process_upload(
                    perf_env["ref_url"], local, ref_remote, expected_md5
                )
            )
            nginx_times.append(
                _copy_process_upload(
                    perf_env["nginx_url"], local, nginx_remote, expected_md5
                )
            )
        else:
            nginx_times.append(
                _copy_process_upload(
                    perf_env["nginx_url"], local, nginx_remote, expected_md5
                )
            )
            ref_times.append(
                _copy_process_upload(
                    perf_env["ref_url"], local, ref_remote, expected_md5
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  CopyProcess upload best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={WRITE_MIB}MiB"
    )
    _assert_within_reference(
        label="CopyProcess upload",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=COPY_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_dirlist_stat_latency_tracks_reference(perf_env):
    """Metadata success path: STAT dirlist latency stays near reference."""
    nginx_times = [
        _time_dirlist_loop(
            perf_env["nginx_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_dirlist_loop(
            perf_env["ref_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  dirlist+stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="dirlist+stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_multifile_stat_sweep_latency_tracks_reference(perf_env):
    """Repeated stat sweep over many files stays near reference."""
    nginx_times = [
        _time_multifile_stat_sweep_loop(
            perf_env["nginx_url"], perf_env["stat_sweep_paths"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_multifile_stat_sweep_loop(
            perf_env["ref_url"], perf_env["stat_sweep_paths"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  multifile stat sweep best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"files={len(perf_env['stat_sweep_paths'])}"
    )
    _assert_within_reference(
        label="multifile stat sweep",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_concurrent_metadata_latency_tracks_reference(perf_env):
    """Concurrent stat+dirlist metadata fanout stays near reference."""
    if CONCURRENT_WORKERS < 2:
        pytest.skip("concurrent metadata conformance needs at least two workers")

    nginx_seconds = _time_concurrent_metadata(
        perf_env["nginx_url"],
        perf_env["meta_dir"],
        perf_env["stat_sweep_paths"],
        perf_env["meta_names"],
    )
    ref_seconds = _time_concurrent_metadata(
        perf_env["ref_url"],
        perf_env["meta_dir"],
        perf_env["stat_sweep_paths"],
        perf_env["meta_names"],
    )
    print(
        "\n  concurrent metadata: "
        f"nginx={nginx_seconds:.4f}s ref={ref_seconds:.4f}s "
        f"workers={CONCURRENT_WORKERS} iters={META_ITERS}"
    )
    _assert_within_reference(
        label="concurrent metadata",
        nginx_seconds=nginx_seconds,
        ref_seconds=ref_seconds,
        ratio_limit=CONCURRENT_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_plain_dirlist_latency_tracks_reference(perf_env):
    """Plain dirlist without stat payloads stays near reference."""
    nginx_times = [
        _time_plain_dirlist_loop(
            perf_env["nginx_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_plain_dirlist_loop(
            perf_env["ref_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  plain dirlist best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="plain dirlist",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_api_ping_latency_tracks_reference(perf_env):
    """PyXRootD FileSystem.ping latency follows the official reference."""
    nginx_times = [
        _time_api_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_api_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  API ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="API ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_locate_latency_tracks_reference(perf_env):
    """kXR_locate success-path latency follows the official reference."""
    nginx_times = [
        _time_locate_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_locate_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  locate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={LOCATE_ITERS}"
    )
    _assert_within_reference(
        label="locate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_query_space_latency_tracks_reference(perf_env):
    """kXR_query SPACE latency follows the official XRootD reference."""
    nginx_times = [
        _time_query_space_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_query_space_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  query SPACE best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="query SPACE",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )
