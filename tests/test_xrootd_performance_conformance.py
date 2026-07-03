from _test_brix_performance_conformance_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)
import pytest

# serial: latency/throughput-vs-reference assertions — invalid under pool load.
pytestmark = pytest.mark.serial

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


def test_query_config_latency_tracks_reference(perf_env):
    """kXR_query CONFIG latency follows the official XRootD reference."""
    nginx_times = [
        _time_query_config_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_query_config_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  query CONFIG best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="query CONFIG",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_ping_latency_tracks_reference(perf_env):
    """Persistent-session raw ping latency follows reference XRootD."""
    nginx_times = [
        _time_raw_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_stat_latency_tracks_reference(perf_env):
    """Raw kXR_stat loop stays near reference without PyXRootD per-call overhead."""
    nginx_times = [
        _time_raw_stat_loop(perf_env["nginx_url"], perf_env["small"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_stat_loop(perf_env["ref_url"], perf_env["small"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_read_latency_tracks_reference(perf_env):
    """Raw kXR_open/read/close loop stays near reference on deterministic data."""
    if PAYLOAD_SIZE <= RAW_READ_SIZE:
        pytest.skip("raw read conformance needs payload larger than read size")

    nginx_times = [
        _time_raw_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_session_login_ping_latency_tracks_reference(perf_env):
    """Connection setup + handshake/login/ping latency follows reference XRootD."""
    nginx_times = [
        _time_raw_session_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_session_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw session+ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SESSION_ITERS}"
    )
    _assert_within_reference(
        label="raw session login ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_mixed_workload_latency_tracks_reference(perf_env):
    """Mixed success/error workload stays in the official reference envelope."""
    nginx_times = [
        _time_mixed_loop(
            base_url=perf_env["nginx_url"],
            payload_remote=perf_env["payload"],
            payload_md5=perf_env["payload_md5"],
            meta_dir=perf_env["meta_dir"],
            expected_names=perf_env["meta_names"],
            small_remote=perf_env["small"],
            small_content=perf_env["small_content"],
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_mixed_loop(
            base_url=perf_env["ref_url"],
            payload_remote=perf_env["payload"],
            payload_md5=perf_env["payload_md5"],
            meta_dir=perf_env["meta_dir"],
            expected_names=perf_env["meta_names"],
            small_remote=perf_env["small"],
            small_content=perf_env["small_content"],
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  mixed workload best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={MIXED_ITERS}"
    )
    _assert_within_reference(
        label="mixed workload",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_eof_short_read_latency_tracks_reference(perf_env):
    """Read spanning EOF returns the same short-read behavior and latency envelope."""
    nginx_times = [
        _time_eof_short_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_eof_short_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  EOF short-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="EOF short read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_exact_eof_read_latency_tracks_reference(perf_env):
    """Read starting exactly at EOF returns zero bytes within the reference envelope."""
    nginx_times = [
        _time_exact_eof_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_exact_eof_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  exact EOF read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="exact EOF read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )
