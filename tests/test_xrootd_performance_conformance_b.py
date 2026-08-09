from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrootd_performance_conformance_helpers")

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
