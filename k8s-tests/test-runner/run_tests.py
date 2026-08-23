#!/usr/bin/env python3
"""Test orchestrator for nginx-xrootd K8s integration tests.

Handles URL discovery for both in-cluster DNS (Kind/K8s) and NodePort-based
host access (minikube/local), TPC scenario configuration, and result aggregation
from parallel test jobs.

Usage:
    python run_tests.py [OPTIONS]

Environment Variables:
    TEST_NAMESPACE   Kubernetes namespace (default: k8s-tests-dev)
    TEST_PROFILE     Test profile name for values file lookup (default: dev)
    AUTH_MODE        Authentication mode: none, gsi, token (default: none)
    RESULTS_DIR      Directory for test results XML files (default: /test-results)
    PYTEST_ARGS      Additional pytest arguments passed verbatim
"""

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path


SCENARIOS = {
    "all": {"patterns": ["*.py"], "exclude": ["test_load_test.py", "perf/"]},
    "native-xrootd": {"patterns": ["test_file_api.py", "test_xrootd.py", "test_readv.py", "test_write.py", "test_query.py", "test_aio.py", "test_metrics.py"], "exclude": []},
    "webdav-full": {"patterns": ["test_webdav.py", "test_http_webdav*.py"], "exclude": []},
    "tpc-cross-node": {"patterns": ["test_root_tpc.py", "test_webdav_tpc.py"], "exclude": [], "requires_source_dest": True},
    "auth-tests": {"patterns": ["test_gsi_*.py", "test_token_*.py", "test_vo_acl.py", "test_crl.py"], "exclude": []},
}


def discover_k8s_endpoints(namespace: str) -> dict[str, str]:
    """Discover server endpoints via in-cluster DNS (works with Kind and K8s).

    Falls back to NodePort-based host access if DNS resolution fails.
    Returns a mapping of service suffix -> full URL string.
    """
    urls = {}

    for suffix in ("xrootd", "webdav-https"):
        service_name = f"xrootd-servers-{suffix}"
        dns_name = f"{service_name}.{namespace}.svc.cluster.local"
        port = 1094 if suffix == "xrootd" else 8443
        scheme = "root" if suffix == "xrootd" else "davs"

        try:
            socket.gethostbyname(dns_name)
            urls[f"{suffix}_url"] = f"{scheme}://{dns_name}:{port}"
        except socket.gaierror:
            pass

    return urls


def discover_nodeport_endpoints() -> dict[str, str]:
    """Discover server endpoints via NodePort mapping on localhost.

    This is the fallback for minikube where in-cluster DNS may not be available
    from the test runner pod when using host networking or direct access.
    Returns a mapping of service suffix -> full URL string pointing to localhost.
    """
    urls = {}

    # Common NodePort ranges assigned by Helm chart: 31094+node_index for xrootd,
    # 32443+node_index for webdav-https
    for node_idx in range(5):
        xrd_port = 31094 + node_idx
        dav_port = 32443 + node_idx

        urls["xrootd_url"] = f"root://localhost:{xrd_port}"
        urls["webdav-https_url"] = f"davs://localhost:{dav_port}"

    return urls


def resolve_test_urls(namespace: str | None) -> dict[str, str]:
    """Resolve test URLs by trying K8s DNS first, then NodePort fallback."""
    ns = namespace or os.environ.get("TEST_NAMESPACE", "k8s-tests-dev")

    # Try in-cluster DNS first (works with Kind and proper K8s clusters)
    k8s_urls = discover_k8s_endpoints(ns)

    if k8s_urls:
        return k8s_urls

    # Fall back to NodePort-based host access (minikube/local)
    return discover_nodeport_endpoints()


def select_test_files(tests_dir: str, scenario: str) -> list[str]:
    """Select test files based on the scenario configuration."""
    test_dir_path = Path(tests_dir)
    if not test_dir_path.exists():
        print(f"Tests directory not found: {tests_dir}", file=sys.stderr)
        return []
    config = _scenario_config(scenario)
    return _matching_test_files(test_dir_path, config)


def _scenario_config(scenario):
    if scenario in SCENARIOS:
        return SCENARIOS[scenario]
    print(f"Unknown scenario '{scenario}', using 'all'", file=sys.stderr)
    return SCENARIOS["all"]


def _matching_test_files(tests_dir, config):
    exclude = set(config.get("exclude", []))
    selected = []
    for pattern in config["patterns"]:
        selected.extend(_included_matches(tests_dir, pattern, exclude))
    return selected


def _included_matches(tests_dir, pattern, exclude):
    matches = []
    for path in sorted(tests_dir.glob(pattern)):
        relative = str(path.relative_to(tests_dir))
        if not any(item in relative for item in exclude):
            matches.append(str(path))
    return matches


def setup_environment(urls: dict[str, str], auth_mode: str) -> None:
    """Set up environment variables for pytest based on discovered endpoints."""
    os.environ["AUTH_MODE"] = auth_mode
    os.environ.setdefault("TEST_NAMESPACE", "k8s-tests-dev")

    _set_endpoint_environment(urls)
    _set_tpc_environment()
    _set_pki_environment()


def _set_endpoint_environment(urls):
    xrootd_url = urls.get("xrootd_url")
    if xrootd_url:
        os.environ["TEST_NGINX_URL"] = xrootd_url
    webdav_url = urls.get("webdav-https_url")
    if webdav_url:
        os.environ.setdefault("TEST_DAVS_URL", webdav_url)


def _set_tpc_environment():
    source = os.environ.get("tpc_source_url")
    destination = os.environ.get("tpc_dest_url")
    if source and destination:
        os.environ["TPC_SOURCE"] = source
        os.environ["TPC_DESTINATION"] = destination


def _set_pki_environment():
    pki_dir = os.environ.get("PKI_DIR", "/etc/grid-security")
    if Path(pki_dir).exists():
        os.environ["X509_CERT_DIR"] = f"{pki_dir}/certificates"


def run_tests(test_files: list[str], extra_args: list[str] | None = None) -> int:
    """Execute pytest with the selected test files and arguments."""
    cmd = ["python", "-m", "pytest", "-v", "--tb=short"]

    if extra_args is not None:
        cmd.extend(extra_args)

    # Add timeout to prevent hanging tests (10 minutes per test file)
    cmd.extend(["--timeout=600"])

    # Append selected test files or full directory
    if test_files:
        cmd.extend(test_files)
    else:
        cmd.append(os.environ.get("TESTS_DIR", "/test"))

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, env={**os.environ})
    return result.returncode


def _argument_parser():
    parser = argparse.ArgumentParser(description="Run nginx-xrootd K8s tests")
    parser.add_argument("--namespace", default=None, help="Kubernetes namespace (overrides TEST_NAMESPACE)")
    parser.add_argument("--profile", "-p", default=os.environ.get("TEST_PROFILE", "dev"),
                        help="Test profile (dev, staging, perf)")
    parser.add_argument("--auth-mode", default=os.environ.get("AUTH_MODE", "none"),
                        help="Authentication mode: none, gsi, token")
    parser.add_argument("--scenario", "-s", choices=list(SCENARIOS.keys()) + ["custom"],
                        default=os.environ.get("TEST_SCENARIO", "all"),
                        help="Test scenario to run (default: all)")
    parser.add_argument("--tests-dir", "-d", default=os.environ.get("TESTS_DIR", "/test"),
                        help="Directory containing pytest tests")
    parser.add_argument("--tpc-source-url", default=None, help="TPC source server URL for cross-node copy tests")
    parser.add_argument("--tpc-dest-url", default=None, help="TPC destination server URL for cross-node copy tests")
    parser.add_argument("--test-patterns", nargs="*", default=None,
                        help="Override test file patterns (space-separated globs)")
    parser.add_argument("--extra-args", "-a", nargs="+", default=None,
                        help="Additional pytest arguments")
    return parser


def _configure_endpoints(args):
    urls = resolve_test_urls(args.namespace)
    if urls:
        setup_environment(urls, args.auth_mode)
        return
    print("WARNING: Could not discover any server endpoints.", file=sys.stderr)
    print("Using localhost defaults. Ensure servers are accessible on ports 1094/8443.",
          file=sys.stderr)
    os.environ["TEST_NGINX_URL"] = "root://localhost:1094"
    os.environ.setdefault("TEST_DAVS_URL", "davs://localhost:8443")


def _configure_tpc(args):
    if args.tpc_source_url and args.tpc_dest_url:
        os.environ["tpc_source_url"] = args.tpc_source_url
        os.environ["tpc_dest_url"] = args.tpc_dest_url


def _custom_test_files(args):
    selected = []
    for pattern in args.test_patterns:
        selected.extend(sorted(Path(args.tests_dir).glob(pattern)))
    return [str(path) for path in selected]


def _selected_test_files(args):
    if args.test_patterns:
        return _custom_test_files(args)
    if args.scenario != "custom":
        return select_test_files(args.tests_dir, args.scenario)
    return []


def main():
    args = _argument_parser().parse_args()
    _configure_endpoints(args)
    _configure_tpc(args)
    test_files = _selected_test_files(args)

    exit_code = run_tests(test_files, args.extra_args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
