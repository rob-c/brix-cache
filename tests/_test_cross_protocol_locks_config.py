"""Configuration-negative continuation for test_cross_protocol_locks.py."""


def _write_bad_enforcement_conf(directory: str) -> str:
    os.makedirs(os.path.join(directory, "logs"), exist_ok=True)
    os.makedirs(os.path.join(directory, "exp"), exist_ok=True)
    conf = os.path.join(directory, "nginx.conf")
    modules = [module for module in os.environ.get(
        "TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if module]
    with open(conf, "w") as conf_file:
        conf_file.write("".join(f"load_module {module};\n" for module in modules)
                        + f"error_log {directory}/logs/e.log info;\n"
                        + f"pid {directory}/logs/n.pid;\n"
                        + "events {}\nstream {\n  server {\n"
                        + f"    listen {BIND_HOST}:{SHARED_PARSE_PLACEHOLDER_PORT};\n"
                        + "    brix_root on;\n    brix_auth none;\n"
                        + f"    brix_export {directory}/exp;\n"
                        + "    brix_allow_write on;\n"
                        + "    brix_lock_enforcement yes;\n"
                        + "  }\n}\n")
    return conf


def test_lock_enforcement_bad_value_refused_at_nginx_t():
    """``brix_lock_enforcement yes`` is rejected during nginx parsing."""
    _need_nginx()
    with tempfile.TemporaryDirectory() as directory:
        conf = _write_bad_enforcement_conf(directory)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", conf, "-p", directory],
            capture_output=True, text=True, timeout=30, env=env)
    output = result.stdout + result.stderr
    assert result.returncode != 0, "nginx -t accepted brix_lock_enforcement yes"
    assert 'invalid value "yes"' in output, output[-1500:]
