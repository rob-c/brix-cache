from split_continuation import reexport as _reexport
def _check_test_cse_and_close_gate_through_proxy_1(st):
    assert st == kXR_status, f"proxy must pass the CSE frame, got {st}"

def _check_test_cse_and_close_gate_through_proxy_2(st, err):
    assert st == kXR_error and err == kXR_ChkSumErr, (st, err)


_reexport(globals(), "_test_pgwrite_cse_helpers")

class TestProxyPassthrough:
    def _proxy_port(self):
        try:
            from settings import PROXY_PURE_NGINX_PROXY_PORT
            return PROXY_PURE_NGINX_PROXY_PORT
        except Exception:
            return None

    def test_cse_and_close_gate_through_proxy(self):
        port = self._proxy_port()
        if port is None:
            pytest.skip("no pure-nginx proxy port configured")
        try:
            sock = _handshake_login(_HOST, port)
        except OSError:
            pytest.skip(f"proxy not listening on {port}")
        try:
            fh = _open(sock, b"/_cse_proxy.bin")
            data = os.urandom(kXR_pgPageSZ * 2)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_crc=[0, 1]))
            _check_test_cse_and_close_gate_through_proxy_1(st)
            _c, _f, _l, offs, ok = parse_cse(cse)
            def _assert_test_cse_and_close_gate_through_proxy_1():
                assert ok, "cseCRC must survive the proxy intact"
                assert offs == [0, kXR_pgPageSZ], offs

            _assert_test_cse_and_close_gate_through_proxy_1()
            # The close gate must propagate through the proxy.
            st, err = _close(sock, fh)
            _check_test_cse_and_close_gate_through_proxy_2(st, err)
        finally:
            sock.close()
