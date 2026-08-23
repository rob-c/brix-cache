# --------------------------- P1: cross-connection bind handle races ----------


def _send_readv_attack(connection, handle, offset):
    segments = b"".join(
        struct.pack("!4siq", handle, 1 << 20, offset + index * (1 << 20))
        for index in range(8)
    )
    connection.sendall(_frame(kXR_readv, b"", segments))


def _send_write_attack(connection, handle):
    status, body = _open(connection, "/w.bin", flags=0x0010 | 0x0020)
    write_handle = body[:4] if status == kXR_ok and len(body) >= 4 else handle
    request = struct.pack("!4sqB3s", write_handle, 0, 0, b"\x00" * 3)
    connection.sendall(_frame(kXR_write, request, b"Z" * (1 << 20)))


def _send_aio_attack(connection, rng, handle):
    operation = rng.choice(("pgread", "readv", "write"))
    offset = rng.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
    if operation == "pgread":
        length = rng.choice((8 << 20, 16 << 20))
        connection.sendall(_frame(
            kXR_pgread, struct.pack("!4sqi", handle, offset, length)
        ))
        return
    if operation == "readv":
        _send_readv_attack(connection, handle, offset)
        return
    _send_write_attack(connection, handle)


def _aio_rst_round(port, rng):
    connection = None
    try:
        connection = _connect(port, 4)
        _login(connection)
        status, body = _open(connection, "/big.bin", flags=0x0010)
        if status == kXR_ok and len(body) >= 4:
            _send_aio_attack(connection, rng, body[:4])
    except Exception:
        pass
    finally:
        if connection is not None:
            delay = rng.choice((0, 0.0005, 0.003))
            if delay:
                time.sleep(delay)
            _rst(connection)


def _aio_rst_worker(port, datadir, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        _aio_rst_round(port, rng)



def _http(method, path, body=None, timeout=4, port=None):
    import urllib.request, urllib.error
    url = "http://%s:%d%s" % (HOST, port or _XP_HTTP[0], path)
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


_XP_HTTP = [0]
_XP_S3 = [0]
