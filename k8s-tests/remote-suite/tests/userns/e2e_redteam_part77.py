def run_broker_failclosed(key, data, port, s3port, sock, tok_alice):
    broker_pid = _kill_broker(sock)
    if broker_pid is None:
        return
    _assert_broker_put_closed(data, port, tok_alice)
    _assert_broker_lock_closed(port, tok_alice)
    _assert_broker_s3_closed(data, s3port)


def _kill_broker(sock):
    try:
        with open(sock + ".pid") as fh:
            bpid = int(fh.read().strip())
        os.kill(bpid, 9)
        _wait_for_broker_death(bpid)
        return bpid
    except (OSError, ValueError) as e:  # noqa: BLE001
        ok(False, f"could not kill broker for fail-closed test: {e}")
        return None


def _wait_for_broker_death(pid):
    for _ in range(30):
        if not os.path.exists(f"/proc/{pid}"):
            return
        time.sleep(0.1)


def _assert_broker_put_closed(data, port, tok_alice):
    st, _ = http("PUT", "/alice/after_broker_killed.txt", port, tok_alice, b"x\n")
    fp = os.path.join(data, "alice", "after_broker_killed.txt")
    created = os.path.exists(fp)
    bad_owner = created and os.stat(fp).st_uid != UID_ALICE
    ok(st not in (200, 201, 204) and not (created and bad_owner),
       f"broker killed -> PUT FAILS CLOSED, not silently done as worker "
       f"(HTTP {st}, created={created}, wrong_owner={bad_owner})")


def _assert_broker_lock_closed(port, tok_alice):
    st, _ = http("LOCK", "/alice/hello.txt", port, tok_alice,
                 data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                      b'<D:lockscope><D:exclusive/></D:lockscope>'
                      b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                 hdrs={"Content-Type": "application/xml"})
    ok(st not in (200, 201),
       f"broker killed -> LOCK (xattr op) FAILS CLOSED (HTTP {st})")


def _assert_broker_s3_closed(data, s3port):
    if not s3port:
        return
    st, _ = s3("PUT", "alice/after_broker_s3.txt", s3port, data=b"x\n")
    sfp = os.path.join(data, "alice", "after_broker_s3.txt")
    s_created = os.path.exists(sfp)
    s_bad = s_created and os.stat(sfp).st_uid != UID_ALICE
    ok(st not in (200, 201) and not (s_created and s_bad),
       f"broker killed -> S3 PUT FAILS CLOSED (HTTP {st}, created={s_created})")


if __name__ == "__main__":
    sys.exit(main())
