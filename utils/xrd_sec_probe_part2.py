#!/usr/bin/env python3
"""xrd_sec_probe continuation shard: concurrency probes (CC-01/CC-02) moved out
to keep xrd_sec_probe.py under the 600-logical-line cap.

Not a standalone module and imported WITHOUT referencing xrd_sec_probe (which
runs as __main__), so the helpers are handed in via register_extra() rather than
imported — avoiding a circular / double-__main__ import.  register_extra() runs
the @probe decorators, appending these probes to the shared PROBES registry in
their original order (called at the tail of xrd_sec_probe, after all others)."""
import struct
import threading


def register_extra(probe, connect, do_login, ping_req, recv_resp,
                   safe_close, stat_req, kXR_ok):
    @probe("CC-01  16 threads × 50 pings simultaneously")
    def _():
        errors = []
        def worker(idx):
            try:
                s = connect(); do_login(s)
                for i in range(50):
                    s.sendall(ping_req(struct.pack(">H", (idx*50+i)%0xFFFE+1)))
                ok = 0
                for _ in range(50):
                    try:
                        st, _ = recv_resp(s)
                        if st == kXR_ok: ok += 1
                    except: break
                safe_close(s)
                if ok < 50: errors.append(f"thread {idx}: {ok}/50 pings ok")
            except Exception as e: errors.append(f"thread {idx}: {e}")
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in ts: t.start()
        for t in ts: t.join(30)
        if errors:
            return ("FINDING", "Concurrent ping errors: " + "; ".join(errors[:3]),
                    "16 simultaneous connections each sending 50 pings")

    @probe("CC-02  8 ping threads + 8 stat threads concurrently")
    def _():
        errors = []
        def ping_w():
            try:
                s = connect(); do_login(s)
                for i in range(20):
                    s.sendall(ping_req(struct.pack(">H", i+1)))
                    st, _ = recv_resp(s)
                    if st != kXR_ok: errors.append(f"ping {i}→{st}")
                safe_close(s)
            except Exception as e: errors.append(f"ping: {e}")
        def stat_w():
            try:
                s = connect(); do_login(s)
                for i in range(20):
                    s.sendall(stat_req(b'/test.bin', sid=struct.pack(">H", i+1)))
                    st, _ = recv_resp(s)
                    if st != kXR_ok: errors.append(f"stat {i}→{st}")
                safe_close(s)
            except Exception as e: errors.append(f"stat: {e}")
        ts = ([threading.Thread(target=ping_w) for _ in range(8)]
            + [threading.Thread(target=stat_w) for _ in range(8)])
        for t in ts: t.start()
        for t in ts: t.join(30)
        if errors:
            return ("FINDING", "; ".join(errors[:4]),
                    "8 ping threads + 8 stat threads simultaneously")
