from split_continuation import reexport as _reexport
def _guard_test_metrics_ipv6_label_cardinality_bounded_1(status):
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")

def _check_test_metrics_ipv6_label_cardinality_bounded_1(status):
    assert status == 200, status

def _guard_test_metrics_ipv6_label_cardinality_bounded_2(saw_any):
    if not saw_any:
        pytest.skip("no labeled metrics emitted yet on the ipv6-mgr instance")


_reexport(globals(), "_test_ipv6_admin_ratelimit_metrics_helpers")

@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_metrics_ipv6_label_cardinality_bounded():
    """REGRESSION / invariant #8: every metric label *value* is drawn from the
    bounded low-cardinality character set (alnum + ``_ . - /`` and ``r/s``-style
    rate tokens) — no path, bucket-name, UUID, or peer address ever leaks into a
    label.  This is the structural form of the cardinality invariant: a colon
    (the giveaway of an IPv6 literal or a host:port) must never appear in a label
    value, and the distinct label-key set stays small."""
    _skip_unless_mgr_http()
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    _guard_test_metrics_ipv6_label_cardinality_bounded_1(status)
    _check_test_metrics_ipv6_label_cardinality_bounded_1(status)
    text = body.decode("utf-8", "replace")

    label_keys = set()
    # ':' is allowed only for the bounded cluster-server identity (host:port);
    # every other key forbids it (it would be an IPv6 literal or a host:port
    # smuggled into a non-identity axis).
    bad_char_re = re.compile(r"[^A-Za-z0-9_./\-+ ]")
    saw_any = False
    for name, block in _metric_label_blocks(text):
        for k, v in _label_pairs(block):
            saw_any = True
            label_keys.add(k)
            if k in _CLUSTER_IDENTITY_LABEL_KEYS:
                # Bounded cluster-membership identity (host:port, IPv4 or IPv6),
                # the Prometheus ``instance=`` analogue — colon permitted.
                continue
            # No colon (would be an IPv6 literal or host:port) and no other
            # high-cardinality punctuation in any non-identity value.
            def _assert_test_metrics_ipv6_label_cardinality_bounded_2():
                assert ":" not in v, (
                    f"colon in metric label value {name}{{{k}=\"{v}\"}}")
                assert not bad_char_re.search(v), (
                    f"high-cardinality char in metric label value "
                    f"{name}{{{k}=\"{v}\"}}")

            _assert_test_metrics_ipv6_label_cardinality_bounded_2()
    _guard_test_metrics_ipv6_label_cardinality_bounded_2(saw_any)
    # The label-key axis is small and *enumerable*: every key is a bounded,
    # closed-set dimension (an opcode, a status class, a listener port, a
    # histogram bucket boundary, the pipeline depth, ...), never an unbounded
    # axis (path, bucket name, UUID, peer address).  Asserting the emitted keys
    # are a SUBSET of this allow-list catches a cardinality regression by *name*
    # — a rogue high-cardinality key trips it even if the total count stays low,
    # which a bare count cap would miss.  Add a key here only after confirming it
    # is genuinely closed-set.
    allowed_label_keys = {
        "action",        # write-through stage throttle action: wait/reject
        "auth",          # auth method: anon/gsi/token/sss/krb
        "backend",       # storage backend driver name (fs_list.h census: posix/pblock/...)
        "class",         # cvmfs request class: cas/manifest/geo
        "depth",         # request-pipeline depth bucket (phase-29)
        "direction",     # in/out (read vs write data direction)
        "event",         # lifecycle event class
        "le",            # Prometheus histogram bucket upper bound
        "method",        # HTTP method (GET/PUT/...)
        "mode",          # server mode (standalone/manager/...)
        "op",            # protocol opcode (read/stat/open/...)
        "outcome",       # cred-deleg gate terminal outcome (ENUM: 3 fixed values)
        "plane",         # data vs control plane
        "port",          # listener port (closed set of configured listeners)
        "proto",         # protocol (root/https/s3/...)
        "reason",        # bounded reason code
        "result",        # ok/error/...
        "server",        # cluster-membership identity (host:port) — see above
        "source",        # cvmfs bytes-served source: hit/fill
        "status",        # protocol/HTTP status code
        "status_class",  # 2xx/4xx/5xx aggregate
        "surface",       # request surface (api/data/admin/...)
    }
    rogue = label_keys - allowed_label_keys
    def _assert_test_metrics_ipv6_label_cardinality_bounded_1():
        assert not rogue, (
            "unexpected (possibly high-cardinality) metric label key(s)",
            sorted(rogue), "all keys:", sorted(label_keys))
        # Backstop: even within the allow-list the live key set must stay small.
        assert len(label_keys) <= len(allowed_label_keys), (
            "metric label-key cardinality too high",
            sorted(label_keys))

    _assert_test_metrics_ipv6_label_cardinality_bounded_1()
