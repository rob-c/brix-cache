"""Test cases for audit16g_pmark_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16g_pmark_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16g_pmark_flags_helpers")


@_needs_ipv6
def test_the_kernel_admits_one_exclusive_holder_per_label():
    """The mechanism behind #74 and #75, and the cure, in four setsockopt calls.

    Nothing brix-side runs here: this pins the kernel behaviour the two findings
    rest on, so a future reader can tell "the label was scarce" from "brix asked
    for it to be scarce".  IPV6_FL_S_EXCL admits exactly one holder; the shares
    brix does not use admit four.
    """
    exclusive = _expression_1()
    try:
        held = _expression_2(exclusive)
        _check_test_the_kernel_admits_one_exclusive_holder_per_label_3(held, exclusive)
    finally:
        for sock in exclusive:
            _guard_test_the_kernel_admits_one_exclusive_holder_per_label_1(sock)

    shared = _expression_3()  # S_USER
    try:
        held = _expression_4(shared)
        _check_test_the_kernel_admits_one_exclusive_holder_per_label_4(held, shared)
    finally:
        for sock in shared:
            _guard_test_the_kernel_admits_one_exclusive_holder_per_label_2(sock)


# --------------------------------------------------------------------------- #
# §G — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, *, knobs="", srv="", http="", outer="", stream="",
           stream_main=""):
    """`nginx -t` the scaffold with one slot filled.

    Every slot is rendered with a trailing newline and the scaffold's own
    indentation, so a filled slot reads like the line an operator would type.
    """
    def _block(text, indent):
        if not text:
            return ""
        return "".join(f"{indent}{line}\n" for line in text.splitlines())

    return nginx_t(
        "nginx_audit16gparse.conf", tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path),
        DATA=str(tmp_path),
        KNOBS=_block(knobs, " " * 12),
        SRV_KNOBS=_block(srv, " " * 8),
        HTTP_KNOBS=_block(http, " " * 4),
        OUTER=_block(outer, ""),
        STREAM_KNOBS=_block(stream, " " * 8),
        STREAM_MAIN=_block(stream_main, " " * 4))


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["on", "off"])
def test_both_arms_parse_in_a_webdav_location(tmp_path, name, value):
    """The pair at parse level, for all six.  This is the claim the audit's
    step-2 measurement says nothing in the corpus had ever made: the word
    ``off``, written out, for a directive whose OFF behaviour had only ever been
    reached by leaving it out — or, for the three that default to 1, never
    reached at all."""
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode == 0, f"{name} {value} was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["on", "off"])
def test_both_arms_parse_in_a_stream_server(tmp_path, name, value):
    """The same six names on the root:// plane.  They are one X-macro
    (directives.h) instantiated twice, and this is the half a WebDAV-only test
    would never touch: NGX_STREAM_SRV_CONF, a different command table and a
    different conf type."""
    result = _parse(tmp_path, stream=f"{name} {value};")
    assert result.returncode == 0, \
        f"{name} {value} was refused on the stream plane:\n{result.stderr}"


@_needs_nginx
def test_the_documented_firefly_only_stream_recipe_parses(tmp_path):
    """The one place the corpus already wrote an ``off`` arm was documentation:
    docs/10-reference/comparison/deployment-reference.md offers a root:// server
    with ``brix_pmark_flowlabel off`` as "Firefly-only parity with stock
    XRootD".  It is the advertised way to run the feature and nothing executed
    it, on either plane, until this file — so the recipe is pinned as a whole
    rather than only as four independent directives."""
    result = _parse(tmp_path, stream="brix_pmark on;\n"
                                     "brix_pmark_firefly on;\n"
                                     "brix_pmark_scitag_cgi on;\n"
                                     "brix_pmark_flowlabel off;")
    assert result.returncode == 0, \
        f"the documented firefly-only recipe was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["maybe", "1", "0", "yes", "true", '""'])
def test_a_non_boolean_value_is_refused(tmp_path, name, value):
    """ngx_conf_set_flag_slot accepts the two words and nothing else.  ``1``,
    ``0``, ``yes`` and ``true`` are the spellings an operator brings from other
    software, and every one of them is an error rather than a silent truth
    value — which matters most for ``0``, where a silent truthy read would turn
    an intended disable into an enable."""
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode != 0, f"{name} {value} was accepted"
    assert "invalid value" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["ON", "OFF", "On", "oFf"])
def test_the_two_words_are_matched_case_insensitively(tmp_path, name, value):
    """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so ``OFF`` is a legal
    spelling of the arm this tranche says was never written.

    Pinned rather than assumed, because it is what makes the audit's step-2
    measurement a case-insensitive grep: had it been case-sensitive, a corpus
    that wrote ``OFF`` would have been scored as never writing the off arm and
    this whole file would rest on a miscount.
    """
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode == 0, f"{name} {value} was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("args", ["", "on off"],
                         ids=["no-argument", "two-arguments"])
def test_the_wrong_arity_is_refused(tmp_path, name, args):
    line = f"{name} {args};".replace("  ", " ")
    result = _parse(tmp_path, knobs=line)
    assert result.returncode != 0, f"`{line}` was accepted"
    assert "invalid number of arguments" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
def test_writing_the_same_flag_twice_is_refused(tmp_path, name):
    """The duplicate diagnostic is what makes the scaffold carry none of the six
    itself: it arrives before any value or arity error would."""
    result = _parse(tmp_path, knobs=f"{name} on;\n{name} off;")
    assert result.returncode != 0, f"{name} was accepted twice"
    assert "is duplicate" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("slot", ["outer", "stream_main"])
def test_the_wrong_context_is_refused(tmp_path, name, slot):
    """The main context and a stream-LEVEL placement stay wrong (the stream
    plane's entries are NGX_STREAM_SRV_CONF).  The main-context case is the one
    that reads differently — the directive is not merely misplaced, it is
    unknown before any module's command table is in scope."""
    result = _parse(tmp_path, **{slot: f"{name} on;"})
    assert result.returncode != 0, f"{name} was accepted in the {slot} context"
    assert ("not allowed here" in result.stderr
            or "unknown directive" in result.stderr), result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("slot", ["srv", "http"])
def test_the_widened_http_scopes_are_accepted(tmp_path, name, slot):
    """The http plane's entries moved to the COMMON module at
    BRIX_HTTP_ALL_CONF (http_directives_ops.h): a site- or server-wide
    ``brix_pmark on`` is exactly the deployment shape SciTags wants, so the
    srv/http placements now parse and inherit downward."""
    result = _parse(tmp_path, **{slot: f"{name} on;"})
    assert result.returncode == 0, (
        f"{name} was refused in the {slot} context:\n{result.stderr}")


# --------------------------------------------------------------------------- #
# §H — the mechanism is where this file says it is                             #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text(encoding="utf-8")


def _flat(path):
    """Whitespace-flattened source, so a call that wraps across lines reads the
    same as one that does not."""
    return " ".join(_source(path).split())


class TestTheMechanismIsWhereThisFileSaysItIs:

    @pytest.mark.parametrize("name,field,default", FLAGS, ids=FLAG_NAMES)
    def test_every_flag_merges_to_its_measured_default(self, name, field,
                                                       default):
        """The claim every ``absent`` arm in this file rests on — including the
        three that default to 1, where ``absent`` is the ON arm and the
        never-written ``off`` is the only way to the other behaviour."""
        call = f"ngx_conf_merge_value(conf->{field}, prev->{field}, {default});"
        assert call in _flat(CONFIG_C), \
            f"{name} no longer merges to {default} — expected {call}"

    @pytest.mark.parametrize("name,field,_default", FLAGS, ids=FLAG_NAMES)
    def test_every_flag_is_a_plain_flag_slot_in_the_x_macro(self, name, field,
                                                           _default):
        """The tranche's subject is the 128 ``ngx_conf_set_flag_slot``
        directives; a setter of its own would put the directive in a different
        measurement and give it config-time behaviour this file never probed."""
        entry = _flat(DIRECTIVES_H).split(f'ngx_string("{name}")')[1].split("},")[0]
        assert "ngx_conf_set_flag_slot" in entry, entry
        assert "conf_scope | NGX_CONF_FLAG" in entry, entry
        assert f"common.pmark.{field}" in entry, entry

    def test_the_six_are_declared_once_and_instantiated_twice(self):
        """Why §G asks about two planes.  The stream plane instantiates the
        X-macro (directives_pmark.h); the http plane registers the family as
        literal entries on the COMMON module (http_directives_ops.h) since the
        BRIX_HTTP_ALL_CONF widening.  A third instantiation would leave this
        file's parse tier short by a plane."""
        instantiations = sorted(
            path.name for path in ROOT.joinpath("src").rglob("*.h")
            if "BRIX_PMARK_DIRECTIVES(NGX_" in path.read_text(encoding="utf-8"))
        http_ops = ROOT.joinpath(
            "src/core/config/http_directives_ops.h").read_text(encoding="utf-8")
        assert 'ngx_string("brix_pmark")' in http_ops
        assert instantiations == ["directives_pmark.h"], \
            instantiations
        source = _flat(DIRECTIVES_H)
        assert source.count("#define BRIX_PMARK_DIRECTIVES(") == 1

    def test_the_end_counter_sits_behind_the_firefly_gate(self):
        """DEFECT #72's mechanism.  The start increment is outside every gate and
        the end increment is inside the firefly one."""
        source = _flat(FIREFLY_C)
        assert "BRIX_PMARK_METRIC_INC(pmark_flows_started_total); return f; }" \
            in source, "the start counter moved out of flow_begin's tail"
        assert "if (flow->firefly_started && flow->pm->firefly) { " \
               'pmark_emit(flow, "end", 1, log); ' \
               "BRIX_PMARK_METRIC_INC(pmark_flows_ended_total);" in source, \
            "flow_end's gate changed — DEFECT #72 has to be re-measured"

    def test_the_origin_send_discards_its_result(self):
        """DEFECT #73's mechanism: one sendto is counted both ways, the other is
        cast to void."""
        source = _flat(FIREFLY_C)
        assert "(void) sendto(fd, buf, n, 0, (struct sockaddr *) &o, f->peer_len);" \
            in source, "the origin sendto now has a return path"
        assert "BRIX_PMARK_METRIC_INC(pmark_firefly_dropped_total);" in source
        assert source.count("BRIX_PMARK_METRIC_INC(pmark_firefly_sent_total);") == 1

    def test_the_probe_leases_one_fixed_label_exclusively_and_caches_it(self):
        """DEFECT #74's mechanism, in four lines of flowlabel.c: the label is a
        constant, the share is exclusive, the verdict is a per-worker static, and
        nothing retries it."""
        source = _flat(FLOWLABEL_C)
        assert "fl.flr_label = htonl(brix_pmark_flowlabel_encode(" \
               "BRIX_PMARK_EXP_MIN, BRIX_PMARK_ACT_MIN));" in source, \
            "the probe's label is no longer the structural minimum"
        assert "fl.flr_share = PMARK_FL_S_EXCL;" in source
        assert "static int pmark_fl_usable = -1;" in source
        assert source.count("pmark_fl_usable = 0;") == 1
        assert "#define PMARK_FL_S_EXCL 1" in source
        assert PROBE_NOTICE in source, \
            "the probe's NOTICE was reworded, so _probe_declined is now blind"

    def test_the_two_entry_points_order_the_probe_differently(self):
        """DEFECT #76's mechanism, as a pair of orders rather than a claim.

        apply() puts the capability probe in the same condition as its fd check,
        so it runs before getpeername tells anyone the peer's family; apply_addr()
        tests the family first and short-circuits, so a v4 destination never
        probes.  One of the two is wrong, and the tests above say which behaviour
        each order produces.
        """
        source = _flat(FLOWLABEL_C)
        assert "if (fd < 0 || brix_pmark_flowlabel_usable(log) != NGX_OK) { " \
               "return NGX_DECLINED; } " in source, \
            "apply()'s probe is no longer ahead of the family gate"
        assert "|| dst->sa_family != AF_INET6 " \
               "|| brix_pmark_flowlabel_usable(log) != NGX_OK)" in source, \
            "apply_addr() no longer short-circuits on family before probing"

    def test_the_per_flow_label_carries_five_entropy_bits(self):
        """DEFECT #75's mechanism: the mask decides how many labels one
        (experiment, activity) pair can ever spell, and the exclusive share
        decides that each is spelled once."""
        assert f"#define BRIX_PMARK_FL_ENTROPY_MASK 0x{FL_ENTROPY_MASK:08X}u" \
            in _flat(PMARK_H)
        assert bin(FL_ENTROPY_MASK).count("1") == 5
        source = _flat(FLOWLABEL_C)
        assert "label = brix_pmark_flowlabel_encode(exp, act) " \
               "| ((uint32_t) ngx_random() & BRIX_PMARK_FL_ENTROPY_MASK);" in source
        assert source.count("fl.flr_share = PMARK_FL_S_EXCL;") == 2

    def test_a_copy_is_marked_without_consulting_http_plain(self):
        """§D's mechanism: the method test short-circuits for COPY before
        http_plain is read."""
        assert "if (!conf->common.pmark.enable || (r->method != NGX_HTTP_COPY " \
               "&& !(conf->common.pmark.http_plain && (r->method == NGX_HTTP_GET " \
               "|| r->method == NGX_HTTP_PUT))))" in _flat(DISPATCH_C), \
            "webdav_dispatch_pmark's method gate changed"
