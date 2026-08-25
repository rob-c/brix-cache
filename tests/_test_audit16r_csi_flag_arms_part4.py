# --------------------------------------------------------------------------- #
# §G — the declarations, the merges and the corpus                            #
# --------------------------------------------------------------------------- #

def _squashed(path):
    return " ".join(path.read_text().split())


# Where the audit's step-1/step-2 grep looks, and the suffixes it counts.  As in
# file 17, these directives are configured from test sources and documented in
# prose rather than from a rendered template, so a census restricted to
# `configs/` would report a gap that is not there and miss the one that is.
CORPUS_ROOTS = (ROOT / "tests", ROOT / "docs", ROOT / "k8s-tests")
CORPUS_SUFFIXES = (".py", ".conf", ".md", ".sh")


def _corpus_writes(token):
    """Every file OUTSIDE this test's own modules that spells `token`
    literally.  The facade and its shards are one test split by TS-5, so the
    off-arm constants the facade defines for the live negatives must not read
    as the corpus writing the arm."""
    here = Path(__file__).resolve()
    own = {here} | {p.resolve() for p in
                    here.parent.glob("*test_audit16r_csi_flag_arms*.py")}
    hits = []
    for root in CORPUS_ROOTS:
        hits.extend(_corpus_root_writes(root, token, own))
    return sorted(hits)


def _corpus_root_writes(root, token, own):
    hits = []
    for path in root.rglob("*"):
        hit = _corpus_hit(path, token, own)
        if hit:
            hits.append(hit)
    return hits


def _corpus_hit(path, token, own):
    if path.suffix not in CORPUS_SUFFIXES or not path.is_file():
        return None
    if path.resolve() in own:
        return None
    try:
        present = token in path.read_text(errors="replace")
    except OSError:                              # pragma: no cover - diagnostic
        return None
    return str(path.relative_to(ROOT)) if present else None


class TestTheDeclarationsAndTheCorpus:
    """Every reading above is an inference from a handful of lines of C and from
    what the corpus does not contain.  If either changes, the tests would keep
    passing while measuring something else."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_declaration_is_a_server_scoped_flag_slot(self, directive):
        """One scope, ``ngx_conf_set_flag_slot``, NGX_STREAM_SRV_CONF_OFFSET —
        the shape §F measures and the promise §A's per-server control keeps."""
        text = DIRECTIVES_H.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:5]]
        assert lines[0] == "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,", lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_STREAM_SRV_CONF_OFFSET,", lines
        assert lines[3] == ("offsetof(ngx_stream_brix_srv_conf_t, "
                            f"csi.{SUBJECTS[directive]}),"), lines

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_is_declared_on_the_stream_plane_only(self, directive):
        """Unlike file 17's three, these two names have no http twin anywhere in
        ``src/`` — so a WebDAV or S3 export has no way to ask for either
        behaviour, and §F has one plane to measure rather than two."""
        elsewhere = [str(path.relative_to(ROOT))
                     for path in sorted(SRC_DIR.rglob("*.c"))
                     if f'ngx_string("{directive}")' in
                     path.read_text(errors="replace")]
        assert elsewhere == [], elsewhere

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_initialises_unset_and_merges_to_zero(self, directive):
        """The two routes to the same value that §A and §B each measure: absence
        arrives as NGX_CONF_UNSET and is merged to 0, which is what makes ``off``
        the arm nobody needed to write and ``on`` the arm everybody did."""
        field = SUBJECTS[directive]
        squashed = _squashed(CONF_STRUCTS_H)
        assert f"c->{field} = NGX_CONF_UNSET;" in squashed
        assert f"ngx_conf_merge_value(c->{field}, p->{field}, 0);" in squashed

    def test_the_master_switch_defaults_the_other_way(self):
        """``brix_csi`` merges to 1 while both subjects merge to 0 — the engine
        runs by default and neither policy is on by default.  This asymmetry is
        why the corpus wrote ``on`` for the subjects and why §A's floor is a
        recording export rather than a bare one."""
        assert "ngx_conf_merge_value(c->enable, p->enable, 1);" in \
            _squashed(CONF_STRUCTS_H)

    def test_the_read_path_is_the_only_reader_of_either_field(self):
        """Both flags are consulted in one function, on the open path, and
        nowhere else in ``src/`` — which is why §A and §B can each hold three
        arms in one worker, and why §C's nesting is the whole story."""
        readers = _csi_reader_files()
        assert readers == {
            "src/protocols/root/read/open_resolved_file_finalize.c"}, readers

    def test_the_endpoint_banner_says_nothing_about_integrity(self):
        """The source behind §C's silence: the startup census that names the
        export, the mode and the auth scheme has no CSI branch at all."""
        text = POSTCONF_C.read_text()
        assert "root:// endpoint ready" in text
        assert "csi" not in text.lower()

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_corpus_writes_the_on_arm_and_never_the_off_arm(self,
                                                               directive):
        """Steps 1 and 2 of the audit's own measurement, as this file found
        them.  If another file starts writing ``off``, re-run the gap table
        rather than relaxing this."""
        assert _corpus_writes(f"{directive} on;"), \
            f"{directive} is written nowhere at all"
        assert _corpus_writes(f"{directive} off;") == []

    @pytest.mark.parametrize("arm", OFF_ARMS)
    def test_this_file_writes_every_off_arm_literally(self, arm):
        """The closure itself.  The audit greps the tree for
        ``<directive> <value>;``, so an arm assembled at runtime from a name and
        a token would leave the gap open while the tests passed."""
        assert arm in Path(__file__).read_text()

    def test_the_only_other_exerciser_is_a_gated_live_script(self):
        """Why this file exists next to ``gsi_trust_live.py``: that script needs
        a built native ``xrdcp``, is not collected by pytest, and writes its
        control arm as absence.  Pinned so a future reader does not delete one
        as a duplicate of the other."""
        script = ROOT / "tests/cmdscripts/gsi_trust_live.py"
        text = script.read_text()
        assert "brix_csi_trust_fs on;" in text
        assert "brix_csi_require on;" in text
        assert "brix_csi_trust_fs off;" not in text
        assert "brix_csi_require off;" not in text
        assert "native xrdcp not built" in text

    def test_the_template_carries_four_csi_slots_and_writes_no_arm(self):
        """The template offers a whole CSI block per listener and takes no
        position on either subject: four root:// servers, one export, and not
        one of the four arms written in the file itself."""
        text = (CONFIGS_DIR / TEMPLATE).read_text()
        _assert_template_slots(text)
        squashed = " ".join(text.split())
        _assert_template_omits_arms(squashed)
        _assert_template_shape(squashed)

    def test_the_ledger_owns_one_port_per_listener(self):
        """Four sockets, four ledger allocations, all distinct.  Four acceptors
        rather than one restarted four times is what makes §A's and §B's
        per-server controls possible at all."""
        slot = LIFECYCLE_SHARED_PORTS[NAME]
        ports = [slot["port"], *slot["extra"].values()]
        assert sorted(slot["extra"]) == ["B_PORT", "C_PORT", "D_PORT"]
        assert len(set(ports)) == 4, ports


def _csi_reader_files():
    paths = (path for path in sorted(SRC_DIR.rglob("*"))
             if path.suffix in (".c", ".h") and path.is_file())
    return {str(path.relative_to(ROOT)) for path in paths
            if _reads_csi_policy(path)}


def _reads_csi_policy(path):
    text = path.read_text(errors="replace")
    return any(("conf->csi.require" in text, "conf->csi.trust_fs" in text))


def _assert_template_slots(text):
    for slot in ("{A_CSI}", "{B_CSI}", "{C_CSI}", "{D_CSI}"):
        assert slot in text, slot


def _assert_template_omits_arms(squashed):
    for directive in SUBJECTS:
        assert f"{directive} on;" not in squashed, directive
        assert f"{directive} off;" not in squashed, directive


def _assert_template_shape(squashed):
    assert squashed.count("brix_root on;") == 4
    assert squashed.count("brix_auth none;") == 4
    assert squashed.count("{DATA_ROOT}") == 4
