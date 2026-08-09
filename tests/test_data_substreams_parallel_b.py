from split_continuation import reexport as _reexport
_reexport(globals(), "_test_data_substreams_parallel_helpers")

class TestClientDownloadFanout:
    """The BriX client (`brix-xrdcp`) also fans a DOWNLOAD across the bound
    secondaries BY DEFAULT (streams=4).  kXR_read carries no pathid, so a read
    issued on a bound secondary is served there against the primary-published
    handle; the client round-robins its reads over primary+secondaries.  Any
    secondary miss falls back to the primary read, so this is byte-exact even
    against a server that won't serve bound reads."""

    def test_default_download_fans_out_byte_exact(self, endpoint, tmp_path):
        host, port = endpoint
        # The download reads XRDC_COPY_CHUNK (8 MiB) per pump iteration, so the
        # file must span several chunks for the round-robin to reach a secondary:
        # 40 MiB → 5 reads → offsets 8/16/24 MiB land on bound secondaries.
        size = 40 * 1024 * 1024
        content = _det(size)
        name = "client-dl-fanout.bin"
        _write_data_file(name, content)            # seed the server export
        dst = tmp_path / "dl-fanout.bin"

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "-f", f"root://{host}:{port}//{name}", str(dst)],
            capture_output=True, text=True, env=env, timeout=120)
        assert res.returncode == 0, f"xrdcp download failed: {res.stderr}"

        assert dst.read_bytes() == content, "client download not byte-exact"

        dbg = [l for l in res.stderr.splitlines() if "download substreams=" in l]
        assert dbg, f"no download substream diagnostic emitted: {res.stderr}"
        # e.g. "brix: download substreams=3 chunks-on-secondaries=96"
        n_sec = int(dbg[-1].split("substreams=")[1].split()[0])
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert n_sec >= 1, "client did not establish any bound secondary by default"
        assert on_sec > 0, "no chunks were read on a secondary (silent fallback?)"

    def test_parallel_striped_download_byte_exact(self, endpoint, tmp_path):
        """--parallel runs the TRUE concurrent striped download: one thread per
        bound connection, each pwrite-ing its disjoint byte range.  The stripes
        are reassembled by offset, so the file is byte-exact; the diagnostic
        proves >=2 stripes actually ran (real multi-stream, not the serial pump)."""
        host, port = endpoint
        size = 40 * 1024 * 1024                    # 4 stripes of 10 MiB @ streams=4
        content = _det(size)
        name = "client-par-dl.bin"
        _write_data_file(name, content)
        dst = tmp_path / "par-dl.bin"

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "--parallel", "-S", "4", "-f",
             f"root://{host}:{port}//{name}", str(dst)],
            capture_output=True, text=True, env=env, timeout=120)
        assert res.returncode == 0, f"parallel download failed: {res.stderr}"
        assert dst.read_bytes() == content, "parallel striped download not byte-exact"

        dbg = [l for l in res.stderr.splitlines() if "parallel-download stripes=" in l]
        assert dbg, f"parallel path did not engage: {res.stderr}"
        stripes = int(dbg[-1].split("stripes=")[1].split()[0])
        assert stripes >= 2, f"expected >=2 concurrent stripes, got {stripes}"



class TestSubwrittenChecksumParity:
    """S5 (phase-94 §4.4): a file written across bound secondaries (disjoint,
    possibly out-of-order pwrites@offset) must hash IDENTICALLY to the same bytes
    written on a single stream.  We upload the same content twice — once with the
    default streams=4 fan-out (genuinely sub-written: we assert chunks-on-secondaries>0
    so the parity check is not vacuous) and once single-stream (-S 1) — then ask the
    SERVER to checksum both.  Guards against a future streaming/rolling digest that
    would silently break under out-of-order disjoint substream writes."""

    def test_subwritten_file_checksum_matches_single_stream(self, endpoint, tmp_path):
        host, port = endpoint
        size = 8 * 1024 * 1024                      # spans many 64 KiB chunks
        content = _det(size)
        src = tmp_path / "cksum-src.bin"
        src.write_bytes(content)

        sub_name = "cksum-subwritten.bin"
        one_name = "cksum-singlestream.bin"
        _rm_export_file(sub_name)
        _rm_export_file(one_name)

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        # (1) sub-written: default streams=4 fan-out across bound secondaries
        r_sub = subprocess.run(
            [_XRDCP, "-f", str(src), f"root://{host}:{port}//{sub_name}"],
            capture_output=True, text=True, env=env, timeout=120)
        assert r_sub.returncode == 0, f"sub-written upload failed: {r_sub.stderr}"
        dbg = [l for l in r_sub.stderr.splitlines() if "upload substreams=" in l]
        assert dbg, f"no upload diagnostic: {r_sub.stderr}"
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert on_sec > 0, "parity test vacuous: no chunks landed on a secondary"

        # (2) single-stream reference: -S 1 forces one connection
        r_one = subprocess.run(
            [_XRDCP, "-f", "-S", "1", str(src), f"root://{host}:{port}//{one_name}"],
            capture_output=True, text=True, timeout=120)
        assert r_one.returncode == 0, f"single-stream upload failed: {r_one.stderr}"

        # both landed byte-exact on disk
        assert _read_export_file(sub_name) == content
        assert _read_export_file(one_name) == content

        # the SERVER's checksum of the sub-written file equals the single-stream one
        algo_sub, ck_sub = _server_checksum(host, port, sub_name)
        algo_one, ck_one = _server_checksum(host, port, one_name)
        assert algo_sub == algo_one, f"algo mismatch {algo_sub} vs {algo_one}"
        assert ck_sub == ck_one, (
            f"sub-written checksum {ck_sub} != single-stream {ck_one} "
            f"({algo_sub}) — out-of-order substream writes corrupted the digest")

        # and it matches an independent computation of the source bytes
        if algo_sub == "adler32":
            assert ck_sub == format(zlib.adler32(content) & 0xffffffff, "08x")
        elif algo_sub in ("crc32", "crc32c"):
            assert ck_sub == format(zlib.crc32(content) & 0xffffffff, "08x") \
                or algo_sub == "crc32c"   # crc32c differs from zlib crc32; parity above suffices
