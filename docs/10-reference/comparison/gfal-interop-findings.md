# gfal2 Interop Findings — A Production WLCG Client, and the WebDAV Bug It Exposed

> **What this is.** A record of what testing **gfal2** (the WLCG data-management
> layer that FTS and Rucio drive — `gfal-copy`/`gfal-ls`/`gfal-stat`/`gfal-sum`/…)
> against this module revealed. Unlike go-hep, gfal2 is **not** a protocol
> reimplementation: its xrootd plugin links the official `libXrdCl` and its http
> plugin uses `davix`. So it validates the server against the *reference* client at
> a higher API layer (`root://`) and against a *different* protocol stack
> (`davs://`) — which is exactly where it surfaced a real server bug.
>
> Companion: [`xrootd-implementations.md`](xrootd-implementations.md) §7.6.
> Regression tests: `tests/test_gfal_interop.py`.

---

## 1. What gfal2 is (and why it is a stronger probe than `xrdcp`/`curl`)

gfal2 (`gfal2-util` CLIs + the `gfal2` C library) dispatches by URL scheme to
backend plugins:

| Scheme | gfal2 plugin | Underlying engine |
|---|---|---|
| `root://`, `roots://` | `libgfal_plugin_xrootd.so` | the **reference `libXrdCl`** (XRootD C++) |
| `http(s)://`, `davs://` | `libgfal_plugin_http.so` | **`davix`** (HTTP/WebDAV) |
| `gsiftp://` / `srm://` / `s3://` / `sftp://` / `dcap://` | respective plugins | (out of scope here) |

It adds, *above* the transport: a uniform open/copy/stat/checksum API,
**third-party-copy** orchestration (the FTS engine), protocol fallback, retry
policy, and checksum integration (`gfal-sum`; for HTTP it sends RFC 3230
**Want-Digest** and reads the `Digest:` response). "Interoperates with gfal2" is
therefore a stronger claim than "interoperates with `xrdcp`": it is the client
production grid data movement actually uses.

Environment tested: gfal2 2.23.5 / gfal2-util 1.9.1, with both
`libgfal_plugin_xrootd.so` (→ `libXrdCl.so.3`) and `libgfal_plugin_http.so`.

---

## 2. `root://` — fully working (10/10)

gfal2's xrootd plugin (driving `libXrdCl`) against our `root://` stream module ran
the complete file lifecycle, all green:

`gfal-mkdir` · upload (1 MiB) · `gfal-ls -l` · `gfal-stat` (correct size) ·
byte-identical download · `gfal-sum adler32` · `gfal-sum crc32c` (matches our own
`client/bin/xrdcrc32c`) · `gfal-rename` · `gfal-cat` · `gfal-rm`.

Because this path *is* `libXrdCl`, it transitively re-validates the server against
the reference client one API layer above `xrdcp`. No defects found.

---

## 3. `davs://` — the bug it exposed: a file's size reported as the filesystem's

**Symptom.** Data transfers worked (upload, ls, byte-identical download, rm;
`gfal-sum adler32` via our streaming Want-Digest filter), but **`gfal-stat`
reported a garbage size of ~839 GB** for a 1 MiB file — and the value **varied
run-to-run**.

**Why "varying garbage" is the clue.** A varying value means `davix` left
`st_size` set from a non-deterministic source. It was tracking the filesystem's
used bytes: gfal's reported `839673319424` ≈ the value in our PROPFIND's
`<D:quota-used-bytes>` (`839673315328`), differing only by a few KB of `/tmp`
churn between the two calls.

**Root cause — ours, not gfal's.** Our WebDAV `PROPFIND` emitted the **RFC 4331**
quota properties on **file** resources:

```xml
<D:getcontentlength>1048576</D:getcontentlength>        <!-- correct -->
<D:quota-available-bytes>186435506176</D:quota-available-bytes>
<D:quota-used-bytes>839673315328</D:quota-used-bytes>   <!-- filesystem used bytes -->
```

`davix` maps `<D:quota-used-bytes>` onto `st_size`, so the file's size became the
partition's used bytes. RFC 4331 defines `quota-available-bytes`/`quota-used-bytes`
as **collection** properties; stock XrdHttp never emits them per-file
(`XrdHttpReq.cc` ≈ L2482 emits only
getcontentlength/getlastmodified/resourcetype/iscollection/executable).

**The server was provably correct on the value** — `curl` read the right size two
independent ways:

```
HEAD     → Content-Length: 1048576
PROPFIND → <D:getcontentlength>1048576</D:getcontentlength>
```

The defect was emitting an *extra, semantically misplaced* property that a stricter
client (davix) consumed differently than `curl`.

**Fix.** Gate the quota block to collections in `src/protocols/webdav/propfind.c`:

```c
if ((mask & (PF_QUOTA_AVAILABLE | PF_QUOTA_USED)) && S_ISDIR(sb->st_mode)) {
    ...   /* quota is a collection property (RFC 4331); never on files */
}
```

Files now carry only `getcontentlength`; directories still report quota
(unchanged). After the fix, `gfal-stat` on a file returns the true `1048576`.

| | before fix | after fix |
|---|---|---|
| file PROPFIND | has `quota-used-bytes` | only `getcontentlength` |
| **gfal-stat (file)** | **839673319424** ✗ | **1048576** ✓ |
| dir PROPFIND / gfal-ls | quota present; dir recognized | unchanged ✓ |

**Lesson.** A pure *consumer* with no protocol code still exposed a server bug —
not in the bytes (gfal reuses `libXrdCl`/`davix`) but in *property→`stat` mapping*.
A server can be RFC- and `curl`-correct on a value yet mislead a backend by
emitting a property on the wrong resource type. This is only caught by testing
against the clients production runs, not just `xrdcp`/`curl`.

---

## 4. Verification & regression — `tests/test_gfal_interop.py`

- **`test_gfal_brix_plugin_root`** — the full `root://` lifecycle matrix incl.
  `gfal-stat` size and a `gfal-sum crc32c` oracle (compared to `xrdcrc32c`).
- **`test_gfal_http_plugin_davs`** — the `davs://` lifecycle with the byte-identical
  round-trip and (post-fix) the `gfal-stat` size assertion re-enabled.

Both skip cleanly if `gfal-copy` is absent or the fleet ports (`11094`/`8443`) are
down. The quota fix was verified on an isolated WebDAV instance (gfal-stat
839 GB → 1048576); no existing test asserts file-level quota, so the change is
regression-safe.

```bash
PYTHONPATH=tests pytest tests/test_gfal_interop.py -v
# davs:// runs need the system libXrdCl + the grid CApath:
#   unset LD_LIBRARY_PATH ; export X509_CERT_DIR=/path/to/grid-CAs
```

> **Environmental caveat (not a module bug):** gfal's davix/neon TLS backend was
> intermittently flaky against the test endpoint (`SSL handshake failed: packet
> length too long`), independent of the size bug.
