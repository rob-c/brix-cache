[← Contributing overview](contributing.md)

## Adding a new XRootD opcode

Step-by-step recipe: source file, dispatch entry, config, test. Follow these in order — each step is load-bearing.

Use an existing single-opcode file as a template — `src/write/sync.c` is a
good minimal example.

The seven steps touch seven places. This is the wiring you are completing —
a new opcode is "live" only once the request reaches your handler **and** the
build script knows your file exists:

```text
   wire byte                                                  metric + log
   ─────────                                                  ────────────
  opcode 3028 ──▶ ① opcodes.h ──▶ ② wire.h (24-byte struct)
                                       │
                                       ▼
            ⑤ dispatch_*.c  case kXR_newop:
                require_auth / require_write
                       │
                       ▼
            ④ src/<sub>/newop.c   xrootd_handle_newop()
                validate ▶ resolve+acl ▶ do op ▶ ③ metric slot ▶ log ▶ reply
                       │                              │
                       ▼                              ▼
            ⑥ config (deps+srcs) ──▶ ./configure   ③ metrics.h + export.c
                must agree or the file                (index ⇄ name string
                is silently not compiled)              positions must match)
                       │
                       ▼
            ⑦ src/<sub>/README.md   (file table row)

   Miss step ⑥ → code never runs.   Miss step ③ alignment → wrong op counted.
```



### Step 1 — Add the opcode constant

`src/protocol/opcodes.h` lists every opcode in numeric order.  Add yours with
a brief comment, keeping the sequential order.

```c
#define kXR_newop   3028  /* one-line description */
```

### Step 2 — Add the wire struct

`src/protocol/wire.h` has a `ClientXxxRequest` struct for every request
type and a `ServerResponseBody_Xxx` for any non-trivial response body.
Add both here.

```c
typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;
    /* 16 bytes of request-type-specific body */
    kXR_char   reserved[12];
    kXR_unt32  dlen;
} ClientNewOpRequest;
```

All structs are exactly 24 bytes (2+2+16+4).  See `protocol/README.md` for
the endianness rules.

### Step 3 — Add a metrics slot

`src/metrics/metrics.h` maintains a numbered list of operation indices.
Add your slot at the bottom, increment `XROOTD_NOPS`, and add the matching
name string to `xrootd_op_names[]` in `src/metrics/export.c`.

```c
/* metrics/metrics.h */
#define XROOTD_OP_NEWOP   37
#define XROOTD_NOPS       38
```

```c
/* metrics/export.c — xrootd_op_names[] */
"newop",   /* index 37 */
```

The index in `metrics.h` and the string position in `export.c` must agree.

### Step 4 — Write the handler file

Create `src/<subsystem>/newop.c` and the matching `src/<subsystem>/newop.h`.
Follow the eight-step handler pattern from `docs/architecture.md`:

```c
ngx_int_t
xrootd_handle_newop(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientNewOpRequest *req = (ClientNewOpRequest *) ctx->hdr_buf;

    /* 1. Validate the request fields */
    /* 2. Resolve and check the path (path/resolve.c, path/acl.c) */
    /* 3. Perform the operation */
    /* 4. Log, count, respond */
    xrootd_log_access(ctx, c, "NEWOP", path, "", 1, kXR_ok, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_NEWOP);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
```

Steps 6–8 (log + metric + send) must always run in that order.  See
`docs/architecture.md § Inside a handler: the common path`.

### Step 5 — Add the dispatch case

Decide whether the opcode is a session op, a read op, a write op, or a
signing op, then add a `case` to the matching `src/handshake/dispatch_*.c`.

```c
/* dispatch_read.c */
case kXR_newop:
    rc = xrootd_dispatch_require_auth(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; }
    return xrootd_handle_newop(ctx, c, conf);
```

Write opcodes additionally need `xrootd_dispatch_require_write()` before
calling the handler.

### Step 6 — Update the build system

`config` (the nginx module build script in the project root) has two lists:
`ngx_xrootd_stream_deps` (headers) and `ngx_module_srcs` (source files).
Add the new `.h` to deps and the `.c` to srcs.

```sh
# deps list
$ngx_addon_dir/src/read/newop.h \

# srcs list
$ngx_addon_dir/src/read/newop.c \
```

After editing `config`, re-run `./configure` in the nginx source tree to
regenerate the `Makefile`.  A build that skips `./configure` will silently
ignore the new file.

### Step 7 — Update the subsystem README

Add a row to the file table in `src/<subsystem>/README.md` so the next
contributor does not have to read your code to understand what the file does.

---

## 2. Adding a new nginx directive

New directives let operators configure your feature in `nginx.conf`.

### Step 1 — Add the config field

Add a typed field to `ngx_stream_xrootd_srv_conf_t` in
`src/core/ngx_xrootd_module.h`.  Document the directive name in a square-bracket
comment matching the pattern used by adjacent fields.

```c
ngx_flag_t  my_feature;  /* [xrootd_my_feature on|off] */
```

### Step 2 — Register the directive

Add an `ngx_command_t` entry to the directive table in
`src/stream/module.c`.  Pick the correct type flags (`NGX_STREAM_SRV_CONF`,
`NGX_CONF_FLAG` for on/off, `NGX_CONF_TAKE1` for a single string value).

```c
{ ngx_string("xrootd_my_feature"),
  NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
  ngx_conf_set_flag_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, my_feature),
  NULL },
```

For complex directives that need custom parsing, use a `set` function instead
of `ngx_conf_set_flag_slot`.

### Step 3 — Write a parser function (if needed)

If the directive takes more than a simple value, add a parser in
`src/core/config/<subsystem>.c` (or in the subsystem directory itself if the
directive is subsystem-specific).  The function signature is:

```c
char *
xrootd_conf_set_my_feature(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    /* parse cf->args->elts[1], set xcf->my_feature */
    return NGX_CONF_OK;  /* or NGX_CONF_ERROR */
}
```

Declare it in `src/core/config/config.h` if other files need to call it, or keep
it static if it is only referenced from `module.c`.

### Step 4 — Set defaults and merge

`src/core/config/server_conf.c:ngx_stream_xrootd_create_srv_conf()` initialises
every field to a sentinel (`NGX_CONF_UNSET`, `-1`, or `NULL`).  Add yours
there.  `merge_srv_conf()` in the same file applies inheritance from parent
blocks; use `ngx_conf_merge_value()` or `ngx_conf_merge_str_value()` as
appropriate.

---
