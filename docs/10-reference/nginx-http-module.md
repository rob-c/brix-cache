# nginx HTTP module: why davs:// lives here

WebDAV and S3 speak HTTP, so they live in the HTTP layer. Here's how the HTTP module content handler slot is used to serve them.

[← nginx concepts overview](nginx-overview.md)

## 4. Why `davs://` uses the HTTP module

WebDAV is an **extension of HTTP/1.1** (RFC 4918). The `davs://` protocol is
plain HTTP over TLS. The client sends standard HTTP/1.1 requests:

```
PUT /store/atlas/run12345.root HTTP/1.1
Host: storage.cern.ch:443
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9…
Content-Type: application/octet-stream
Content-Length: 2147483648

<2 GiB of file data>
```

```
PROPFIND /store/atlas/ HTTP/1.1
Host: storage.cern.ch:443
Depth: 1
Content-Type: application/xml

<?xml version="1.0"?>
<propfind xmlns="DAV:"><prop><resourcetype/><getcontentlength/></prop></propfind>
```

The nginx HTTP module provides every layer of this for free:

- **HTTP/1.1 framing**: request line, header parsing, `Content-Length` /
  chunked transfer encoding — all parsed before the handler is called
- **Keepalive**: multiple requests on one TLS connection without any module code
- **TLS**: `ngx_http_ssl_module` — configured in `nginx.conf`, zero C code
- **Request body buffering**: large bodies spooled to a temp file
  (`client_body_temp_path`) so the handler never needs to allocate multi-GiB
  buffers
- **Response building**: set `r->headers_out.status`, fill `ngx_chain_t`,
  call `ngx_http_output_filter()` — HTTP framing added automatically
- **Access logging**: the `access_log` directive captures every request with
  timing, status code, and bytes sent — zero module code
- **Error pages**: `ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN)` sends
  a proper 403 response with the configured `error_page` body

The WebDAV handler registers itself as an `ngx_http_module` content handler:

```c
/* src/protocols/webdav/module.c — simplified */
static ngx_http_module_t ngx_http_xrootd_webdav_module_ctx = {
    NULL,                                          /* preconfiguration */
    ngx_http_xrootd_webdav_postconfiguration,      /* postconfiguration */
    …
};

/* postconfiguration installs the content handler */
static ngx_int_t
ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    *h = ngx_http_xrootd_webdav_handler;
    return NGX_OK;
}
```

From then on, every HTTP request to a `xrootd_webdav on` location calls
`ngx_http_xrootd_webdav_handler(r)` with a fully-parsed `ngx_http_request_t`.

### What XRootD's HTTP plugin implements manually that we get for free

The official XRootD daemon has `XrdHttp` (the HTTP/WebDAV plugin). It uses
a third-party HTTP parser (`libmicrohttpd` or its own in-process state machine
depending on version) and re-implements every layer nginx provides:

| Feature | XrdHttp | nginx-xrootd HTTP module |
|---|---|---|
| HTTP/1.1 parsing | Custom or `libmicrohttpd` | nginx core — zero code |
| TLS termination | OpenSSL wiring in `XrdTlsSocket` | `ngx_http_ssl_module` |
| Keepalive | Manual connection reuse logic | nginx core — zero code |
| Header parsing | `XrdHttpReq::parseHeader()` | `ngx_http_request_t.headers_in` |
| Body buffering | In-memory ring buffer per connection | `client_body_temp_path` + `ngx_http_read_client_request_body` |
| Chunked transfer | Manual decoder | nginx core |
| Response framing | `XrdHttpReq::appendHeader()` for every field | Set `headers_out`, call output filter |
| Access logging | Separate `XrdHttpStats` | nginx `access_log` directive |
| Virtual hosting | Custom Host header parsing | nginx `server_name` directive |
| Rate limiting | Not built-in | nginx `limit_req_zone` directive |
| IP allow/deny | Partial (`sec.protocol http allow`) | nginx `allow`/`deny` directives |
| Upstream proxying | Not in XrdHttp | nginx `proxy_pass` directive |
