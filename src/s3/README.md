# s3 — S3-compatible REST endpoint

Provides an S3-compatible HTTP endpoint for XrdClS3 and `aws s3` CLI clients. Implements GET, HEAD, PUT, DELETE, ListObjectsV2, and multipart upload operations on the same POSIX filesystem visible through root:// and davs:// protocols. SigV4 authentication is separate from WLCG token auth — never shared logic.

| File | Responsibility |
|---|---|
| `auth_sigv4_canonical.c` | Signature V4 canonical request construction: HTTP method, URI, headers, payload hash |
| `auth_sigv4_headers.c` | SigV4 header parsing and extraction from incoming S3 requests |
| `auth_sigv4_parse.c` | SigV4 credential string parsing: access key, scope, date, algorithm |
| `auth_sigv4_verify.c` | Signature verification: HMAC-SHA256 signing chain, signature comparison |
| `copy.c` | S3 COPY operation: object copy within bucket (PUT with Content-Copy-Source header) |
| `delete_objects.c` | Batch DELETE (DeleteObjects): multi-object deletion with XML response |
| `handler.c` | S3 request dispatch: route HTTP method + path to appropriate handler |
| `list_objects_v2.c` | ListObjectsV2 implementation: bucket listing with pagination, delimiter support |
| `list_walk.c` | Directory walk for ListObjectsV2: traverse POSIX filesystem for bucket contents |
| `metrics.c` | S3-specific Prometheus metrics: request counters, bytes sent/received |
| `module.c` | nginx module registration: location handler, config merge, init/shutdown hooks |
| `multipart_abort.c` | Multipart abort: terminate incomplete upload, delete all part files |
| `multipart_complete_body.c` | Multipart complete body parsing: XML ListParts response generation |
| `multipart_complete.c` | Multipart complete: assemble all parts into final object, XML response |
| `multipart_complete_list_parts.c` | ListParts within multipart complete: enumerate uploaded parts with sizes/ETags |
| `multipart_complete_list_uploads.c` | ListMultipartUploads: enumerate incomplete uploads in bucket |
| `multipart_complete_upload_part_copy.c` | UploadPartCopy within multipart complete: copy part from source object |
| `multipart_helpers.c` | Shared multipart helpers: part numbering, size validation, temp path generation |
| `multipart_initiate.c` | Multipart initiate: create upload ID, generate XML response with upload ID |
| `multipart_internal.h` | Internal multipart types and cross-file prototypes |
| `object.c` | Object operations: metadata extraction, ETag computation, content-type handling |
| `operation_table.c` | S3 operation dispatch table: HTTP method → handler mapping |
| `put.c` | S3 PUT operation: single-object upload, content-length validation, file write |
| `s3_auth_internal.h` | Internal SigV4 auth types and prototypes |
| `s3.h` | Public S3 types and cross-file prototypes |
| `util.c` | Shared S3 utilities: bucket/path parsing, XML escaping, date formatting |
