# locks — WebDAV Locking Support

Implements WebDAV RFC 4918 locking mechanisms.

| File | Responsibility |
|------|----------------|
| `request.c` | LOCK request parsing: Timeout, If/Lock-Token, Depth, owner, lockscope |
| `request.h` | WebDAV lock request types and prototypes |
