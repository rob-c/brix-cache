# util — WebDAV Utilities

Shared utility functions for the WebDAV module.

| File | Responsibility |
|------|----------------|
| `logging.c` | Safe path formatting and sanitization for nginx error logs |
| `logging.h` | WebDAV logging types and prototypes |
| `uri.c` | Percent-decoding for request and Destination URI paths |
| `uri.h` | WebDAV URI utility types and prototypes |
| `xml.c` | XML text escaping for PROPFIND/HEAD/LOCK response bodies |
| `xml.h` | WebDAV XML utility types and prototypes |
