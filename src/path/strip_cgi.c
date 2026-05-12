#include <string.h>

void
xrootd_strip_cgi(const char *in, char *out, size_t outsz)
{
    const char *q = strchr(in, '?');
    size_t      len;

    if (q != NULL) {
        len = (size_t) (q - in);
    } else {
        len = strlen(in);
    }

    if (len >= outsz) {
        len = outsz - 1;
    }

    memcpy(out, in, len);
    out[len] = '\0';
}
