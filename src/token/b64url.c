#include "b64url.h"
#include <openssl/evp.h>
#include <string.h>

ssize_t b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max) {
    size_t padded_len = in_len + (4 - in_len % 4) % 4;
    if (padded_len > 8192) return -1;
    char tmp[8192];
    size_t i;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '-')      tmp[i] = '+';
        else if (in[i] == '_') tmp[i] = '/';
        else                   tmp[i] = in[i];
    }
    for (; i < padded_len; i++) tmp[i] = '=';
    size_t pad = 0;
    while (pad < padded_len && tmp[padded_len - pad - 1] == '=') pad++;
    size_t decoded_max = padded_len / 4 * 3 - pad;
    if (decoded_max > out_max) return -1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx) return -1;
    EVP_DecodeInit(ctx);
    int out_len = 0, tmp_len = 0;
    if (EVP_DecodeUpdate(ctx, (unsigned char*)out, &out_len, (unsigned char*)tmp, (int)padded_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, (unsigned char*)out + out_len, &tmp_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    EVP_ENCODE_CTX_free(ctx);
    return (ssize_t)(out_len + tmp_len);
}
