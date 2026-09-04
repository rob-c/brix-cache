#ifndef BRIX_GFTP_GSI_H
#define BRIX_GFTP_GSI_H

#include "gftp_client.h"

gftp_gsi_t *gftp_gsi_create(const char *proxy_path, const char *ca_dir,
    gftp_session_t *session);
int gftp_gsi_step(gftp_gsi_t *gsi, const uint8_t *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session);
int gftp_gsi_wrap(gftp_gsi_t *gsi, const void *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session);
int gftp_gsi_unwrap(gftp_gsi_t *gsi, const void *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session);
void gftp_gsi_free(gftp_gsi_t *gsi);

char *gftp_base64_encode(const uint8_t *data, size_t len);
uint8_t *gftp_base64_decode(const char *text, size_t *out_len);

#endif /* BRIX_GFTP_GSI_H */
