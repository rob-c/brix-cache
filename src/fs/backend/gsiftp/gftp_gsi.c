/* OpenSSL GSI initiator for AUTH GSSAPI/ADAT control-channel security. */
#include "gftp_gsi.h"
#include "auth/gsi/proxy_req.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    GFTP_GSI_TLS = 0,
    GFTP_GSI_CSR,
    GFTP_GSI_ACK,
    GFTP_GSI_DONE,
    GFTP_GSI_FAILED
};

struct gftp_gsi_s {
    SSL_CTX  *ctx;
    SSL      *ssl;
    BIO      *rbio;
    BIO      *wbio;
    EVP_PKEY *key;
    uint8_t  *pem;
    size_t    pem_len;
    int       state;
};

static int
gftp_ssl_error(gftp_session_t *session, const char *action)
{
    unsigned long code = ERR_get_error();
    char          detail[160] = "no OpenSSL detail";

    if (code != 0) {
        ERR_error_string_n(code, detail, sizeof(detail));
    }
    ERR_clear_error();
    gftp_set_error(session, EACCES, "GridFTP GSI %s: %s", action, detail);
    return -1;
}

char *
gftp_base64_encode(const uint8_t *data, size_t len)
{
    char  *out;
    size_t cap;
    int    n;

    if (data == NULL || len == 0 || len > (size_t) INT_MAX / 2) {
        return NULL;
    }
    cap = ((len + 2) / 3) * 4 + 1;
    out = malloc(cap);
    if (out == NULL) {
        return NULL;
    }
    n = EVP_EncodeBlock((unsigned char *) out, data, (int) len);
    if (n < 0) {
        free(out);
        return NULL;
    }
    out[n] = '\0';
    return out;
}

uint8_t *
gftp_base64_decode(const char *text, size_t *out_len)
{
    uint8_t *out;
    size_t   len;
    size_t   padding = 0;
    int      n;

    if (text == NULL || out_len == NULL) {
        return NULL;
    }
    len = strlen(text);
    if (len == 0 || (len % 4) != 0 || len > (size_t) INT_MAX) {
        return NULL;
    }
    if (text[len - 1] == '=') { padding++; }
    if (len > 1 && text[len - 2] == '=') { padding++; }
    out = malloc(len / 4 * 3 + 1);
    if (out == NULL) {
        return NULL;
    }
    n = EVP_DecodeBlock(out, (const unsigned char *) text, (int) len);
    if (n < 0 || (size_t) n < padding) {
        free(out);
        return NULL;
    }
    *out_len = (size_t) n - padding;
    return out;
}

static BIO *
gftp_proxy_bio(const char *path)
{
    struct stat st;
    int         fd;
    BIO        *bio;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* vfs-seam-allow: DOMAIN_CREDENTIAL — configured/delegated X.509 proxy */
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 022) != 0) {
        close(fd);
        errno = EACCES;
        return NULL;
    }
    bio = BIO_new_fd(fd, BIO_CLOSE);
    if (bio == NULL) {
        close(fd);
    }
    return bio;
}

static int
gftp_gsi_load_certs(gftp_gsi_t *gsi, const char *path,
    gftp_session_t *session)
{
    BIO     *input;
    BIO     *memory;
    X509    *cert;
    BUF_MEM *data;
    int      count = 0;

    input = gftp_proxy_bio(path);
    memory = BIO_new(BIO_s_mem());
    if (input == NULL || memory == NULL) {
        BIO_free(input);
        BIO_free(memory);
        gftp_set_error(session, EACCES, "cannot read GridFTP X.509 proxy");
        return -1;
    }
    while ((cert = PEM_read_bio_X509(input, NULL, NULL, NULL)) != NULL) {
        int ok = PEM_write_bio_X509(memory, cert);

        if (ok) {
            ok = count == 0 ? SSL_CTX_use_certificate(gsi->ctx, cert)
                            : SSL_CTX_add1_chain_cert(gsi->ctx, cert);
        }
        X509_free(cert);
        if (!ok) {
            BIO_free(input);
            BIO_free(memory);
            return gftp_ssl_error(session, "install certificate");
        }
        count++;
    }
    ERR_clear_error();
    BIO_free(input);
    if (count == 0) {
        BIO_free(memory);
        gftp_set_error(session, EACCES, "GridFTP proxy has no certificate");
        return -1;
    }
    BIO_get_mem_ptr(memory, &data);
    gsi->pem = malloc(data->length);
    if (gsi->pem == NULL) {
        BIO_free(memory);
        gftp_set_error(session, ENOMEM, "cannot retain GridFTP proxy chain");
        return -1;
    }
    memcpy(gsi->pem, data->data, data->length);
    gsi->pem_len = data->length;
    BIO_free(memory);
    return 0;
}

static int
gftp_gsi_load_key(gftp_gsi_t *gsi, const char *path,
    gftp_session_t *session)
{
    BIO *input = gftp_proxy_bio(path);

    if (input != NULL) {
        gsi->key = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL);
        BIO_free(input);
    }
    ERR_clear_error();
    if (gsi->key == NULL || SSL_CTX_use_PrivateKey(gsi->ctx, gsi->key) != 1) {
        return gftp_ssl_error(session, "load proxy private key");
    }
    return 0;
}

static int
gftp_gsi_setup(gftp_gsi_t *gsi, const char *path, const char *ca_dir,
    gftp_session_t *session)
{
    X509_VERIFY_PARAM *param;
    const char        *trust = ca_dir;

    gsi->ctx = SSL_CTX_new(TLS_client_method());
    if (gsi->ctx == NULL
        || SSL_CTX_set_max_proto_version(gsi->ctx, TLS1_2_VERSION) != 1
        || SSL_CTX_set_min_proto_version(gsi->ctx, TLS1_VERSION) != 1) {
        return gftp_ssl_error(session, "create TLS context");
    }
    SSL_CTX_set_verify(gsi->ctx, SSL_VERIFY_PEER, NULL);
    if (trust == NULL || trust[0] == '\0') {
        trust = getenv("X509_CERT_DIR");
    }
    if (trust == NULL || trust[0] == '\0') {
        trust = "/etc/grid-security/certificates";
    }
    if (SSL_CTX_load_verify_locations(gsi->ctx, NULL, trust) != 1) {
        gftp_set_error(session, EACCES, "cannot load GridFTP CA directory");
        return -1;
    }
    param = SSL_CTX_get0_param(gsi->ctx);
    if (param != NULL) {
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
    }
    if (gftp_gsi_load_certs(gsi, path, session) != 0) {
        return -1;
    }
    return gftp_gsi_load_key(gsi, path, session);
}

gftp_gsi_t *
gftp_gsi_create(const char *proxy_path, const char *ca_dir,
    gftp_session_t *session)
{
    gftp_gsi_t *gsi = calloc(1, sizeof(*gsi));

    if (gsi == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP GSI context");
        return NULL;
    }
    if (gftp_gsi_setup(gsi, proxy_path, ca_dir, session) != 0) {
        gftp_gsi_free(gsi);
        return NULL;
    }
    gsi->ssl = SSL_new(gsi->ctx);
    gsi->rbio = BIO_new(BIO_s_mem());
    gsi->wbio = BIO_new(BIO_s_mem());
    if (gsi->ssl == NULL || gsi->rbio == NULL || gsi->wbio == NULL) {
        (void) gftp_ssl_error(session, "allocate TLS state");
        gftp_gsi_free(gsi);
        return NULL;
    }
    SSL_set_bio(gsi->ssl, gsi->rbio, gsi->wbio);
    SSL_set_connect_state(gsi->ssl);
    gsi->state = GFTP_GSI_TLS;
    return gsi;
}

static int
gftp_gsi_drain(gftp_gsi_t *gsi, uint8_t **out, size_t *out_len,
    gftp_session_t *session)
{
    char *data = NULL;
    long  len;

    *out = NULL;
    *out_len = 0;
    len = BIO_get_mem_data(gsi->wbio, &data);
    if (len <= 0) {
        return 0;
    }
    *out = malloc((size_t) len);
    if (*out == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP GSI token");
        return -1;
    }
    memcpy(*out, data, (size_t) len);
    *out_len = (size_t) len;
    (void) BIO_reset(gsi->wbio);
    return 0;
}

static int
gftp_gsi_read_app(gftp_gsi_t *gsi, uint8_t **out, size_t *out_len,
    gftp_session_t *session)
{
    size_t   cap = 16384;
    size_t   used = 0;
    uint8_t *data = malloc(cap);

    if (data == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP GSI payload");
        return -1;
    }
    while (used < (size_t) 1 << 20) {
        int n = SSL_read(gsi->ssl, data + used, (int) (cap - used));

        if (n <= 0) {
            break;
        }
        used += (size_t) n;
        if (used == cap) {
            uint8_t *larger;

            cap *= 2;
            larger = realloc(data, cap);
            if (larger == NULL) {
                free(data);
                gftp_set_error(session, ENOMEM,
                    "cannot grow GridFTP GSI payload");
                return -1;
            }
            data = larger;
        }
    }
    ERR_clear_error();
    *out = data;
    *out_len = used;
    return 0;
}

static int
gftp_gsi_tls_step(gftp_gsi_t *gsi, uint8_t **out, size_t *out_len,
    gftp_session_t *session)
{
    int rc = SSL_connect(gsi->ssl);
    int ssl_error;

    if (rc == 1) {
        if (SSL_write(gsi->ssl, "D", 1) != 1) {
            gsi->state = GFTP_GSI_FAILED;
            return gftp_ssl_error(session, "send delegation marker");
        }
        gsi->state = GFTP_GSI_CSR;
        return gftp_gsi_drain(gsi, out, out_len, session) == 0 ? 1 : -1;
    }
    ssl_error = SSL_get_error(gsi->ssl, rc);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        return gftp_gsi_drain(gsi, out, out_len, session) == 0 ? 1 : -1;
    }
    gsi->state = GFTP_GSI_FAILED;
    return gftp_ssl_error(session, "TLS handshake");
}

static int
gftp_gsi_sign(gftp_gsi_t *gsi, const uint8_t *request, size_t request_len,
    uint8_t **der_out, size_t *der_len, gftp_session_t *session)
{
    brix_gsi_blob_t signer = { gsi->pem, gsi->pem_len };
    brix_gsi_blob_t req = { request, request_len };
    brix_gsi_buf_t  issued_pem = { NULL, 0 };
    char            detail[160] = "";
    brix_gsi_err_t  error = { detail, sizeof(detail) };
    X509           *issued;
    unsigned char  *der = NULL;
    int             len;
    BIO            *memory;

    if (brix_gsi_sign_pxyreq(&signer, gsi->key, &req, &issued_pem,
                             &error) != 0) {
        gftp_set_error(session, EACCES, "GridFTP proxy delegation: %s", detail);
        return -1;
    }
    memory = BIO_new_mem_buf(issued_pem.data, (int) issued_pem.len);
    issued = memory != NULL ? PEM_read_bio_X509(memory, NULL, NULL, NULL) : NULL;
    BIO_free(memory);
    free(issued_pem.data);
    if (issued == NULL) {
        return gftp_ssl_error(session, "decode delegated proxy");
    }
    len = i2d_X509(issued, &der);
    X509_free(issued);
    if (len <= 0 || der == NULL) {
        return gftp_ssl_error(session, "encode delegated proxy");
    }
    *der_out = malloc((size_t) len);
    if (*der_out == NULL) {
        OPENSSL_free(der);
        gftp_set_error(session, ENOMEM, "cannot allocate delegated proxy");
        return -1;
    }
    memcpy(*der_out, der, (size_t) len);
    *der_len = (size_t) len;
    OPENSSL_free(der);
    return 0;
}

static int
gftp_gsi_csr_step(gftp_gsi_t *gsi, uint8_t **out, size_t *out_len,
    gftp_session_t *session)
{
    uint8_t *request = NULL;
    uint8_t *issued = NULL;
    size_t   request_len = 0;
    size_t   issued_len = 0;
    int      rc;

    if (gftp_gsi_read_app(gsi, &request, &request_len, session) != 0) {
        free(request);
        gsi->state = GFTP_GSI_FAILED;
        return -1;
    }
    if (request_len == 0) {
        free(request);
        gsi->state = GFTP_GSI_FAILED;
        gftp_set_error(session, EPROTO,
            "GridFTP delegation request is empty");
        return -1;
    }
    rc = gftp_gsi_sign(gsi, request, request_len, &issued, &issued_len, session);
    free(request);
    if (rc != 0) {
        free(issued);
        gsi->state = GFTP_GSI_FAILED;
        return -1;
    }
    if (SSL_write(gsi->ssl, issued, (int) issued_len) <= 0) {
        free(issued);
        gsi->state = GFTP_GSI_FAILED;
        return gftp_ssl_error(session, "send delegated proxy");
    }
    free(issued);
    gsi->state = GFTP_GSI_ACK;
    return gftp_gsi_drain(gsi, out, out_len, session) == 0 ? 1 : -1;
}

int
gftp_gsi_step(gftp_gsi_t *gsi, const uint8_t *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session)
{
    *output = NULL;
    *output_len = 0;
    if (gsi->state == GFTP_GSI_FAILED) {
        gftp_set_error(session, EACCES, "GridFTP GSI context has failed");
        return -1;
    }
    if (gsi->state == GFTP_GSI_DONE) {
        return 0;
    }
    if (input_len > 0 && BIO_write(gsi->rbio, input, (int) input_len) <= 0) {
        gsi->state = GFTP_GSI_FAILED;
        return gftp_ssl_error(session, "buffer peer token");
    }
    if (gsi->state == GFTP_GSI_TLS) {
        return gftp_gsi_tls_step(gsi, output, output_len, session);
    }
    if (gsi->state == GFTP_GSI_CSR) {
        return gftp_gsi_csr_step(gsi, output, output_len, session);
    }
    gsi->state = GFTP_GSI_DONE;
    return 0;
}

int
gftp_gsi_wrap(gftp_gsi_t *gsi, const void *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session)
{
    if (SSL_write(gsi->ssl, input, (int) input_len) <= 0) {
        return gftp_ssl_error(session, "protect command");
    }
    return gftp_gsi_drain(gsi, output, output_len, session);
}

int
gftp_gsi_unwrap(gftp_gsi_t *gsi, const void *input, size_t input_len,
    uint8_t **output, size_t *output_len, gftp_session_t *session)
{
    if (input_len > 0 && BIO_write(gsi->rbio, input, (int) input_len) <= 0) {
        return gftp_ssl_error(session, "buffer protected reply");
    }
    if (gftp_gsi_read_app(gsi, output, output_len, session) != 0) {
        return -1;
    }
    if (*output_len == 0) {
        free(*output);
        *output = NULL;
        gftp_set_error(session, EPROTO, "GridFTP protected reply is empty");
        return -1;
    }
    return 0;
}

void
gftp_gsi_free(gftp_gsi_t *gsi)
{
    if (gsi == NULL) {
        return;
    }
    if (gsi->ssl != NULL) {
        SSL_free(gsi->ssl);
    } else {
        BIO_free(gsi->rbio);
        BIO_free(gsi->wbio);
    }
    EVP_PKEY_free(gsi->key);
    SSL_CTX_free(gsi->ctx);
    free(gsi->pem);
    free(gsi);
}
