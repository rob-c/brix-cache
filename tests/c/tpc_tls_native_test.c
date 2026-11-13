/* Authenticate a real TLS peer before publishing any TPC socket credentials. */
#include "tpc/engine/tpc_internal.h"
#include <assert.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <unistd.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
} fixture;

static int mode(const char *name)
{
    return !strcmp(((fixture *) ngx_cycle)->mode, name);
}

SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *method);
SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *method)
{
    return mode("context-failure") ? NULL : __real_SSL_CTX_new(method);
}

SSL *__real_SSL_new(SSL_CTX *ctx);
SSL *__wrap_SSL_new(SSL_CTX *ctx)
{
    return mode("session-failure") ? NULL : __real_SSL_new(ctx);
}

int __real_SSL_set_fd(SSL *ssl, int fd);
int __wrap_SSL_set_fd(SSL *ssl, int fd)
{
    return mode("descriptor-failure") ? 0 : __real_SSL_set_fd(ssl, fd);
}

int __real_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
int __wrap_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    return mode("default-failure") ? 0 : __real_SSL_CTX_set_default_verify_paths(ctx);
}

int __real_X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *parameters, const char *host, size_t length);
int __wrap_X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *parameters, const char *host, size_t length)
{
    return mode("name-failure") ? 0 : __real_X509_VERIFY_PARAM_set1_host(parameters, host, length);
}

long __real_SSL_ctrl(SSL *ssl, int command, long argument, void *pointer);
long __wrap_SSL_ctrl(SSL *ssl, int command, long argument, void *pointer)
{
    if (mode("sni-failure") && command == SSL_CTRL_SET_TLSEXT_HOSTNAME) { return 0; }
    return __real_SSL_ctrl(ssl, command, argument, pointer);
}

long __real_SSL_get_verify_result(const SSL *ssl);
long __wrap_SSL_get_verify_result(const SSL *ssl)
{
    return mode("post-verify-failure") ? X509_V_ERR_CERT_REVOKED : __real_SSL_get_verify_result(ssl);
}

int main(int argc, char **argv)
{
    assert(argc == 6);
    fixture f = {0}; brix_tpc_pull_t task = {0}; ngx_stream_brix_srv_conf_t conf = {0};
    f.mode = argv[1]; ngx_cycle = &f.cycle;
    int fd = atoi(argv[2]), success = atoi(argv[5]);
    signal(SIGPIPE, SIG_IGN);
    task.conf = &conf; task.primary_fd = mode("unowned") ? -1 : fd;
    conf.common.trusted_ca.data = (u_char *) argv[3];
    conf.common.trusted_ca.len = strlen(argv[3]);
    if (mode("invalid-path")) { conf.common.trusted_ca.len = PATH_MAX + 1; }
    ngx_cpystrn((u_char *) task.src_host, (u_char *) argv[4], sizeof(task.src_host));
    if (mode("substream")) {
        task.primary_fd = -1; task.nsub = 2;
        task.sub[0].fd = -1; task.sub[1].fd = fd;
    }
    int result = tpc_start_tls(&task, fd);
    assert(result == (success ? 0 : -1));
    if (success) {
        SSL *ssl = mode("substream") ? task.sub[1].tls : task.tls;
        assert(ssl && (mode("substream") ? task.sub[1].tls_verified : task.tls_verified));
        assert(SSL_write(ssl, "verified", 8) == 8);
        tpc_tls_teardown_fd(&task, fd + 1000);
        assert(mode("substream") ? task.sub[1].tls == ssl : task.tls == ssl);
    } else {
        assert(!task.tls && !task.tls_ctx && !task.tls_verified);
        assert(!task.sub[1].tls && !task.sub[1].tls_verified);
        if (!mode("descriptor-failure")) {
            assert(task.err_msg[0]);
            assert(task.xrd_error == ((mode("context-failure") || mode("session-failure"))
                                      ? kXR_ServerError : kXR_NotAuthorized));
        }
    }
    tpc_tls_teardown_fd(&task, fd); tpc_tls_teardown_fd(&task, fd);
    assert(!task.tls && !task.tls_ctx && !task.tls_verified);
    assert(!task.sub[1].tls && !task.sub[1].tls_ctx && !task.sub[1].tls_verified);
    close(fd);
    return 0;
}
