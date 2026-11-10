/* Real TLS discovery, ES256 signing and advertisement, with finite timers. */
#include "fs/cache/origin/pelican_register.h"
#include "auth/token/jwt_sign.h"
#include <assert.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

static ngx_str_t
text_value(char *value)
{
    ngx_str_t text = {strlen(value), (u_char *) value};
    return text;
}

int
main(int argc, char **argv)
{
    ngx_stream_brix_srv_conf_t conf = {0};
    ngx_log_t log = {0};
    ngx_open_file_t file = {0};
    ngx_cycle_t cycle = {0};
    ngx_int_t result;
    assert(argc == 6);
    ngx_time_init();
    ngx_pagesize = 4096;
    file.fd = STDERR_FILENO;
    log.file = &file;
    log.log_level = NGX_LOG_INFO;
    cycle.log = &log;
    cycle.pool = ngx_create_pool(16384, &log);
    assert(cycle.pool != NULL);
    assert(ngx_event_timer_init(&log) == NGX_OK);
    assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    conf.advertise.enable = strcmp(argv[4], "disabled") != 0;
    conf.advertise.federation = text_value(argv[5]);
    conf.advertise.federation_port = atoi(argv[1]);
    conf.advertise.interval = 60000;
    conf.advertise.key = text_value(argv[3]);
    conf.advertise.data_url = text_value("https://cache.example.test/data");
    conf.advertise.sitename = text_value("native-fixture");
    conf.common.trusted_ca = text_value(argv[2]);
    if (strcmp(argv[4], "no-data") == 0) { conf.advertise.data_url.len = 0; }
    brix_cache_pelican_schedule_advertise(&cycle, &conf);
    if (conf.advertise.timer != NULL) {
        ngx_event_t *event = conf.advertise.timer;
        ngx_del_timer(event);
        event->handler(event);
        ngx_del_timer(event);
    }
    result = brix_cache_pelican_advertise_once(&conf, &log);
    printf("result=%ld generation=%lu\n", (long) result,
           (unsigned long) conf.advertise.gen);
    EVP_PKEY_free(conf.advertise.key_pkey);
    ngx_destroy_pool(cycle.pool);
    curl_global_cleanup();
    return 0;
}
