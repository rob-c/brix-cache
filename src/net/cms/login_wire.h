/* One bounded CmsLoginData encoder for node announcements and manager replies.
 * Requires: configured nginx headers, included here for ngx_str_t and u_char.
 * Manager replies deliberately advertise no data capacity or optional features.
 */
#pragma once

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    uint32_t mode;
    uint32_t hold_time;
    uint32_t total_gb;
    uint32_t free_mb;
    uint32_t min_free_mb;
    uint16_t fs_num;
    uint16_t fs_util;
    uint16_t data_port;
    uint16_t subscriber_port;
    ngx_str_t sid;
    ngx_str_t paths;
    ngx_str_t interfaces;
    ngx_str_t environment;
} brix_cms_login_fields_t;

/* Return encoded bytes, or 0 without writing if fields/capacity are invalid. */
size_t brix_cms_login_encode(u_char *output, size_t capacity,
    const brix_cms_login_fields_t *fields);
