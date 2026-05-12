#include "cms_internal.h"


uint16_t
ngx_xrootd_cms_get16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}


uint32_t
ngx_xrootd_cms_get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | (uint32_t) p[3];
}


void
ngx_xrootd_cms_put16(u_char *p, uint16_t value)
{
    p[0] = (u_char) (value >> 8);
    p[1] = (u_char) value;
}


void
ngx_xrootd_cms_put32(u_char *p, uint32_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}


u_char *
ngx_xrootd_cms_put_short(u_char *p, uint16_t value)
{
    *p++ = CMS_PT_SHORT;
    ngx_xrootd_cms_put16(p, value);
    return p + 2;
}


u_char *
ngx_xrootd_cms_put_int(u_char *p, uint32_t value)
{
    *p++ = CMS_PT_INT;
    ngx_xrootd_cms_put32(p, value);
    return p + 4;
}
