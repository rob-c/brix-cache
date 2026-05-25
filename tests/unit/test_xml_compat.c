#include "../../src/compat/xml.h"

#include <stdio.h>
#include <string.h>

static int
expect_str(const char *name, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("%s failed: got [%s] want [%s]\n", name, got, want);
        return 1;
    }

    return 0;
}

int
main(void)
{
    const unsigned char webdav_src[] = { '&', '<', '>', '"', '\'', 0x01, 0 };
    const char *lock_xml =
        "<?xml version=\"1.0\"?>"
        "<D:lockinfo xmlns:D=\"DAV:\">"
        "<D:lockscope><D:shared/></D:lockscope>"
        "<D:owner><D:href>mailto:a&amp;b@example.test</D:href></D:owner>"
        "</D:lockinfo>";
    const char *exclusive_xml =
        "<lockinfo xmlns=\"DAV:\">"
        "<lockscope><exclusive/></lockscope>"
        "<owner>plain-owner</owner>"
        "</lockinfo>";
    const char *xxe_xml =
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE lockinfo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        "<lockinfo xmlns=\"DAV:\"><owner>&xxe;</owner></lockinfo>";
    char   out[128];
    char   owner[128];
    size_t written;
    int    exclusive;
    int    failed = 0;

    if (xrootd_xml_escape(webdav_src, sizeof(webdav_src) - 1,
                          XROOTD_XML_ESCAPE_CONTROL_PERCENT,
                          (unsigned char *) out, sizeof(out),
                          &written) != 0)
    {
        printf("webdav escape returned error\n");
        return 1;
    }
    failed |= expect_str("webdav escape", out,
                         "&amp;&lt;&gt;&quot;&#39;%01");
    if (written != strlen(out)) {
        printf("webdav escape written length failed\n");
        failed = 1;
    }

    if (xrootd_xml_escape((const unsigned char *) "'", 1,
                          XROOTD_XML_ESCAPE_APOS_ENTITY,
                          (unsigned char *) out, sizeof(out),
                          NULL) != 0)
    {
        printf("s3 escape returned error\n");
        return 1;
    }
    failed |= expect_str("s3 apostrophe", out, "&apos;");

    if (xrootd_xml_escape((const unsigned char *) "&&&&", 4, 0,
                          (unsigned char *) out, 4, NULL) == 0)
    {
        printf("short escape buffer was accepted\n");
        failed = 1;
    }

    if (xrootd_xml_write_text_element("D:href",
                                      (const unsigned char *) "a&b<'",
                                      strlen("a&b<'"),
                                      XROOTD_XML_ESCAPE_APOS_ENTITY,
                                      (unsigned char *) out, sizeof(out),
                                      &written) != 0)
    {
        printf("text element writer returned error\n");
        return 1;
    }
    failed |= expect_str("text element", out,
                         "<D:href>a&amp;b&lt;&apos;</D:href>");
    if (written != strlen(out)) {
        printf("text element written length failed\n");
        failed = 1;
    }
    if (xrootd_xml_text_element_len("D:href",
                                    (const unsigned char *) "a&b<'",
                                    strlen("a&b<'"),
                                    XROOTD_XML_ESCAPE_APOS_ENTITY)
        != strlen(out))
    {
        printf("text element length helper failed\n");
        failed = 1;
    }
    if (xrootd_xml_write_text_element("bad name",
                                      (const unsigned char *) "x", 1, 0,
                                      (unsigned char *) out, sizeof(out),
                                      NULL) == 0)
    {
        printf("invalid element name was accepted\n");
        failed = 1;
    }

    exclusive = 1;
    if (xrootd_xml_parse_lockinfo(lock_xml, strlen(lock_xml),
                                  owner, sizeof(owner), &exclusive) != 0)
    {
        printf("lockinfo parse failed with backend %s\n",
               xrootd_xml_backend_name());
        failed = 1;
    } else {
        if (strcmp(xrootd_xml_backend_name(), "libxml2") == 0) {
            failed |= expect_str("lock owner", owner,
                                 "mailto:a&b@example.test");
        } else {
            failed |= expect_str("lock owner", owner,
                                 "mailto:a&amp;b@example.test");
        }
        if (exclusive != 0) {
            printf("shared lockscope did not clear exclusive flag\n");
            failed = 1;
        }
    }

    exclusive = 0;
    if (xrootd_xml_parse_lockinfo(exclusive_xml, strlen(exclusive_xml),
                                  owner, sizeof(owner), &exclusive) != 0)
    {
        printf("exclusive lockinfo parse failed\n");
        failed = 1;
    } else {
        failed |= expect_str("plain owner", owner, "plain-owner");
        if (exclusive != 1) {
            printf("exclusive lockscope did not set default exclusive flag\n");
            failed = 1;
        }
    }

    exclusive = 1;
    owner[0] = '\0';
    (void) xrootd_xml_parse_lockinfo(xxe_xml, strlen(xxe_xml),
                                     owner, sizeof(owner), &exclusive);
    if (strstr(owner, "root:") != NULL) {
        printf("external entity content was expanded into owner\n");
        failed = 1;
    }

    if (strcmp(xrootd_xml_backend_name(), "libxml2") == 0
        && xrootd_xml_parse_lockinfo("<lockinfo>", strlen("<lockinfo>"),
                                     owner, sizeof(owner), &exclusive) == 0)
    {
        printf("malformed lockinfo was accepted by libxml2 parser\n");
        failed = 1;
    }

    if (failed) {
        return 1;
    }

    printf("xml compat helpers passed using %s\n", xrootd_xml_backend_name());
    return 0;
}
