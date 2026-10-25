/* Explicit-address TGT fixture using only the public MIT Kerberos API.
 * Native interface enumeration differs between hosts; no production auth
 * check is changed and the test still verifies the actual ticket addresses.
 */
#include <krb5.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    krb5_context context;
    krb5_principal principal;
    krb5_keytab keytab;
    krb5_ccache cache;
    krb5_get_init_creds_opt *options;
    krb5_creds credentials;
} ticket_owner;

/* WHAT: Release only owned Kerberos objects. WHY: Error paths cannot leak keys.
 * HOW: 1. Close optional handles. 2. Free credentials/options. 3. Free context. */
static void
ticket_cleanup(ticket_owner *owner)
{
    if (!owner->context) { return; }
    if (owner->cache) { krb5_cc_close(owner->context, owner->cache); }
    if (owner->keytab) { krb5_kt_close(owner->context, owner->keytab); }
    if (owner->principal) { krb5_free_principal(owner->context, owner->principal); }
    if (owner->options) { krb5_get_init_creds_opt_free(owner->context, owner->options); }
    krb5_free_cred_contents(owner->context, &owner->credentials);
    krb5_free_context(owner->context);
}

/* WHAT: Acquire fixture context/keytab/options, returning a Kerberos status.
 * WHY: Keep acquisition independent of ticket issuance and cache mutation.
 * HOW: 1. Initialize context. 2. Parse principal. 3. Open keytab. 4. Allocate options. */
static krb5_error_code
ticket_init(ticket_owner *owner, const char *keytab, const char *principal)
{
    krb5_error_code rc = krb5_init_context(&owner->context);
    if (rc) { return rc; }
    rc = krb5_parse_name(owner->context, principal, &owner->principal);
    if (rc) { return rc; }
    rc = krb5_kt_resolve(owner->context, keytab, &owner->keytab);
    if (rc) { return rc; }
    return krb5_get_init_creds_opt_alloc(owner->context, &owner->options);
}

/* WHAT: Request exactly one address-restricted TGT.
 * WHY: FreeBSD's local-address enumeration includes the test's foreign aliases.
 * HOW: 1. Supply an explicit NULL-terminated address list. 2. Use the fixture keytab. */
static krb5_error_code
ticket_issue(ticket_owner *owner, struct in_addr *source)
{
    krb5_address address = {0};
    address.addrtype = ADDRTYPE_INET;
    address.length = sizeof(*source);
    address.contents = (krb5_octet *) source;
    krb5_address *addresses[] = {&address, NULL};
    krb5_get_init_creds_opt_set_address_list(owner->options, addresses);
    return krb5_get_init_creds_keytab(owner->context, &owner->credentials,
        owner->principal, owner->keytab, 0, NULL, owner->options);
}

/* WHAT: Save issued credentials to the private FILE cache.
 * WHY: Failed issuance must never initialize or truncate a credential cache.
 * HOW: 1. Resolve explicit cache type. 2. Initialize client. 3. Store the TGT. */
static krb5_error_code
ticket_save(ticket_owner *owner, const char *cache)
{
    krb5_error_code rc = krb5_cc_resolve(owner->context, cache, &owner->cache);
    if (rc) { return rc; }
    rc = krb5_cc_initialize(owner->context, owner->cache, owner->principal);
    if (rc) { return rc; }
    return krb5_cc_store_cred(owner->context, owner->cache, &owner->credentials);
}

/* WHAT: Issue a fixture TGT; return 2 for input errors and 1 for Kerberos errors.
 * WHY: A malformed address or foreign cache type must fail before touching a cache.
 * HOW: 1. Validate arguments. 2. Initialize/issue/save. 3. Report status and unwind. */
int
main(int argc, char **argv)
{
    if (argc != 5 || strncmp(argv[3], "FILE:/", 6) != 0) {
        fprintf(stderr, "usage: addressed-ticket KEYTAB PRINCIPAL FILE:/CACHE IPV4\n");
        return 2;
    }
    struct in_addr address;
    if (inet_pton(AF_INET, argv[4], &address) != 1) {
        fprintf(stderr, "invalid fixture IPv4 address\n");
        return 2;
    }
    ticket_owner owner = {0};
    krb5_error_code rc = ticket_init(&owner, argv[1], argv[2]);
    if (!rc) { rc = ticket_issue(&owner, &address); }
    if (!rc) { rc = ticket_save(&owner, argv[3]); }
    if (rc && owner.context) {
        const char *message = krb5_get_error_message(owner.context, rc);
        fprintf(stderr, "fixture ticket issuance failed: %s\n", message);
        krb5_free_error_message(owner.context, message);
    }
    ticket_cleanup(&owner);
    return rc ? 1 : 0;
}
