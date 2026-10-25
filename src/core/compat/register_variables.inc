/*
 * Type-safe nginx variable registration template, shared by HTTP and stream.
 * Requires ngx_conf_t and the chosen variable type before inclusion. Define
 * BRIX_VARIABLE_TYPE, BRIX_VARIABLE_ADD, BRIX_VARIABLE_REGISTER and
 * BRIX_VARIABLE_LINKAGE, then undefine them at the instantiation site.
 * This produces ordinary typed functions, not casts between incompatible
 * HTTP/stream handler pointers or a statement macro returning from a caller.
 */

/* WHAT: Register every descriptor and retain its typed getter and data.
 * WHY: HTTP planes and stream share one registration policy without assuming
 * that their distinct C callback types have interchangeable representations.
 * HOW: Walk to the sentinel, call the selected native registrar, refuse its
 * failure, and copy only the getter/data fields the existing contract sets.
 */
BRIX_VARIABLE_LINKAGE ngx_int_t
BRIX_VARIABLE_REGISTER(ngx_conf_t *cf, BRIX_VARIABLE_TYPE *variables)
{
    BRIX_VARIABLE_TYPE *variable, *registered;

    for (variable = variables; variable->name.len; variable++) {
        registered = BRIX_VARIABLE_ADD(cf, &variable->name, variable->flags);
        if (registered == NULL) {
            return NGX_ERROR;
        }
        registered->get_handler = variable->get_handler;
        registered->data = variable->data;
    }
    return NGX_OK;
}
