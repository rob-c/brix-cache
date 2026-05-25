/*
* Proxy response relay and dispatch are split into named C source fragments
* to keep each unit approachable while preserving the original code and
* comments. Do not compile these fragments directly; forward_relay.c owns
 * the module unit.
 *
 * WHAT: This file is a single compilation unit that includes three
 *       sub-fragments covering proxy response relay, dispatch logic,
 *       and audit logging for transparent XRootD proxy mode.
 *
 * WHY:  Splitting into named fragments keeps each unit under ~200 lines,
 *       making them easier to review and modify without losing the
 *       original code comments that document wire protocol behavior.
 *
 * HOW:  Each fragment is included via #include at file scope. The
 *       compiler treats them as one translation unit; symbols from
 *       all fragments share the same namespace.
*/

#include "forward_relay_audit.c"
#include "forward_relay_response.c"
#include "forward_relay_dispatch.c"
