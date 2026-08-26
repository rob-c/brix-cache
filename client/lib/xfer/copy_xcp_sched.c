/* worker startup-reservation release + claim/steal scheduling loop + join gate
 *
 * Extracted from copy_xcp.c to hold each translation unit under the
 * 600-line file-size cap. Included by copy_xcp.c (one TU); not built
 * standalone. */
/* ---- Release an unstarted worker's reserved block ----
 *
 * WHAT: Return a startup reservation to the normal claim pool.
 *
 * WHY: A replica can fail before it reaches the block loop; its reserved
 *      block must not remain invisible to the surviving workers.
 *
 * HOW: Atomically change only XCP_RESERVED to XCP_TODO. A worker that has
 *      already claimed the reservation owns the ordinary release path.
 */
static void
xcp_release_reserved_block(xcp_shared_t *sh, size_t idx)
{
    unsigned char expected = XCP_RESERVED;
    atomic_compare_exchange_strong(&sh->state[idx], &expected, XCP_TODO);
}


/* ---- Drive one worker's claim/fetch loop ----
 *
 * WHAT: Fetch the startup reservation and then claim or steal blocks until the
 *       destination is complete, cancellation is requested, or a fetch fails.
 *       Returns 0 for a worker that can leave normally and -1 for its failure.
 *
 * WHY: The thread entry point owns connection/buffer lifetime; keeping the
 *      scheduler in this helper makes those resource edges independent of the
 *      block-stealing state machine and keeps both paths below the complexity
 *      gate.
 *
 * HOW: 1. Convert the startup reservation into a normal busy claim and fetch it.
 *      2. Repeatedly claim/steal, fetch, and release the stealer latch.
 *      3. Wait briefly when a straggler owns the remaining work; stop on DONE or
 *         cancellation and return the worker verdict.
 */
static int
xcp_worker_blocks(xcp_worker_t *w, brix_conn *c, brix_file *f, uint8_t *buf)
{
    xcp_shared_t *sh = w->sh;
    int rc = 0;

    if (w->initial_reserved) {
        unsigned char expected = XCP_RESERVED;

        if (atomic_compare_exchange_strong(&sh->state[w->initial_idx],
                                           &expected, XCP_BUSY)) {
            w->initial_reserved = 0;
            if (xcp_fetch_block(w, c, f, w->initial_idx, buf) != 0) {
                xcp_release_block(sh, w->initial_idx, 0);
                rc = -1;
            }
        } else {
            w->initial_reserved = 0;
        }
    }

    while (rc == 0) {
        int stole = 0;
        ssize_t idx = xcp_claim(sh, w->claim_hint, &stole);

        if (idx < 0) {
            if (xcp_all_done(sh)) {
                break;
            }
            if (brix_copy_quit_requested()) {
                brix_status_set(&w->st, XRDC_ESOCK, EINTR,
                                "cancelled (signal)");
                rc = -1;
                break;
            }
            /* Blocks remain but none claimable: idle-wait for a straggler
             * to finish, die, or free its steal slot. Bounded tail spin. */
            {
                struct timespec ts = { 0, 20 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            continue;
        }

        w->claim_hint = (unsigned) idx + 1;
        if (xcp_fetch_block(w, c, f, (size_t) idx, buf) != 0) {
            xcp_release_block(sh, (size_t) idx, stole);
            rc = -1;
            break;
        }
        if (stole) {
            atomic_store(&sh->stealer[(size_t) idx], 0);
        }
    }

    return rc;
}


/* ---- Wait for every source's open attempt to resolve (bounded) ----
 *
 * WHAT: Block until sh->resolved reaches the spawn width, the grace cap
 *       expires, or the operator cancels.
 *
 * WHY: Without a start rendezvous the first source to finish its XRootD open
 *      can drain the whole block table before a sibling's handshake completes
 *      — on a fast link --sources N silently degrades to one source. Holding
 *      the claim start until every open RESOLVES (success or failure — a dead
 *      mirror lifts the gate as fast as a live one) guarantees each opened
 *      source at least its first claim. The grace cap keeps a black-holed
 *      mirror from stalling the transfer start beyond a bounded delay.
 *
 * HOW: 1. Poll resolved vs nworkers in 2 ms sleeps. 2. Give up waiting at
 *         XRDC_XCP_JOIN_GRACE_MS or on quit — the claim loop handles cancel.
 */
static void
xcp_join_gate(const xcp_shared_t *sh)
{
    unsigned waited_ms = 0;

    while (atomic_load(&sh->resolved) < sh->nworkers
           && waited_ms < XRDC_XCP_JOIN_GRACE_MS
           && !brix_copy_quit_requested()) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        waited_ms += 2;
    }
}
