# mock_registry_part2.py — continuation shard split off from mock_registry.py for the 600
# logical-line cap; exec'd into its namespace by split_continuation.load so the
# module's import API is unchanged.

class V6Server(ThreadingHTTPServer):
    """The same server on AF_INET6, for the IPv6-literal reference lane.

    A bare `--bind ::1` would otherwise be handed to socket.bind() on an
    AF_INET socket and fail; the family is a property of the address, so it is
    decided here rather than by a flag the caller could get wrong.
    """
    address_family = socket.AF_INET6


def server_for(bind, port):
    cls = V6Server if ":" in bind else ThreadingHTTPServer
    return cls((bind, port), Handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="127.0.0.1")  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--auth", action="store_true",
                    help="401 + Bearer challenge on the data plane")
    ap.add_argument("--token-port", type=int, default=None,
                    help="serve /token on a second listener too")
    ap.add_argument("--token-bind", default=None,
                    help="address for the --token-port listener (default: "
                         "--bind); a token service on an address of its own "
                         "is what an off-domain realm looks like")
    ap.add_argument("--realm", default=None,
                    help="advertise this realm URL instead of self (the "
                         "third-party-realm negative); \"-\" omits the realm "
                         "parameter entirely")
    ap.add_argument("--basic", default=None, metavar="USER:PASS",
                    help="/token requires exactly these Basic creds")
    ap.add_argument("--user", action="append", default=[],
                    metavar="USER:PASS",
                    help="account table entry (repeatable); with any --user, "
                         "/token validates a presented Basic against the "
                         "table, mints anonymously when none is presented, "
                         "and binds each token to its account")
    ap.add_argument("--private", action="append", default=[],
                    metavar="REPO=USER[,USER...]",
                    help="repository readable only by the named accounts "
                         "(repeatable); an empty user list means nobody. "
                         "Any other identity — anonymous included — gets "
                         "401 (no token) or 403 (token outside its grant)")
    ap.add_argument("--token-ttl", type=int, default=300,
                    help="expires_in on issued tokens; 0 omits the field")
    ap.add_argument("--token-key", default="token",
                    choices=("token", "access_token"),
                    help="which JSON field carries the token (Quay spells it "
                         "access_token)")
    ap.add_argument("--push", action="store_true",
                    help="accept the upload state machine + manifest PUT")
    ap.add_argument("--blob-redirect", default=None, metavar="URL",
                    help="302 every blob GET to URL + path (CDN twin)")
    ap.add_argument("--blob-redirect-sign", action="store_true",
                    help="sign that redirect in the query, CloudFront-style")
    ap.add_argument("--require-signature", action="store_true",
                    help="CDN twin: 403 a blob request with no Signature=")
    ap.add_argument("--token-redirect-loop", action="store_true",
                    help="/token answers 302 to itself forever — the client's "
                         "redirect budget is the only thing that ends it")
    ap.add_argument("--token-len", type=int, default=0, metavar="N",
                    help="pad issued bearers to N chars (JWT-sized tokens)")
    ap.add_argument("--cdn", action="store_true",
                    help="CDN twin: serve blobs only, count Authorization "
                         "headers (/ctl/saw_authorization)")
    ap.add_argument("--page-tags", type=int, default=0, metavar="N",
                    help="page tags/list N at a time even without ?n=")
    args = ap.parse_args()
    STATE.update(auth=args.auth and not args.cdn, push=args.push,
                 realm=args.realm, basic=args.basic,
                 token_ttl=args.token_ttl, token_key=args.token_key,
                 blob_redirect=args.blob_redirect,
                 blob_redirect_sign=args.blob_redirect_sign,
                 require_signature=args.require_signature,
                 token_len=args.token_len, page_tags=args.page_tags,
                 token_redirect_loop=args.token_redirect_loop,
                 users=dict(u.partition(":")[::2] for u in args.user),
                 private={r: frozenset(filter(None, us.split(",")))
                          for r, _, us in
                          (spec.partition("=") for spec in args.private)})
    build_images(args.seed)
    if args.token_port is not None:
        threading.Thread(target=server_for(args.token_bind or args.bind,
                                           args.token_port).serve_forever,
                         daemon=True).start()
    server_for(args.bind, args.port).serve_forever()


if __name__ == "__main__":
    main()
