"""Fixed epoch and the proxy-certificate OIDs, defined once.

The flat stack repeated these six assignments verbatim at the head of
``x509forge.py`` and both of its continuation shards -- the shards were
``exec``-ed into the parent's globals, so each rebound the names the previous
one had just set.  Identical values made that harmless and also made it
invisible: a change to one copy would have been silently overwritten by the
next shard to load, in load order, with no error anywhere.
"""

import datetime

_EPOCH = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_DAY = datetime.timedelta(days=1)

# Policy-language OIDs.
OID_PROXY_CERT_INFO = "1.3.6.1.5.5.7.1.14"
OID_PPL_INHERIT_ALL = "1.3.6.1.5.5.7.21.1"   # full / impersonation
OID_PPL_INDEPENDENT = "1.3.6.1.5.5.7.21.2"   # independent
OID_GLOBUS_LIMITED = "1.3.6.1.4.1.3536.1.1.1.9"
