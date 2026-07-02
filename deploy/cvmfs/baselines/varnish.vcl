# deploy/cvmfs/baselines/varnish.vcl — minimal CVMFS caching baseline.
vcl 4.1;
backend stratum1 { .host = "@ORIGINHOST@"; .port = "@ORIGINPORT@"; }

sub vcl_recv {
    if (req.url !~ "^/cvmfs/") { return (synth(403)); }
    if (req.url ~ "/api/v1\.0/geo/") { return (pass); }
    return (hash);
}
sub vcl_backend_response {
    if (bereq.url ~ "/data/") { set beresp.ttl = 30d; }
    elsif (bereq.url ~ "\.cvmfs(published|whitelist|reflog)$") {
        set beresp.ttl = 61s; set beresp.grace = 10m;
    }
}
