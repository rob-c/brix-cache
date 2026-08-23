"""Nginx configuration builders for the SHM fork-safety regression."""

from settings import BIND_HOST


WORKERS = 2


def _common_head(prefix):
    return (
        "worker_processes %d;\n"
        "daemon on;\n"
        "master_process on;\n"
        "pid %s/logs/nginx.pid;\n"
        "error_log %s/logs/error.log info;\n"
        "events { worker_connections 256; }\n"
    ) % (WORKERS, prefix, prefix)


def comprehensive_conf(prefix, datadir, frmdir, root_port, mgr_port, http_port):
    """Register the unconditional and optional custom shared-memory zones."""
    body = """
stream {
    access_log off;
    brix_kv_zone tcache 1m key=64 val=512;
    brix_rate_limit_zone zone=rlz:10m;

    server {
        listen __H__:__ROOT__;
        brix_root on;
        brix_storage_backend posix:__DATA__;
        brix_auth none;
        brix_allow_write on;
        brix_session_slots 64;
        brix_registry_slots 64;
        brix_tpc_allow_local on;
        brix_tpc_key_ttl 60s;
        brix_prepare_command /bin/true;
        brix_frm on;
        brix_frm_queue_path __FRM__/queue;
        brix_frm_max_inflight 8;
        brix_frm_stagecmd /bin/true;
        brix_rate_limit_rule zone=rlz key=ip rate=10000r/s burst=20000;
    }

    server {
        listen __H__:__MGR__;
        brix_root on;
        brix_auth none;
        brix_manager_mode on;
        brix_collapse_redir on;
        brix_collapse_redir_ttl 5s;
        brix_redir_cache_slots 64;
    }
}

http {
    access_log off;
    client_body_temp_path __PREFIX__/logs/cbt;
    proxy_temp_path __PREFIX__/logs/pt;
    fastcgi_temp_path __PREFIX__/logs/ft;
    uwsgi_temp_path __PREFIX__/logs/ut;
    scgi_temp_path __PREFIX__/logs/st;

    server {
        listen __H__:__HTTP__;
        location = /metrics { brix_metrics on; }

        location /dav/ {
            brix_webdav on;
            brix_storage_backend posix:__DATA__;
            brix_webdav_auth none;
            brix_allow_write on;
        }

        location /s3/ {
            brix_s3 on;
            brix_storage_backend posix:__DATA__;
            brix_s3_region us-east-1;
            brix_s3_access_key testkey;
            brix_s3_secret_key testsecret;
        }

        location /proxy/ {
            brix_webdav_proxy on;
            brix_webdav_proxy_dynamic on;
            brix_admin_allow 127.0.0.1/32 ::1/128;
        }
    }
}
"""
    replacements = {
        "__H__": BIND_HOST,
        "__ROOT__": str(root_port),
        "__MGR__": str(mgr_port),
        "__HTTP__": str(http_port),
        "__DATA__": datadir,
        "__FRM__": frmdir,
        "__PREFIX__": prefix,
    }
    for marker, value in replacements.items():
        body = body.replace(marker, value)
    return _common_head(prefix) + body


def minimal_conf(prefix, datadir, root_port, http_port):
    """Register the unconditional stream zones and metrics endpoint."""
    body = """
stream {
    access_log off;
    server {
        listen __H__:__ROOT__;
        brix_root on;
        brix_storage_backend posix:__DATA__;
        brix_auth none;
        brix_allow_write on;
    }
}

http {
    access_log off;
    server {
        listen __H__:__HTTP__;
        location = /metrics { brix_metrics on; }
    }
}
"""
    replacements = {
        "__H__": BIND_HOST,
        "__ROOT__": str(root_port),
        "__HTTP__": str(http_port),
        "__DATA__": datadir,
    }
    for marker, value in replacements.items():
        body = body.replace(marker, value)
    return _common_head(prefix) + body
