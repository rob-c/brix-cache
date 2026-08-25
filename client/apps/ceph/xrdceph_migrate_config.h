/*
 * xrdceph_migrate_config.h — site-profile config file for the C++
 * XrdCeph<->CephFS migration tools (shared by xrdceph_striper_migrate.cpp
 * and xrdceph_cephfs_to_striper.cpp; format identical to the Python tools'
 * pymigrate.common.load_tool_config).
 *
 * WHAT: A tiny header-only parser for the flat `key = value` profile passed
 *       via --config (or $XRDCEPH_MIGRATE_CONF): '#' comments (inline
 *       allowed), blank lines ignored, whitespace trimmed, empty value =
 *       unset. The key set is CLOSED — an unknown key is a hard error,
 *       because a typo'd pool name in a tool that can delete data must fail
 *       loudly, not silently fall back to a default.
 *
 * WHY:  Operators define pools + connection identity once per site instead
 *       of retyping them per invocation; it also makes the client id and
 *       CephFS fs name configurable (both were hardcoded before).
 *
 * HOW:  Header-only so the tools' single-file `g++ tool.cpp -l...` builds
 *       keep working. Precedence is applied by the caller:
 *       explicit CLI > config file > built-in default (see
 *       xrdceph_migrate_cfg_resolve).
 *
 * Besides the profile parser this also carries the CLI plumbing the two
 * tools share: the argv walk (xrdceph_migrate_cli_walk), the common value
 * options (xrdceph_migrate_cli_common), the positional-arity gate
 * (xrdceph_migrate_cli_arity) and the resolution tail / driver
 * (xrdceph_migrate_cfg_finish / xrdceph_migrate_cfg_resolve_with).
 *
 * Recognised keys:
 *   striper_pool meta_pool data_pool conf client fs_name dest_prefix strip
 */
#ifndef XRDCEPH_MIGRATE_CONFIG_H
#define XRDCEPH_MIGRATE_CONFIG_H

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

struct xrdceph_migrate_cfg {
    std::map<std::string, std::string> kv;   /* only keys with a value */
};

namespace xrdceph_migrate_cfg_detail {

inline std::string
trim(const std::string &s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) { return ""; }
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

inline bool
known_key(const std::string &k)
{
    static const char *keys[] = { "striper_pool", "meta_pool", "data_pool",
                                  "conf", "client", "fs_name",
                                  "dest_prefix", "strip" };
    for (const char *key : keys) { if (k == key) { return true; } }
    return false;
}

} /* namespace xrdceph_migrate_cfg_detail */

/* Parse `path` into *cfg. Returns true on success; on failure prints a
 * one-line reason (with file:line) to stderr and returns false. */
inline bool
xrdceph_migrate_cfg_load(const std::string &path, xrdceph_migrate_cfg *cfg)
{
    using xrdceph_migrate_cfg_detail::trim;
    using xrdceph_migrate_cfg_detail::known_key;

    std::ifstream f(path);
    if (!f) {
        fprintf(stderr, "--config: cannot open %s\n", path.c_str());
        return false;
    }
    std::string raw;
    int lineno = 0;
    while (std::getline(f, raw)) {
        lineno++;
        std::string line = raw;
        size_t hash = line.find('#');
        if (hash != std::string::npos) { line.erase(hash); }
        line = trim(line);
        if (line.empty()) { continue; }

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            fprintf(stderr, "--config: %s:%d: expected 'key = value', "
                    "got \"%s\"\n", path.c_str(), lineno, raw.c_str());
            return false;
        }
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (!known_key(key)) {
            fprintf(stderr, "--config: %s:%d: unknown config key '%s' "
                    "(known: striper_pool, meta_pool, data_pool, conf, "
                    "client, fs_name, dest_prefix, strip)\n",
                    path.c_str(), lineno, key.c_str());
            return false;
        }
        if (!val.empty()) { cfg->kv[key] = val; }
    }
    return true;
}

/* Precedence: explicit CLI (non-empty) > config file > built-in default. */
inline std::string
xrdceph_migrate_cfg_resolve(const std::string &cli_value,
                            const xrdceph_migrate_cfg &cfg,
                            const std::string &key,
                            const std::string &dflt = "")
{
    if (!cli_value.empty()) { return cli_value; }
    auto it = cfg.kv.find(key);
    if (it != cfg.kv.end()) { return it->second; }
    return dflt;
}

/* The value options every migration tool takes: --strip --conf --config
 * --threads. Returns 1 when `a` was consumed (advancing *i past the value). */
inline int
xrdceph_migrate_cli_common(const std::string &a, int *i, int argc, char **argv,
                           std::string *strip, std::string *conf,
                           std::string *config, int *threads)
{
    const std::pair<const char *, std::string *> sopts[] = {
        { "--strip", strip }, { "--conf", conf }, { "--config", config },
    };
    for (auto &o : sopts) {
        if (a == o.first && *i + 1 < argc) { *o.second = argv[++(*i)]; return 1; }
    }
    if (a == "--threads" && *i + 1 < argc) { *threads = atoi(argv[++(*i)]); return 1; }
    return 0;
}

/* Shared argv walk: the tool's value options first (1 = consumed, -1 = hard
 * error), then its boolean flags, then positionals; an unknown --option is
 * refused. Returns 0 or the exit code. */
inline int
xrdceph_migrate_cli_walk(int argc, char **argv,
                         int (*value_opt)(const std::string &, int *, int, char **),
                         int (*flag_opt)(const std::string &),
                         std::vector<std::string> *pos)
{
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        int rc = value_opt(a, &i, argc, argv);
        if (rc < 0) { return 2; }
        if (rc > 0) { continue; }
        if (flag_opt(a)) { continue; }
        if (a.rfind("--", 0) == 0) {
            fprintf(stderr, "unknown option %s\n", a.c_str());
            return 2;
        }
        pos->push_back(a);
    }
    return 0;
}

/* Positional-arity gate: the tools take all three positionals or NONE (a
 * partial mix with --config is ambiguous and refused). */
inline int
xrdceph_migrate_cli_arity(const std::vector<std::string> &pos, const char *prog,
                          const char *usage)
{
    if (pos.size() != 3 && pos.size() != 0) {
        fprintf(stderr, "usage: %s %s [opts]\n"
                "       (give all three positionals, or none with --config)\n",
                prog, usage);
        return 2;
    }
    return 0;
}

/* Shared resolution tail: every required key must have resolved non-empty,
 * then the ceph.conf fallback chain (--conf > profile `conf` > $CEPH_CONF >
 * /etc/ceph/ceph.conf) and the worker-count clamp. Returns 0 or exit code. */
inline int
xrdceph_migrate_cfg_finish(const std::pair<const char *, std::string *> *req,
                           size_t nreq, const xrdceph_migrate_cfg &cfg,
                           std::string *conf, int *threads)
{
    for (size_t k = 0; k < nreq; k++) {
        if (req[k].second->empty()) {
            fprintf(stderr, "missing %s: pass positionals or set it in --config\n",
                    req[k].first);
            return 2;
        }
    }
    if (conf->empty()) { *conf = xrdceph_migrate_cfg_resolve("", cfg, "conf"); }
    if (conf->empty()) { *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF")
                                                     : "/etc/ceph/ceph.conf"; }
    if (*threads < 1) { *threads = 1; }
    return 0;
}

/* Shared resolution driver: pick up $XRDCEPH_MIGRATE_CONF when --config was
 * not given, load the profile, then run the tool's own resolve step on it. */
inline int
xrdceph_migrate_cfg_resolve_with(const std::vector<std::string> &pos,
                                 const char *prog, std::string *config,
                                 int (*resolve_fn)(const std::vector<std::string> &,
                                                   const char *,
                                                   const xrdceph_migrate_cfg &))
{
    if (config->empty() && getenv("XRDCEPH_MIGRATE_CONF") != NULL) {
        *config = getenv("XRDCEPH_MIGRATE_CONF");
    }
    xrdceph_migrate_cfg cfg;
    if (!config->empty() && !xrdceph_migrate_cfg_load(*config, &cfg)) { return 2; }
    return resolve_fn(pos, prog, cfg);
}

#endif /* XRDCEPH_MIGRATE_CONFIG_H */
