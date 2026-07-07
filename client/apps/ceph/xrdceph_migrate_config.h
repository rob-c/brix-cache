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
 * Recognised keys:
 *   striper_pool meta_pool data_pool conf client fs_name dest_prefix strip
 */
#ifndef XRDCEPH_MIGRATE_CONFIG_H
#define XRDCEPH_MIGRATE_CONFIG_H

#include <cstdio>
#include <fstream>
#include <map>
#include <string>

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

#endif /* XRDCEPH_MIGRATE_CONFIG_H */
