# Config Sources

These files cover nginx directive parsing, merged server config, and startup
validation for the native XRootD stream module:

- `server_conf.c`: create, merge, and enable callbacks for stream server config
- `helpers.c`: shared config string and filesystem validation helpers
- `policy.c`: VO/group policy directives and policy finalization
- `manager_map.c`: manager-map directive parsing for CMS cluster configuration
- `root_prepare.c`: root directory preparation and confinement validation
- `root_prepare.h`: Root-preparation types and prototypes
- `shared_conf.h`: Shared config types across stream and HTTP modules
- `config.h`: Config types, constants, and NGX_CONF_UNSET initialization
