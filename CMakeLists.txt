# ==========================================================================
# CMakeLists.txt — developer/system build for BriX-Cache
#
# This is a *thin orchestrator*, not a from-scratch CMake port. The real build
# logic lives in two places that already work and stay authoritative:
#
#   1. nginx dynamic modules — driven by nginx's own ./configure against the
#      distribution nginx source shipped by `nginx-mod-devel`, plus this repo's
#      root ./config source list (exactly what the RPM's %nginx_modconfigure /
#      %nginx_modbuild macros do).
#   2. native client tools    — driven by the in-tree client/ and shared/xrdproto
#      Makefiles.
#
# CMake wires those together so you can:
#
#     cmake -B build
#     cmake --build build -j$(nproc)
#     sudo cmake --install build          # overwrites an installed brix RPM's files
#
# It intentionally installs to the SAME absolute paths the RPM uses, so a system
# install lands on top of nginx-mod-brix-cache / brix-cache-client. See the
# "Overwriting an installed RPM" note at the bottom.
# ==========================================================================

cmake_minimum_required(VERSION 3.16)
# Enable C purely so GNUInstallDirs can detect the multilib libdir (lib64 on
# el9/x86_64). CMake still compiles nothing itself — the module and client builds
# are driven through nginx's ./configure and the in-tree Makefiles below.
project(brix-cache C)

include(GNUInstallDirs)
include(ProcessorCount)
ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 1)
endif()

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------
option(BRIX_BUILD_MODULES    "Build the nginx dynamic modules"           ON)
option(BRIX_BUILD_CLIENT     "Build the native client tools (client/)"   ON)
option(BRIX_BUILD_CEPH_TOOLS "Build the Ceph migration/rescue tools"     ON)
option(BRIX_BUILD_COMPAT     "Also produce brix- prefixed compat tools"  OFF)

# Default the install prefix to /usr (not /usr/local) so `make install` lands on
# the RPM's client-tool paths (/usr/bin, /usr/lib64). Only forced when the user
# did not pass -DCMAKE_INSTALL_PREFIX=... themselves.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH
        "Install prefix (defaulted to /usr to overwrite the brix RPM)" FORCE)
    include(GNUInstallDirs)   # re-derive CMAKE_INSTALL_FULL_* against the new prefix
endif()

# --------------------------------------------------------------------------
# Locate the distribution nginx source + module install paths.
#
# `nginx-mod-devel` drops both the nginx source tree under /usr/src and an RPM
# macro file that records the exact directories. We read that macro file when it
# exists (authoritative), and fall back to globbing /usr/src otherwise. Every
# value is an overridable cache variable.
# --------------------------------------------------------------------------
set(NGINX_MACROS "/usr/lib/rpm/macros.d/macros.nginxmods")

function(_brix_read_macro out_var macro_name default)
    set(_val "${default}")
    if(EXISTS "${NGINX_MACROS}")
        file(STRINGS "${NGINX_MACROS}" _line REGEX "^%${macro_name}[ \t]+")
        if(_line)
            string(REGEX REPLACE "^%${macro_name}[ \t]+" "" _val "${_line}")
            string(STRIP "${_val}" _val)
        endif()
    endif()
    set(${out_var} "${_val}" PARENT_SCOPE)
endfunction()

# nginx source dir: prefer the macro, else newest /usr/src/nginx-*
_brix_read_macro(_macro_srcdir "_nginx_srcdir" "")
if(_macro_srcdir STREQUAL "")
    file(GLOB _nginx_src_candidates "/usr/src/nginx-*")
    if(_nginx_src_candidates)
        list(SORT _nginx_src_candidates)
        list(GET _nginx_src_candidates -1 _macro_srcdir)
    endif()
endif()

_brix_read_macro(_macro_moddir     "nginx_moddir"     "/usr/lib64/nginx/modules")
_brix_read_macro(_macro_modconfdir "nginx_modconfdir" "/usr/share/nginx/modules")
_brix_read_macro(_macro_abi        "_nginx_abiversion" "unknown")

set(NGINX_SRC_DIR     "${_macro_srcdir}"     CACHE PATH "Distribution nginx source tree (from nginx-mod-devel)")
set(NGINX_MOD_DIR     "${_macro_moddir}"     CACHE PATH "nginx module install dir")
set(NGINX_MODCONF_DIR "${_macro_modconfdir}" CACHE PATH "nginx module-loader config dir")

if(BRIX_BUILD_MODULES)
    if(NGINX_SRC_DIR STREQUAL "" OR NOT EXISTS "${NGINX_SRC_DIR}/configure")
        message(FATAL_ERROR
            "nginx source not found. Install the module SDK:\n"
            "    sudo dnf install nginx-mod-devel\n"
            "or point -DNGINX_SRC_DIR=/path/to/nginx-source at an unpacked nginx tree.")
    endif()
    message(STATUS "nginx source .......... ${NGINX_SRC_DIR} (abi ${_macro_abi})")
    message(STATUS "nginx module dir ...... ${NGINX_MOD_DIR}")
    message(STATUS "nginx modconf dir ..... ${NGINX_MODCONF_DIR}")
endif()

# --------------------------------------------------------------------------
# Compiler/linker flags for the nginx module build.
#
# Mirror the RPM: use the distro %{optflags} and %{build_ldflags} when rpm is
# available (guarantees the same hardening the packaged build uses), else a
# sensible default. --with-ld-opt always adds -Wl,-E so the combined module
# exports its symbols to the separately-loaded xrdhttp filter module.
# --------------------------------------------------------------------------
find_program(RPM_EXECUTABLE rpm)
# Keep the hardening set in step with the canonical nginx build in ./config
# (FORTIFY + stack-clash + CET + format hardening); this fallback is only used
# for non-RPM dev builds, where rpm %{optflags} is unavailable.
set(_default_optflags "-O2 -g -pipe -Wall -Werror=format-security -Wformat -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -march=x86-64-v2")
set(_default_ldflags  "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")
if(RPM_EXECUTABLE)
    execute_process(COMMAND ${RPM_EXECUTABLE} --eval "%{optflags}"
        OUTPUT_VARIABLE _rpm_optflags OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${RPM_EXECUTABLE} --eval "%{build_ldflags}"
        OUTPUT_VARIABLE _rpm_ldflags OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
if(NOT _rpm_optflags OR _rpm_optflags MATCHES "optflags")
    set(_rpm_optflags "${_default_optflags}")
endif()
if(NOT _rpm_ldflags OR _rpm_ldflags MATCHES "build_ldflags")
    set(_rpm_ldflags "${_default_ldflags}")
endif()
set(BRIX_MODULE_CFLAGS "${_rpm_optflags}" CACHE STRING "cc-opt for the nginx module build")
set(BRIX_MODULE_LDFLAGS "${_rpm_ldflags}" CACHE STRING "ld-opt (base) for the nginx module build")

# pcre cflags — the nginx-mod-devel macro appends $(pcre-config --cflags); it is
# optional (empty if the tool is absent), so probe without failing.
find_program(PCRE_CONFIG NAMES pcre-config pcre2-config)
set(_pcre_cflags "")
if(PCRE_CONFIG)
    execute_process(COMMAND ${PCRE_CONFIG} --cflags
        OUTPUT_VARIABLE _pcre_cflags OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET RESULT_VARIABLE _pcre_rc)
    if(NOT _pcre_rc EQUAL 0)
        set(_pcre_cflags "")
    endif()
endif()

# --------------------------------------------------------------------------
# Target 1: nginx dynamic modules
#
# Emit an idempotent helper script (copy nginx source once, ./configure when the
# root ./config changes, then `make modules` — which is itself incremental) and
# drive it from an always-run custom target. The two .so land in the module
# build dir below.
# --------------------------------------------------------------------------
set(MOD_WORK_DIR "${CMAKE_CURRENT_BINARY_DIR}/nginx-src")   # copy of the nginx tree
set(MOD_OUT_DIR  "${CMAKE_CURRENT_BINARY_DIR}/modules")     # nginx --builddir (holds the .so)
set(STREAM_SO "${MOD_OUT_DIR}/ngx_stream_brix_module.so")
set(FILTER_SO "${MOD_OUT_DIR}/ngx_http_brix_xrdhttp_filter_module.so")
set(MOD_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/build-nginx-modules.sh")

# NOTE: inside the script use bash vars WITHOUT braces ("$VAR"); CMake expands
# only ${...}, so we bake configure-time values via ${...} at the top and use
# plain $VAR everywhere else.
file(WRITE "${MOD_SCRIPT}"
"#!/usr/bin/env bash
# Auto-generated by CMake — do not edit; regenerated on every `cmake` run.
set -euo pipefail

NGINX_SRC=\"${NGINX_SRC_DIR}\"
REPO=\"${REPO_ROOT}\"
WORK=\"${MOD_WORK_DIR}\"
BUILDDIR=\"${MOD_OUT_DIR}\"
CC_OPT=\"${BRIX_MODULE_CFLAGS} ${_pcre_cflags}\"
LD_OPT=\"${BRIX_MODULE_LDFLAGS} -Wl,-E\"
JOBS=\"${NPROC}\"

mkdir -p \"$WORK\" \"$BUILDDIR\"

# 1. Copy the distribution nginx source once (configure/ presence = stamp).
if [ ! -f \"$WORK/configure\" ]; then
    echo \"[brix] copying nginx source: $NGINX_SRC -> $WORK\"
    cp -a \"$NGINX_SRC/.\" \"$WORK/\"
fi

cd \"$WORK\"

# 2. (Re)configure when needed: no Makefile yet, or the module source list
#    (repo ./config) changed since we last configured.
if [ ! -f \"$WORK/Makefile\" ] || [ \"$REPO/config\" -nt \"$WORK/Makefile\" ]; then
    echo \"[brix] configuring nginx module build\"
    ./configure --with-compat \\
        --with-cc-opt=\"$CC_OPT\" \\
        --with-ld-opt=\"$LD_OPT\" \\
        --add-dynamic-module=\"$REPO\" \\
        --builddir=\"$BUILDDIR\" \\
        --with-threads \\
        --with-stream=dynamic \\
        --with-stream_ssl_module \\
        --with-http_ssl_module \\
        --with-http_dav_module
fi

# 3. Build the modules (incremental).
echo \"[brix] building nginx modules (-j$JOBS)\"
make -C \"$WORK\" -j\"$JOBS\" modules

ls -l \"$BUILDDIR\"/ngx_stream_brix_module.so \\
      \"$BUILDDIR\"/ngx_http_brix_xrdhttp_filter_module.so
")

if(BRIX_BUILD_MODULES)
    add_custom_target(nginx-modules ALL
        COMMAND bash "${MOD_SCRIPT}"
        BYPRODUCTS "${STREAM_SO}" "${FILTER_SO}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Building nginx dynamic modules against ${NGINX_SRC_DIR}"
        USES_TERMINAL VERBATIM)
endif()

# --------------------------------------------------------------------------
# Target 2: native client tools (client/ + shared/xrdproto).
#
# Build + verification + install live in cmake/BrixClientTools.cmake (feature
# probing, granular proto->tools->ceph targets, post-build assertions, a clean
# target, and the DESTDIR-aware install hook).
# --------------------------------------------------------------------------
if(BRIX_BUILD_CLIENT)
    include(cmake/BrixClientTools.cmake)
endif()

# --------------------------------------------------------------------------
# Install rules — land on the RPM's absolute paths.
# --------------------------------------------------------------------------
if(BRIX_BUILD_MODULES)
    # Generate the loader snippet (combined module first so its symbols back the
    # filter via RTLD_GLOBAL — same order the RPM writes).
    set(MOD_LOADER "${CMAKE_CURRENT_BINARY_DIR}/mod-xrootd.conf")
    file(WRITE "${MOD_LOADER}"
"load_module \"${NGINX_MOD_DIR}/ngx_stream_brix_module.so\";
load_module \"${NGINX_MOD_DIR}/ngx_http_brix_xrdhttp_filter_module.so\";
")

    install(PROGRAMS "${STREAM_SO}" "${FILTER_SO}" DESTINATION "${NGINX_MOD_DIR}")
    install(FILES    "${MOD_LOADER}"               DESTINATION "${NGINX_MODCONF_DIR}")

    # Example server config, logrotate rule, and Grafana/Prometheus contrib
    # (same locations as the RPM). Absolute DESTINATIONs ignore the prefix.
    install(FILES "${REPO_ROOT}/contrib/brix-cache.conf.example"
            DESTINATION "/etc/nginx/conf.d")
    install(FILES "${REPO_ROOT}/contrib/logrotate.d/nginx-xrootd"
            DESTINATION "/etc/logrotate.d")
    install(FILES "${REPO_ROOT}/contrib/grafana-dashboard.json"
                  "${REPO_ROOT}/contrib/prometheus-alerts.yml"
            DESTINATION "${CMAKE_INSTALL_FULL_DATADIR}/nginx-xrootd")
endif()

# (client-tool install rules are registered by cmake/BrixClientTools.cmake)

# --------------------------------------------------------------------------
# Post-install hint for overwriting a running install.
# --------------------------------------------------------------------------
if(BRIX_BUILD_MODULES)
    install(CODE "
        message(STATUS \"\")
        message(STATUS \"BriX modules installed to ${NGINX_MOD_DIR}.\")
        message(STATUS \"If nginx is running: sudo nginx -t && sudo systemctl reload nginx\")
        message(STATUS \"(Overwrites files owned by an installed brix RPM; run\")
        message(STATUS \" 'rpm -V nginx-mod-brix-cache' to see the divergence.)\")
    ")
endif()

# ==========================================================================
# Overwriting an installed RPM
# --------------------------------------------------------------------------
# `cmake --install` writes files directly to the paths above. If a
# nginx-mod-brix-cache / brix-cache-client RPM is installed, those files are
# overwritten in place. The RPM database is NOT updated, so:
#   * `rpm -V nginx-mod-brix-cache` will report the changed files (expected).
#   * A later `dnf reinstall/update` of the RPM will replace your files again.
# This is intentional for a local dev override. To go back to the packaged
# build:  sudo dnf reinstall nginx-mod-brix-cache brix-cache-client
# ==========================================================================
