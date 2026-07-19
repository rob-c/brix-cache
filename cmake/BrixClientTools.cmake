# ==========================================================================
# BrixClientTools.cmake — build + install the native client tools.
#
# Included by the top-level CMakeLists.txt. Like the nginx-module build, this is
# a *thin orchestrator* over the authoritative in-tree Makefiles (client/ and
# shared/xrdproto/) — it does NOT reimplement their feature-gated source lists in
# CMake. What it adds on top of a bare `make -C client`:
#
#   * feature probing + a build summary (which optional tools will build here),
#   * granular targets (proto -> tools -> ceph-tools) with correct ordering,
#   * an aggregate `brix-client` target,
#   * post-build verification that the always-on core binaries actually linked
#     (mirrors the RPM spec's "assert nothing was silently gate-skipped" loop),
#   * a `brix-client-clean` convenience target,
#   * the DESTDIR-aware install hook (client/Makefile install-bin).
#
# Requires from the parent scope: REPO_ROOT, NPROC, BRIX_BUILD_CEPH_TOOLS,
# BRIX_BUILD_COMPAT, CMAKE_INSTALL_PREFIX, CMAKE_INSTALL_FULL_LIBDIR.
# ==========================================================================

# --------------------------------------------------------------------------
# Optional flag overrides. Empty by default -> the Makefiles' own flags (known
# good; that's what the CLAUDE.md dev flow uses). Set these for a hardened build,
# e.g. -DBRIX_CLIENT_CFLAGS="$(rpm --eval %{optflags})". NOTE: changing the flag
# regime in an already-built tree needs a `brix-client-clean` first (object files
# compiled under different flags — e.g. non-PIE — will not relink cleanly).
# --------------------------------------------------------------------------
set(BRIX_CLIENT_CFLAGS  "" CACHE STRING "Extra CFLAGS for the client tool build (empty = Makefile default)")
set(BRIX_CLIENT_LDFLAGS "" CACHE STRING "Extra LDFLAGS for the client tool build (empty = Makefile default)")

set(_client_make_flags "")
if(BRIX_CLIENT_CFLAGS)
    list(APPEND _client_make_flags "CFLAGS=${BRIX_CLIENT_CFLAGS}")
endif()
if(BRIX_CLIENT_LDFLAGS)
    list(APPEND _client_make_flags "LDFLAGS=${BRIX_CLIENT_LDFLAGS}")
endif()

# --------------------------------------------------------------------------
# Feature probing — purely to print an accurate build summary. The client
# Makefile does its own authoritative gating; these mirror its probes so the
# CMake output tells the truth about what will (and won't) build on this host.
# --------------------------------------------------------------------------
find_package(PkgConfig QUIET)
set(_have_fuse3 NO)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(FUSE3 QUIET fuse3)
    if(FUSE3_FOUND)
        set(_have_fuse3 YES)
    endif()
endif()

find_path(BRIX_RADOS_INCLUDE        rados/librados.h)
find_path(BRIX_CEPHFS_INCLUDE       cephfs/libcephfs.h)
find_path(BRIX_RADOSSTRIPER_INCLUDE radosstriper/libradosstriper.h)
find_program(BRIX_CXX NAMES g++ c++)

set(_have_rados NO)
if(BRIX_RADOS_INCLUDE)
    set(_have_rados YES)
endif()

message(STATUS "client tools .......... core CLI (xrd, xrdcp, xrdfs, ...) always built")
message(STATUS "  FUSE mounts (xrootdfs/brixMount) .. ${_have_fuse3} (libfuse3)")
message(STATUS "  Ceph rescue tools ................. ${_have_rados} (rados/librados.h)")
if(BRIX_BUILD_CEPH_TOOLS AND NOT _have_rados)
    message(WARNING
        "BRIX_BUILD_CEPH_TOOLS=ON but rados/librados.h not found — the ceph-tools "
        "target will be a no-op. Install librados-devel/libradosstriper-devel/"
        "libcephfs-devel, or set -DBRIX_BUILD_CEPH_TOOLS=OFF.")
endif()

# --------------------------------------------------------------------------
# Build targets.
#
#   brix-client-proto : shared/xrdproto (the protocol core the tools link)
#   brix-client-tools : client/         (CLI + FUSE + preload shim; depends proto)
#   brix-ceph-tools   : client ceph-tools target (depends tools; opt-in)
#   brix-client       : aggregate of the above (ALL)
#
# All are always-run (make handles incrementalism). USES_TERMINAL streams the
# compiler output live.
# --------------------------------------------------------------------------
add_custom_target(brix-client-proto
    COMMAND make -C "${REPO_ROOT}/shared/xrdproto" -j${NPROC} ${_client_make_flags}
    COMMENT "Building shared/xrdproto (protocol core)"
    USES_TERMINAL VERBATIM)

# Core binaries that must always build — verified after the tools target.
set(_brix_core_bins
    xrd xrdfs xrdcp xrdcksum xrdprep xrdgsiproxy xrddiag
    xrdmapc xrdgsitest xrdsssadmin xrdstorascan)

add_custom_target(brix-client-tools
    COMMAND make -C "${REPO_ROOT}/client" -j${NPROC} ${_client_make_flags}
    BYPRODUCTS
        "${REPO_ROOT}/client/bin/xrdcp"
        "${REPO_ROOT}/client/bin/xrdfs"
        "${REPO_ROOT}/client/bin/xrd"
    COMMENT "Building client tools (client/)"
    USES_TERMINAL VERBATIM)
add_dependencies(brix-client-tools brix-client-proto)

# Post-build assertion: the core CLI set must exist. Catches a silently broken
# link/gate before install rather than at runtime.
add_custom_command(TARGET brix-client-tools POST_BUILD
    COMMAND ${CMAKE_COMMAND}
        -DBIN_DIR=${REPO_ROOT}/client/bin
        "-DEXPECTED=${_brix_core_bins}"
        -DLABEL=core client tools
        -P ${CMAKE_CURRENT_LIST_DIR}/BrixVerifyBins.cmake
    VERBATIM)

if(BRIX_BUILD_CEPH_TOOLS)
    add_custom_target(brix-ceph-tools
        COMMAND make -C "${REPO_ROOT}/client" ceph-tools -j${NPROC} ${_client_make_flags}
        COMMENT "Building Ceph migration/rescue tools (client/apps/ceph)"
        USES_TERMINAL VERBATIM)
    add_dependencies(brix-ceph-tools brix-client-tools)

    # Only the rados-only rescue tools are guaranteed by rados headers alone;
    # verify those when rados is present (the two C++ tools need g++ + extra
    # headers and are reported, not strictly asserted).
    if(_have_rados)
        add_custom_command(TARGET brix-ceph-tools POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                -DBIN_DIR=${REPO_ROOT}/client/bin
                "-DEXPECTED=xrdrados_rescue;xrdcephfs_rescue;xrdceph_migrate"
                -DLABEL=ceph rescue tools
                -P ${CMAKE_CURRENT_LIST_DIR}/BrixVerifyBins.cmake
            VERBATIM)
    endif()
endif()

# --------------------------------------------------------------------------
# Compat flavour (opt-in) — the SAME name-agnostic binaries surfaced under a
# "brix-" prefix via the Makefile `compat` target (in-tree client/bin/brix-*
# symlinks; the tools self-ID from argv[0]). Mirrors the Makefile so CI and the
# tests/test_client_compat_naming.py checks have client/bin/brix-* to run.
# --------------------------------------------------------------------------
if(BRIX_BUILD_COMPAT)
    add_custom_target(brix-client-compat
        COMMAND make -C "${REPO_ROOT}/client" compat -j${NPROC} ${_client_make_flags}
        COMMENT "Producing brix- prefixed compat tool links (client/bin/brix-*)"
        USES_TERMINAL VERBATIM)
    add_dependencies(brix-client-compat brix-client-tools)
    # compat's ceph links depend on the ceph binaries existing first.
    if(BRIX_BUILD_CEPH_TOOLS)
        add_dependencies(brix-client-compat brix-ceph-tools)
    endif()

    # Assert the prefixed core set exists — the compat mirror of the core-tools
    # POST_BUILD check above (same guarantee, brix- names).
    set(_brix_core_compat_bins "")
    foreach(_b IN LISTS _brix_core_bins)
        list(APPEND _brix_core_compat_bins "brix-${_b}")
    endforeach()
    add_custom_command(TARGET brix-client-compat POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DBIN_DIR=${REPO_ROOT}/client/bin
            "-DEXPECTED=${_brix_core_compat_bins}"
            -DLABEL=compat client tools
            -P ${CMAKE_CURRENT_LIST_DIR}/BrixVerifyBins.cmake
        VERBATIM)
endif()

# Aggregate — this is what ends up in `make all`.
add_custom_target(brix-client ALL)
add_dependencies(brix-client brix-client-tools)
if(BRIX_BUILD_CEPH_TOOLS)
    add_dependencies(brix-client brix-ceph-tools)
endif()
if(BRIX_BUILD_COMPAT)
    add_dependencies(brix-client brix-client-compat)
endif()

# --------------------------------------------------------------------------
# Clean convenience — `cmake --build build --target brix-client-clean`.
# The in-tree Makefiles hold their own objects; CMake's own `clean` does not
# reach them, so expose their clean targets explicitly.
# --------------------------------------------------------------------------
add_custom_target(brix-client-clean
    COMMAND make -C "${REPO_ROOT}/client" clean
    COMMAND make -C "${REPO_ROOT}/shared/xrdproto" clean
    COMMENT "Cleaning client/ and shared/xrdproto/ build artifacts"
    USES_TERMINAL VERBATIM)

# --------------------------------------------------------------------------
# Install — delegate to the client Makefile's DESTDIR-aware install-bin so the
# RPM's exact tool set (CLI + links + FUSE + preload + pymigrate + man +
# completions) is installed. $ENV{DESTDIR} is honored for staged installs.
# --------------------------------------------------------------------------
install(CODE "
    message(STATUS \"Installing client tools via client/Makefile install-bin\")
    execute_process(
        COMMAND make -C \"${REPO_ROOT}/client\" install-bin
                DESTDIR=\$ENV{DESTDIR}
                PREFIX=\"${CMAKE_INSTALL_PREFIX}\"
                LIBDIR=\"${CMAKE_INSTALL_FULL_LIBDIR}\"
        RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR \"client install-bin failed (\${_rc})\")
    endif()
")
