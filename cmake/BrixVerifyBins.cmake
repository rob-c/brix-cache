# ==========================================================================
# BrixVerifyBins.cmake — run in script mode (cmake -P) to assert that an
# expected set of executables exists after a build step.
#
# Invoked by BrixClientTools.cmake POST_BUILD with:
#   -DBIN_DIR=<dir>  -DEXPECTED=<;-list of names>  -DLABEL=<human label>
#
# Fails the build (non-zero) with a clear message if any are missing — the same
# guarantee the RPM spec's `test -x client/bin/$t` loop provides.
# ==========================================================================
set(_missing "")
foreach(_name IN LISTS EXPECTED)
    if(NOT EXISTS "${BIN_DIR}/${_name}")
        list(APPEND _missing "${_name}")
    endif()
endforeach()

if(_missing)
    string(REPLACE ";" ", " _missing_str "${_missing}")
    message(FATAL_ERROR
        "${LABEL}: missing expected binaries in ${BIN_DIR}: ${_missing_str}")
endif()

list(LENGTH EXPECTED _n)
message(STATUS "${LABEL}: verified ${_n} binaries present in ${BIN_DIR}")
