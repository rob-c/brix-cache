def test_shell_library_python_ports_importable():
    import lib_py.dedicated
    import lib_py.fwd_matrix
    import lib_py.nginx
    import lib_py.pki
    import lib_py.refxrootd
    import lib_py.tpc_fwd
    import lib_py.util
    import lib_py.xrdhttp

    assert lib_py.util.have_cmd("python3")
