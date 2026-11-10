class BrixCache < Formula
  desc "Clean-room XRootD-compatible client and cache tools"
  homepage "https://github.com/rob-c/brix-cache"
  url "https://github.com/rob-c/brix-cache.git",
      tag: "v2.0.0"
  license "AGPL-3.0-only"
  head "https://github.com/rob-c/brix-cache.git", branch: "main"

  depends_on "pkgconf" => :build
  depends_on "brotli"
  depends_on "krb5"
  depends_on "lz4"
  depends_on :macos
  depends_on "openssl@4"
  depends_on "python@3.14"
  depends_on "xz"
  depends_on "zstd"

  def install
    build_args = [
      "BRIX_CLIENT_VERSION=#{version}",
      "BRIX_OPTIMIZE=#{Hardware::CPU.arm? ? "apple_silicon" : "v2"}",
      "HAVE_FUSE3=no",
      "PREFIX=#{prefix}",
      "LIBDIR=#{lib}",
      "INCLUDEDIR=#{include}",
      "PKGCONFDIR=#{lib}/pkgconfig",
    ]

    system "make", "-C", "client", "clean"
    system "make", "-C", "client", "-j#{ENV.make_jobs}", *build_args, "all"
    system "make", "-C", "client", *build_args, "install"
    system "make", "-C", "client", *build_args, "install-compat"

    # install-compat intentionally excludes this already-prefixed standalone
    # diagnostic proxy. It is still part of the client distribution.
    bin.install "client/bin/brix-fault-proxy"
    (libexec/"brix").install "tools/brix_config_migrate.py",
                             "tools/brix_config_migrate_core.py",
                             "tools/brix_config_migrate_render.py",
                             "tools/brix_config_migrate_runtime.py",
                             "tools/logging_support.py"
    bin.install_symlink libexec/"brix/brix_config_migrate.py" => "brix-config-migrate"
    man1.install "client/man/brix-fault-proxy.1"
    man1.install "client/man/brix-config-migrate.1"
    lib.install "client/libbrixposix_preload.dylib"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/brix-xrdcp --version")
    assert_match "suggest BriX-Cache", shell_output("#{bin}/brix-config-migrate --help")

    source = testpath/"source.txt"
    destination = testpath/"destination.txt"
    source.write("brix-cache Homebrew bottle\n")
    system bin/"brix-xrdcp", source, destination
    assert_equal source.read, destination.read
  end
end
