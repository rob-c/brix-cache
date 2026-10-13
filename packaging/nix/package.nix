{ pkgs, src }:

let
  inherit (pkgs) lib stdenv;
  version = "2.0.0";

  source = lib.cleanSourceWith {
    inherit src;
    filter = path: type:
      let
        name = baseNameOf path;
        generatedSuffixes = [
          ".a"
          ".d"
          ".dylib"
          ".gcda"
          ".gcno"
          ".o"
          ".pyc"
          ".so"
        ];
      in
        !(lib.elem name [
          ".git"
          ".debbuild"
          ".nix-venv"
          ".rpmbuild"
          ".pytest_cache"
          ".venv"
          "bin"
          "brix-conform-report"
          "build"
          "dist"
          "result"
          "__pycache__"
        ])
        && !(lib.hasPrefix "result-" name)
        && !(lib.hasInfix ".so." name)
        && !(lib.hasInfix ".dylib." name)
        && !(lib.any (suffix: lib.hasSuffix suffix name) generatedSuffixes);
  };

  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = with pkgs; [
    brotli
    bzip2
    ceph
    curl
    fuse3
    jansson
    krb5
    libseccomp
    liburing
    libxcrypt
    libxml2
    lz4
    openssl
    python3
    sqlite
    xz
    zlib
    zstd
  ];

  brix-cache-client = stdenv.mkDerivation {
    pname = "brix-cache-client";
    inherit version nativeBuildInputs buildInputs;
    src = source;

    enableParallelBuilding = true;

    buildPhase = ''
      runHook preBuild
      make -C client clean
      make -C client -j"$NIX_BUILD_CORES" \
        BRIX_CLIENT_VERSION="${version}" \
        BRIX_LZ4_CFLAGS="-I${pkgs.lz4.dev}/include" \
        BRIX_LZ4_LIBS="-L${lib.getLib pkgs.lz4}/lib -Wl,-rpath,${lib.getLib pkgs.lz4}/lib -l:liblz4.so.1" \
        all
      runHook postBuild
    '';

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      client/bin/xrdcp --version | grep -F "${version}"
      src_file="$(mktemp)"
      dst_file="$(mktemp)"
      printf 'brix-cache nix package\n' > "$src_file"
      client/bin/xrdcp -f "$src_file" "$dst_file"
      cmp "$src_file" "$dst_file"
      runHook postCheck
    '';

    installPhase = ''
      runHook preInstall
      make -C client install install-bin install-compat \
        PREFIX="$out" \
        LIBDIR="$out/lib" \
        INCLUDEDIR="$out/include" \
        PKGCONFDIR="$out/lib/pkgconfig" \
        LIBEXECDIR="$out/libexec/brix"
      patchShebangs "$out/libexec/brix/brix_config_migrate.py"
      runHook postInstall
    '';

    meta = {
      description = "Clean-room XRootD-compatible BriX client and cache tools";
      homepage = "https://github.com/rob-c/brix-cache";
      license = lib.licenses.agpl3Only;
      platforms = lib.platforms.linux;
    };
  };

  brix-nginx-module = stdenv.mkDerivation {
    pname = "brix-cache-nginx-module-source";
    inherit version buildInputs;
    src = source;

    dontBuild = true;
    installPhase = ''
      cp -R . "$out"
    '';

    passthru = {
      dynamic = true;
    };

    meta = {
      description = "BriX-Cache dynamic modules for nginx";
      homepage = "https://github.com/rob-c/brix-cache";
      license = [ lib.licenses.agpl3Only ];
      platforms = lib.platforms.linux;
    };
  };

  nginx-brix-cache = (pkgs.nginxStable.override {
    modules = [ brix-nginx-module ];
    # nginxStable's default can move ahead of curl and Ceph during an OpenSSL
    # transition. BriX links both into nginx, so select nixpkgs' supported
    # default explicitly and keep one OpenSSL ABI in the server process.
    openssl = pkgs.openssl;
  }).overrideAttrs (old: {
    # Module buildInputs supply the .pc files; pkg-config itself is a native
    # build tool and must be added to the resulting nginx derivation.
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.pkg-config ];
    # Nixpkgs evaluates third-party module metadata before mkDerivation makes
    # all dependency attributes observable.  Carry the BriX closure onto the
    # final nginx derivation explicitly so every pkg-config probe is hermetic.
    buildInputs = (old.buildInputs or [ ]) ++ buildInputs;
  });

  # The installed nginx closure intentionally contains only runtime files.
  # Native self-contained seam tests additionally need nginx's source headers
  # and the generated ngx_auto_* headers from the exact release configuration.
  # Preserve that configured tree in a development-only output rather than
  # bloating the release package or reconstructing it imperatively in /tmp.
  # Object-linked tests continue to skip when the runtime package deliberately
  # omits intermediate addon objects.
  nginx-brix-test-sdk = nginx-brix-cache.overrideAttrs (_old: {
    pname = "brix-cache-nginx-test-sdk";
    outputs = [ "out" ];
    allowedReferences = null;
    disallowedReferences = [ ];
    buildPhase = ''
      runHook preBuild
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out"
      cp -R . "$out/"
    '';
  });
in {
  inherit brix-cache-client brix-nginx-module nginx-brix-cache nginx-brix-test-sdk;

  brix-cache = pkgs.symlinkJoin {
    name = "brix-cache-${version}";
    paths = [ brix-cache-client nginx-brix-cache ];
  };

  default = brix-cache-client;
}
