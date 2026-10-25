{
  description = "BriX-Cache native clients and nginx server modules";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        import ./packaging/nix/package.nix {
          pkgs = import nixpkgs { inherit system; };
          src = self;
        });

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) brix-cache-client nginx-brix-cache;
      });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          complexipyWheel = if system == "aarch64-linux" then {
            name = "complexipy-7.0.1-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl";
            url = "https://files.pythonhosted.org/packages/e5/e3/c86048d3fba3b3d6c888de45080fda26261f2c0599b9e323ea3255e79ddb/complexipy-7.0.1-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl";
            hash = "sha256-hAErdDibC/DUgqUqnpj14whpB8DZYuupk133CXWUOfM=";
          } else {
            name = "complexipy-7.0.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
            url = "https://files.pythonhosted.org/packages/db/85/bd15c109459a9b34050a5965c5b3fa5da40f010572c556796441eef99112/complexipy-7.0.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
            hash = "sha256-zBKxlKNimb/Z9yoqr9pxjGA4ue50fzFtlWT6WOwPmCc=";
          };
          complexipy = pkgs.python3Packages.buildPythonPackage {
            pname = "complexipy";
            version = "7.0.1";
            format = "wheel";
            src = pkgs.fetchurl complexipyWheel;
            dependencies = with pkgs.python3Packages; [ tomli typer ];
            pythonImportsCheck = [ "complexipy" ];
          };
          # The pinned nixpkgs binding is 5.x, below requirements.txt's 6.x
          # interoperability baseline. Consume released binary wheels only;
          # the stock reference server remains the nixpkgs package below.
          xrootdWheel = if system == "aarch64-linux" then {
            name = "xrootd-6.2.0-cp313-cp313-manylinux_2_28_aarch64.whl";
            url = "https://files.pythonhosted.org/packages/da/a1/83796efd598a772227d1ab8a929d8e930ebda6193c5166574e6912f32211/xrootd-6.2.0-cp313-cp313-manylinux_2_28_aarch64.whl";
            sha256 = "3232e95c2dcc5521334a792296c08cd5d27282c7fa3a32c1cd1a9a4c5017be11";
          } else {
            name = "xrootd-6.2.0-cp313-cp313-manylinux_2_28_x86_64.whl";
            url = "https://files.pythonhosted.org/packages/04/7e/8fbd5192bfdb0b411c2a1c1f3e55d3637c1c5af9d578665eee02511ec882/xrootd-6.2.0-cp313-cp313-manylinux_2_28_x86_64.whl";
            sha256 = "b28ec3c7fb69c9a9e5b0a8444c2fc4334139211eec304fc139067275e2cacc10";
          };
          xrootdBindings = pkgs.python3Packages.buildPythonPackage {
            pname = "xrootd";
            version = "6.2.0";
            format = "wheel";
            src = pkgs.fetchurl xrootdWheel;
            nativeBuildInputs = [ pkgs.autoPatchelfHook ];
            buildInputs = with pkgs; [ krb5 openssl zlib libuuid stdenv.cc.cc.lib ];
            # autoPatchelf discovers DT_NEEDED libraries, not the authentication
            # plugins dlopened by libXrdUtils. Keep those on its own immutable
            # search path; never mix the wheel's ABI 6 with the reference ABI 5.
            appendRunpaths = [
              "${builtins.placeholder "out"}/${pkgs.python3.sitePackages}/pyxrootd"
            ];
            pythonImportsCheck = [ "XRootD.client" ];
          };
          python = pkgs.python3.withPackages (ps: [ complexipy xrootdBindings ] ++ (with ps; [
            cryptography
            boto3
            botocore
            brotli
            crc32c
            lizard
            numpy
            packaging
            psutil
            pytest
            pytest-rerunfailures
            pytest-timeout
            pytest-xdist
            pyopenssl
            pyyaml
            radon
            requests
            requests-aws4auth
            xattr
            zstandard
          ]));
        in {
          default = pkgs.mkShell {
            passthru.testPython = python;
            inputsFrom = [ self.packages.${system}.brix-cache-client ];
            packages = with pkgs; [
              attr
              bubblewrap
              brotli
              cargo
              coreutils
              createrepo_c
              dpkg
              fail2ban
              (lib.getBin fuse3)
              fuse-overlayfs
              gfal2-util
              git
              haproxy
              iproute2
              kubernetes-helm
              libxslt
              lz4
              minio-client
              nftables
              nghttp2
              openssh
              pcre2
              podman
              procps
              python
              rpm
              ripgrep
              rsync
              rustc
              shadow
              slirp4netns
              socat
              squid
              strace
              unzip
              valgrind
              varnish
              xrootd
              xfsprogs
            ];
            TEST_NGINX_BIN = "${self.packages.${system}.nginx-brix-cache}/bin/nginx";
            BRIX_NIXPKGS_SOURCE = "${nixpkgs}";
            NGX_SRC = "${self.packages.${system}.nginx-brix-test-sdk}";
            TEST_NGINX_SRC = "${self.packages.${system}.nginx-brix-test-sdk}";
            BRIX_NGINX_BUILD_DIR = "${self.packages.${system}.nginx-brix-test-sdk}/objs";
            BRIX_XROOTD_LIBDIR = "${pkgs.lib.getLib pkgs.xrootd}/lib";
            BRIX_LZ4_CFLAGS = "-I${pkgs.lz4.dev}/include";
            BRIX_LZ4_LIBS = "-L${pkgs.lib.getLib pkgs.lz4}/lib -Wl,-rpath,${pkgs.lib.getLib pkgs.lz4}/lib -l:liblz4.so.1";
            # inputsFrom contributes build-time Python tools whose wrappers may
            # otherwise precede this composed interpreter. Keep pytest and every
            # child Python on the environment that owns the declared modules.
            shellHook = ''
              export PATH="${python}/bin:${pkgs.iproute2}/sbin:$PATH"
            '';
          };
        });

      nixosModules.default = { pkgs, ... }: {
        services.nginx.package =
          self.packages.${pkgs.stdenv.hostPlatform.system}.nginx-brix-cache;
      };
    };
}
