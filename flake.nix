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
            name = "complexipy-8.3.0-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl";
            url = "https://files.pythonhosted.org/packages/81/1c/4034329a7b5b48f85f9b108c451c036bbaa39a5ebf1045ebe22541609057/complexipy-8.3.0-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl";
            sha256 = "3fd160d7c9a4a265ec843831a824515c3366ca4e3a4761c2b90fb57c08be01d5";
          } else {
            name = "complexipy-8.3.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
            url = "https://files.pythonhosted.org/packages/3a/1d/c4a04505ade6e0c768b8725bf52ca90b7be0cf7858b528dcbd3c8028bdda/complexipy-8.3.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
            sha256 = "e0faf8e2ddf619a1b36ec19f3d0be0dba7c38e88060c81f39485fcf72ea3ccb7";
          };
          complexipy = pkgs.python3Packages.buildPythonPackage {
            pname = "complexipy";
            version = "8.3.0";
            format = "wheel";
            src = pkgs.fetchurl complexipyWheel;
            dependencies = with pkgs.python3Packages; [ tomli typer ];
            pythonImportsCheck = [ "complexipy" ];
          };
          # The pinned nixpkgs binding is 5.x, below requirements.txt's 6.x
          # interoperability baseline. Consume released binary wheels only;
          # the stock reference server remains the nixpkgs package below.
          xrootdWheel = if system == "aarch64-linux" then {
            name = "xrootd-6.2.1-cp313-cp313-manylinux_2_28_aarch64.whl";
            url = "https://files.pythonhosted.org/packages/aa/f7/25fe0ee6eb35a0caa5d54dc6828a2ded9350e150d7f9ed71d7afe2d50114/xrootd-6.2.1-cp313-cp313-manylinux_2_28_aarch64.whl";
            sha256 = "28784fcef88b11ede359772a589bbe302d3f9bfa208d0c8ee978ff2491ce752d";
          } else {
            name = "xrootd-6.2.1-cp313-cp313-manylinux_2_28_x86_64.whl";
            url = "https://files.pythonhosted.org/packages/ed/8c/6165e9e1ef67d2f4fe7dbda67a6b114ebc5e401bfac8b7860bd330728cae/xrootd-6.2.1-cp313-cp313-manylinux_2_28_x86_64.whl";
            sha256 = "2144c7d42f9dbda29e814c09156d90dc3a82b70a9c36cf0e3be16e58ae198e25";
          };
          xrootdBindings = pkgs.python3Packages.buildPythonPackage {
            pname = "xrootd";
            version = "6.2.1";
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
