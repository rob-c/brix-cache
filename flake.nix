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
          python = pkgs.python3.withPackages (ps: [ complexipy ] ++ (with ps; [
            cryptography
            lizard
            packaging
            pytest
            pytest-rerunfailures
            pytest-timeout
            pytest-xdist
            pyyaml
            radon
            requests
            xrootd
          ]));
        in {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.brix-cache-client ];
            packages = with pkgs; [
              bubblewrap
              cargo
              haproxy
              iproute2
              openssh
              pcre2
              procps
              python
              rustc
              shadow
              xrootd
            ];
            TEST_NGINX_BIN = "${self.packages.${system}.nginx-brix-cache}/bin/nginx";
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
              export PATH="${python}/bin:$PATH"
            '';
          };
        });

      nixosModules.default = { pkgs, ... }: {
        services.nginx.package =
          self.packages.${pkgs.stdenv.hostPlatform.system}.nginx-brix-cache;
      };
    };
}
