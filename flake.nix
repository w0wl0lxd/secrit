{
  description = "secrit: store secrets in a sops + age file, with no value on the command line";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane/v0.24.0";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      parts =
        pkgs:
        let
          craneLib = crane.mkLib pkgs;
          src = craneLib.cleanCargoSource ./.;
          sopsBin = "${pkgs.sops}/bin/sops";
          ageKeygenBin = "${pkgs.age}/bin/age-keygen";
          commonArgs = {
            inherit src;
            strictDeps = true;
            # Baked into the binary with option_env! (PLAN 10.2): installing
            # secrit through Nix installs the exact sops and age-keygen it runs.
            SECRIT_SOPS_BIN = sopsBin;
            SECRIT_AGE_KEYGEN_BIN = ageKeygenBin;
          };
          # The integration tests run the real tools against a temp dir only.
          testEnv = {
            SECRIT_TEST_SOPS = sopsBin;
            SECRIT_TEST_AGE_KEYGEN = ageKeygenBin;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          secrit = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              # The test suite runs in checks.nextest.
              doCheck = false;
              nativeBuildInputs = [ pkgs.installShellFiles ];
              postInstall = ''
                installShellCompletion --cmd secrit \
                  --bash <($out/bin/secrit completions bash) \
                  --fish <($out/bin/secrit completions fish) \
                  --zsh <($out/bin/secrit completions zsh)
              '';
              meta = {
                description = "Store secrets in a sops + age file, with no value on the command line";
                license = with pkgs.lib.licenses; [
                  mit
                  asl20
                ];
                mainProgram = "secrit";
                platforms = pkgs.lib.platforms.linux;
              };
            }
          );
        in
        {
          inherit
            craneLib
            src
            commonArgs
            testEnv
            cargoArtifacts
            secrit
            ;
        };
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          p = parts pkgs;
        in
        {
          default = p.secrit;
          secrit = p.secrit;
        }
      );

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/secrit";
          meta.description = "secrit";
        };
      });

      overlays.default = final: _prev: {
        secrit = self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      checks = forAllSystems (
        pkgs:
        let
          p = parts pkgs;
        in
        {
          package = p.secrit;

          fmt = p.craneLib.cargoFmt { inherit (p) src; };

          clippy = p.craneLib.cargoClippy (
            p.commonArgs
            // {
              inherit (p) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
            }
          );

          nextest = p.craneLib.cargoNextest (
            p.commonArgs
            // p.testEnv
            // {
              inherit (p) cargoArtifacts;
              cargoNextestExtraArgs = "--all-features";
              nativeCheckInputs = [ pkgs.util-linux ];
            }
          );

          # Advisories need the network; CI runs `cargo deny check` in full.
          deny = p.craneLib.cargoDeny {
            inherit (p) src;
            cargoDenyChecks = "bans licenses sources";
          };
        }
      );

      devShells = forAllSystems (
        pkgs:
        let
          p = parts pkgs;
        in
        {
          default = p.craneLib.devShell (
            p.testEnv
            // {
              checks = self.checks.${pkgs.stdenv.hostPlatform.system};
              packages = [
                pkgs.sops
                pkgs.age
                pkgs.cargo-nextest
                pkgs.cargo-deny
                pkgs.util-linux
              ];
            }
          );
        }
      );
    };
}
