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
      # x86_64-linux only: CI builds no other system (CI-1). Add aarch64-linux
      # back together with an arm runner job.
      systems = [ "x86_64-linux" ];
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
          };
          # Baked into the binary with option_env! (PLAN 10.2): installing
          # secrit through Nix installs the exact sops and age-keygen it runs.
          # Kept out of buildDepsOnly, so a sops or age bump does not rebuild
          # the dependencies (NIX-2).
          bakedEnv = {
            SECRIT_SOPS_BIN = sopsBin;
            SECRIT_AGE_KEYGEN_BIN = ageKeygenBin;
          };
          # The integration tests run the real tools against a temp dir only.
          testEnv = {
            SECRIT_TEST_SOPS = sopsBin;
            SECRIT_TEST_AGE_KEYGEN = ageKeygenBin;
            SECRIT_TEST_SSH_KEYGEN = "${pkgs.openssh}/bin/ssh-keygen";
            SECRIT_TEST_GIT = "${pkgs.git}/bin/git";
          };
          # script, setsid and kill (util-linux), ssh-keygen, stty, cmp and git.
          testTools = [
            pkgs.util-linux
            pkgs.openssh
            pkgs.coreutils
            pkgs.diffutils
            pkgs.git
          ];
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          secrit = craneLib.buildPackage (
            commonArgs
            // bakedEnv
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
            bakedEnv
            testEnv
            testTools
            cargoArtifacts
            secrit
            ;
        };

      # The home-manager module, with the package built from the consumer's
      # nixpkgs as the default.
      hmModule =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/hm-module.nix ];
          programs.secrit.package = lib.mkDefault (parts pkgs).secrit;
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
          meta.description = "Store, list, remove and show secrets in a sops + age file";
        };
      });

      # Builds secrit against the consumer's nixpkgs, sops and age (NIX-2).
      overlays.default = final: _prev: {
        secrit = (parts final).secrit;
      };

      homeManagerModules.default = hmModule;

      checks = forAllSystems (
        pkgs:
        let
          p = parts pkgs;
          # Evaluate the module with stubs for the two home-manager options it
          # sets, so the check needs no home-manager input.
          hmEval = pkgs.lib.evalModules {
            modules = [
              hmModule
              (
                { lib, ... }:
                {
                  options.home.packages = lib.mkOption {
                    type = lib.types.listOf lib.types.package;
                    default = [ ];
                  };
                  options.xdg.configFile = lib.mkOption {
                    type = lib.types.attrsOf (
                      lib.types.submodule { options.source = lib.mkOption { type = lib.types.path; }; }
                    );
                    default = { };
                  };
                  config = {
                    _module.args.pkgs = pkgs;
                    programs.secrit = {
                      enable = true;
                      settings = {
                        default_store = "main";
                        stores.main = {
                          backend = "sops";
                          file = "~/store/secrit.yaml";
                        };
                        lock.timeout_secs = 5;
                      };
                    };
                  };
                }
              )
            ];
          };
          hmPackage = builtins.head hmEval.config.home.packages;
          hmConfig = hmEval.config.xdg.configFile."secrit/config.toml".source;
        in
        {
          package = p.secrit;

          fmt = p.craneLib.cargoFmt { inherit (p) src; };

          clippy = p.craneLib.cargoClippy (
            p.commonArgs
            // p.bakedEnv
            // {
              inherit (p) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
            }
          );

          nextest = p.craneLib.cargoNextest (
            p.commonArgs
            // p.bakedEnv
            // p.testEnv
            // {
              inherit (p) cargoArtifacts;
              cargoNextestExtraArgs = "--all-features";
              nativeCheckInputs = p.testTools;
            }
          );

          # Advisories need the network; CI runs `cargo deny check` in full.
          deny = p.craneLib.cargoDeny {
            inherit (p) src;
            cargoDenyChecks = "bans licenses sources";
          };

          # PF-2: the module installs the package and writes a config that
          # secrit accepts. secrit parses the generated file (unknown keys are
          # an error) and stops at the missing store file.
          hm-module = pkgs.runCommand "secrit-hm-module-check" { } ''
            export HOME=$TMPDIR/home
            mkdir -m 700 $HOME $HOME/store
            cp ${hmConfig} $HOME/cfg.toml
            chmod 600 $HOME/cfg.toml
            rc=0
            ${hmPackage}/bin/secrit --config $HOME/cfg.toml ls > $HOME/log 2>&1 || rc=$?
            cat $HOME/log
            test "$rc" = 1
            grep -q 'create it first' $HOME/log
            touch $out
          '';
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
              ]
              ++ p.testTools;
            }
          );
        }
      );
    };
}
