# home-manager module for secrit (PLAN section 10.1).
#
#   programs.secrit = {
#     enable = true;
#     settings = {
#       default_store = "main";
#       stores.main = {
#         backend = "sops";
#         file = "/etc/nixos/secrets/secrit.yaml";
#       };
#     };
#   };
#
# The module installs the package and writes ~/.config/secrit/config.toml.
# It does not make an age key, a .sops.yaml or the store file; the README,
# section "Set up a store", gives those steps.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.secrit;
  toml = pkgs.formats.toml { };
in
{
  options.programs.secrit = {
    enable = lib.mkEnableOption "secrit, which stores secrets in a sops + age file";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The secrit package. The flake module sets it to the flake's package.";
    };

    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      example = lib.literalExpression ''
        {
          default_store = "main";
          stores.main = {
            backend = "sops";
            file = "/etc/nixos/secrets/secrit.yaml";
            age_key_file = "~/.config/sops/age/keys.txt";
          };
          lock.timeout_secs = 30;
        }
      '';
      description = ''
        The contents of {file}`$XDG_CONFIG_HOME/secrit/config.toml`. The keys
        are the ones in the README, section "Configure". secrit refuses an
        unknown key. When the set is empty, the module writes no file.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];
    xdg.configFile."secrit/config.toml" = lib.mkIf (cfg.settings != { }) {
      source = toml.generate "secrit-config.toml" cfg.settings;
    };
  };
}
