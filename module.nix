{ lib, pkgs, ... }@args:
let
  cfg = args.config.services.webnsupdate;
  inherit (lib)
    mkOption
    mkEnableOption
    mkPackageOption
    types
    ;
  format = pkgs.formats.json { };

  settings = mkOption {
    description = "The webnsupdate JSON configuration";
    inherit (format) type;
    default = {
      server.address = "127.0.0.1:5353";
    };
    example = {
      server = {
        address = "[::1]:5353";
        key_file = "/secrets/webnsupdate.key";
      };
      password.file = "/secrets/webnsupdate.pass";

      records = {
        "home.mydomain.org." = {
          router_domain = "home-router.mydomain.org.";
          client_id = "::1234";
        };
        "work.mydomain.org." = {
          router_domain = "work-router.mydomain.org.";
          client_id = "::5678";
        };
      };
    };
  };
in
{
  options.services.webnsupdate = mkOption {
    description = "An HTTP server for nsupdate.";
    default = { };
    type = types.submodule {
      options = {
        enable = mkEnableOption "webnsupdate";
        extraArgs = mkOption {
          description = ''
            Extra arguments to be passed to the webnsupdate server command.
          '';
          type = types.listOf types.str;
          default = [ ];
          example = [ "--ip-source" ];
        };
        package = mkPackageOption pkgs "webnsupdate" { };
        inherit settings;
        user = mkOption {
          description = "The user to run as.";
          type = types.str;
          default = "named";
        };
        group = mkOption {
          description = "The group to run as.";
          type = types.str;
          default = "named";
        };
      };
    };
  };

  config =
    let
      configFile = format.generate "webnsupdate.json" cfg.settings;
      args = lib.strings.escapeShellArgs ([ "--config=${configFile}" ] ++ cfg.extraArgs);
      cmd = "${lib.getExe cfg.package} ${args}";
    in
    lib.mkIf cfg.enable {
      # FIXME: re-enable once I stop using the patched version of bind
      # warnings =
      #   lib.optional (!config.services.bind.enable) "`webnsupdate` is expected to be used alongside `bind`. This is an unsupported configuration.";

      systemd.services.webnsupdate = {
        description = "Web interface for nsupdate.";
        wantedBy = [ "multi-user.target" ];
        after = [
          "network.target"
          "bind.service"
        ];
        preStart = "${lib.getExe cfg.package} verify ${configFile}";
        path = [ pkgs.dig ];
        startLimitIntervalSec = 60;
        environment.DATA_DIR = "%S/webnsupdate";
        serviceConfig = {
          ExecStart = [ cmd ];
          Type = "exec";
          Restart = "on-failure";
          RestartSec = "10s";
          # User and group
          User = cfg.user;
          Group = cfg.group;
          # Runtime directory and mode
          RuntimeDirectory = "webnsupdate";
          RuntimeDirectoryMode = "0750";
          # Cache directory and mode
          CacheDirectory = "webnsupdate";
          CacheDirectoryMode = "0750";
          # Logs directory and mode
          LogsDirectory = "webnsupdate";
          LogsDirectoryMode = "0750";
          # State directory and mode
          StateDirectory = "webnsupdate";
          StateDirectoryMode = "0750";
          # New file permissions
          UMask = "0027";
          # Security
          NoNewPrivileges = true;
          ProtectHome = true;
        };
      };
    };
}
