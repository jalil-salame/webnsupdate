{
  lib,
  pkgs,
  config,
  ...
}: let
  cfg = config.services.webnsupdate;
  inherit (lib) mkOption mkEnableOption types;
in {
  options.services.webnsupdate = mkOption {
    description = "An HTTP server for nsupdate.";
    default = {};
    type = types.submodule {
      options = {
        enable = mkEnableOption "webnsupdate";
        bindIp = mkOption {
          description = ''
            IP address to bind to.

            Setting it to anything other than localhost is very insecure as
            `webnsupdate` only supports plain HTTP and should always be behind a
            reverse proxy.
          '';
          type = types.str;
          default = "localhost";
          example = "0.0.0.0";
        };
        bindPort = mkOption {
          description = "Port to bind to.";
          type = types.port;
          default = 5353;
        };
        passwordFile = mkOption {
          description = ''
            The file where the password is stored.

            This file can be created by running `webnsupdate mkpasswd $USERNAME $PASSWORD`.
          '';
          type = types.path;
          example = "/secrets/webnsupdate.pass";
        };
        keyFile = mkOption {
          description = ''
            The TSIG key that `nsupdate` should use.

            This file will be passed to `nsupdate` through the `-k` option, so look
            at `man 8 nsupdate` for information on the key's format.
          '';
          type = types.path;
          example = "/secrets/webnsupdate.key";
        };
        ttl = mkOption {
          description = "The TTL that should be set on the zone records created by `nsupdate`.";
          type = types.ints.positive;
          default = 60;
          example = 3600;
        };
        records = mkOption {
          description = ''
            The fqdn of records that should be updated.

            Empty lines will be ignored, but whitespace will not be.
          '';
          type = types.nullOr types.lines;
          default = null;
          example = ''
            example.com.

            example.org.
            ci.example.org.
          '';
        };
        recordsFile = mkOption {
          description = ''
            The fqdn of records that should be updated.

            Empty lines will be ignored, but whitespace will not be.
          '';
          type = types.nullOr types.path;
          default = null;
          example = "/secrets/webnsupdate.records";
        };
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

  config = let
    recordsFile =
      if cfg.recordsFile != null
      then cfg.recordsFile
      else pkgs.writeText "webnsrecords" cfg.records;
    cmd = lib.concatStringsSep " " ([lib.getExe pkgs.websnupdate]
      ++ lib.strings.escapeShellArgs [
        "--records"
        recordsFile
        "--key-file"
        cfg.keyFile
        "--password-file"
        cfg.passwordFile
        "--address"
        cfg.bindIp
        "--port"
        (builtins.toString cfg.bindPort)
        "--ttl"
        (builtins.toString cfg.ttl)
      ]);
  in
    lib.mkIf cfg.enable {
      warnings = [
        (lib.optional (!config.services.bind.enable)
          "`webnsupdate` is expected to be used alongside `bind`. This is an unsopported configuration.")
      ];
      assertions = [
        {
          assertion = (cfg.records != null || cfg.recordsFile != null) && !(cfg.records != null && cfg.recordsFile != null);
          message = "Exactly one of `services.webnsupdate.records` and `services.webnsupdate.recordsFile` must be set.";
        }
      ];

      systemd.services.webnsupdate = {
        description = "Web interface for nsupdate.";
        wantedBy = ["multi-user.target"];
        after = ["network.target" "bind.service"];
        preStart = "${cmd} verify";
        startLimitIntervalSec = 60;
        serviceConfig = {
          ExecStart = cmd;
          Restart = "always";
          RestartSec = "10s";
          # User and group
          User = cfg.user;
          Group = cfg.group;
          # Runtime directory and mode
          RuntimeDirectory = "websnupdate";
          RuntimeDirectoryMode = "0750";
          # Cache directory and mode
          CacheDirectory = "webnsupdate";
          CacheDirectoryMode = "0750";
          # Logs directory and mode
          LogsDirectory = "webnsupdate";
          LogsDirectoryMode = "0750";
          # New file permissions
          UMask = "0027";
          # Security
          NoNewPrivileges = true;
        };
      };
    };
}
