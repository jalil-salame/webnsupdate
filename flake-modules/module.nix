let
  module =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    let
      cfg = config.services.webnsupdate;
      inherit (lib)
        mkOption
        mkEnableOption
        mkPackageOption
        types
        ;
      format = pkgs.formats.json { };
    in
    {
      # imports = [
      #   (lib.mkRenamedOptionModule
      #     [ "services" "webnsupdate" "passwordFile" ]
      #     [ "services" "webnsupdate" "settings" "password_file" ]
      #   )
      #   (lib.mkRenamedOptionModule
      #     [ "services" "webnsupdate" "keyFile" ]
      #     [ "services" "webnsupdate" "settings" "key_file" ]
      #   )
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "allowedIPVersion" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.ip_type' which defaults to Both.
      #   '')
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "bindIp" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.address' which defaults to 127.0.0.1:5353.
      #   '')
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "bindPort" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.address' which defaults to 127.0.0.1:5353.
      #   '')
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "records" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.records' which defaults to [].
      #   '')
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "recordsFile" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.records' which defaults to [].
      #   '')
      #   (lib.mkRemovedOptionModule [ "services" "webnsupdate" "ttl" ] ''
      #     This option was replaced with 'services.webnsupdate.settings.ttl' which defaults to 600s.
      #   '')
      # ];

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
            settings = mkOption {
              description = "The webnsupdate JSON configuration";
              default = { };
              type = types.submodule {
                freeformType = format.type;
                options = {
                  address = mkOption {
                    description = ''
                      IP address and port to bind to.

                      Setting it to anything other than localhost is very
                      insecure as `webnsupdate` only supports plain HTTP and
                      should always be behind a reverse proxy.
                    '';
                    type = types.str;
                    default = "127.0.0.1:5353";
                    example = "[::1]:5353";
                  };
                  ip_type = mkOption {
                    description = ''The allowed IP versions to accept updates from.'';
                    type = types.enum [
                      "Both"
                      "Ipv4Only"
                      "Ipv6Only"
                    ];
                    default = "Both";
                    example = "Ipv4Only";
                  };
                  password_file = mkOption {
                    description = ''
                      The file where the password is stored.

                      This file can be created by running `webnsupdate mkpasswd $USERNAME $PASSWORD`.
                    '';
                    type = types.path;
                    example = "/secrets/webnsupdate.pass";
                  };
                  key_file = mkOption {
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
                    default = {
                      secs = 600;
                    };
                    example = {
                      secs = 600;
                      nanos = 50000;
                    };
                    type = types.submodule {
                      options = {
                        secs = mkOption {
                          description = "The TTL (in seconds) that should be set on the zone records created by `nsupdate`.";
                          example = 3600;
                        };
                        nanos = mkOption {
                          description = "The TTL (in nanoseconds) that should be set on the zone records created by `nsupdate`.";
                          default = 0;
                          example = 50000;
                        };
                      };
                    };
                  };
                  records = mkOption {
                    description = ''
                      The fqdn of records that should be updated.

                      Empty lines will be ignored, but whitespace will not be.
                    '';
                    type = types.listOf types.str;
                    default = [ ];
                    example = [
                      "example.com."
                      "example.org."
                      "ci.example.org."
                    ];
                  };
                };
              };
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
    };
in
{
  flake.nixosModules = {
    default = module;
    webnsupdate = module;
  };
}
