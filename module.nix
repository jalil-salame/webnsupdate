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
    default = { };
    type = types.submodule {
      freeformType = format.type;
      options = {
        server = {
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
          key_file = mkOption {
            description = ''
              The TSIG key that `nsupdate` should use.

              This file will be passed to `nsupdate` through the `-k` option, so look
              at `man 8 nsupdate` for information on the key's format.
            '';
            type = types.path;
            example = "/secrets/webnsupdate.key";
          };
        };

        password.file = mkOption {
          description = ''
            The file where the password is stored.

            This file can be created by running `webnsupdate mkpasswd $USERNAME $PASSWORD`.
          '';
          type = types.path;
          example = "/secrets/webnsupdate.pass";
        };

        records = mkOption {
          description = ''
            The records that should be updated.

            Ideally you should do one record per dynamic location, e.g:

            ```nix
            {
              records = {
                "home.mydomain.org." = {
                  router_domain = "home-router.mydomain.org.";
                };
                "work.mydomain.org." = {
                  router_domain = "work-router.mydomain.org.";
                };
              };
            }
            ```

            This will keep `A` and `AAAA` records for `home.mydomain.org` and
            `work.mydomain.org`, and `AAAA` records for
            `home-router.mydomain.org` and `work-router.mydomain.org`.

            If you want to have more subdomain names use the same record, use
            `CNAME` records pointing to the domains. For example:

            ```zone
            ; Home Services
            home-assistant.mydomain.org. IN CNAME home.mydomain.org.
            jellyfin.mydomain.org.       IN CNAME home.mydomain.org.

            ; Work Services
            forgejo.mydomain.org.        IN CNAME work.mydomain.org.
            ```
          '';
          default = { };
          example = {
            "home.mydomain.org." = {
              router_domain = "home-router.mydomain.org.";
            };
            "work.mydomain.org." = {
              router_domain = "work-router.mydomain.org.";
            };
          };
          type = types.attrsOf (
            types.submodule {
              options = {
                ttl = mkOption {
                  description = "The TTL that should be set on the zone records created by `nsupdate`.";
                  default = "10m";
                  example = "60s";
                  type = types.str;
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
              };
            }
          );
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
