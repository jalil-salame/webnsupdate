{ self, ... }:
{
  perSystem =
    { pkgs, self', ... }:
    {
      checks =
        let
          testDomain = "webnstest.example";

          zoneFile = pkgs.writeText "${testDomain}.zoneinfo" ''
            $ORIGIN .
            $TTL 60 ; 1 minute
            ${testDomain} IN SOA ns1.${testDomain}. admin.${testDomain}. (
                    1            ; serial
                    21600        ; refresh (6 hours)
                    3600         ; retry   (1 hour)
                    604800       ; expire  (1 week)
                    86400)       ; negative caching TTL (1 day)

                                      IN  NS    ns1.${testDomain}.
            $ORIGIN ${testDomain}.
            ${testDomain}.            IN  A     127.0.0.1
            ${testDomain}.            IN  AAAA  ::1
            ns1                       IN  A     127.0.0.1
            ns1                       IN  AAAA  ::1
            nsupdate                  IN  A     127.0.0.1
            nsupdate                  IN  AAAA  ::1
          '';

          bindDynamicZone =
            { config, ... }:
            let
              bindCfg = config.services.bind;
              bindData = bindCfg.directory;
              dynamicZonesDir = "${bindData}/zones";
            in
            {
              services.bind.zones.${testDomain} = {
                master = true;
                file = "${dynamicZonesDir}/${testDomain}";
                extraConfig = ''
                  allow-update { key rndc-key; };
                '';
              };

              systemd.services.bind.preStart = ''
                # shellcheck disable=SC2211,SC1127
                rm -f ${dynamicZonesDir}/* # reset dynamic zones

                # create a dynamic zones dir
                mkdir -m 0755 -p ${dynamicZonesDir}
                # copy dynamic zone's file to the dynamic zones dir
                cp ${zoneFile} ${dynamicZonesDir}/${testDomain}
              '';
            };

          webnsupdate-ipv4-machine =
            { lib, ... }:
            {
              imports = [
                bindDynamicZone
                self.nixosModules.webnsupdate
              ];

              config = {
                environment.systemPackages = [
                  pkgs.dig
                  pkgs.curl
                ];

                services = {
                  bind.enable = true;

                  webnsupdate = {
                    enable = true;
                    bindIp = lib.mkDefault "127.0.0.1";
                    keyFile = "/etc/bind/rndc.key";
                    # test:test (user:password)
                    passwordFile = pkgs.writeText "webnsupdate.pass" "FQoNmuU1BKfg8qsU96F6bK5ykp2b0SLe3ZpB3nbtfZA";
                    package = self'.packages.webnsupdate;
                    extraArgs = [
                      "-vvv" # debug messages
                      "--ip-source=ConnectInfo"
                    ];
                    records = ''
                      test1.${testDomain}.
                      test2.${testDomain}.
                      test3.${testDomain}.
                    '';
                  };
                };
              };
            };

          webnsupdate-ipv6-machine = {
            imports = [
              webnsupdate-ipv4-machine
            ];

            config.services.webnsupdate.bindIp = "::1";
          };

          testScript = ''
            machine.start(allow_reboot=True)
            machine.wait_for_unit("bind.service")
            machine.wait_for_unit("webnsupdate.service")

            # ensure base DNS records area available
            with subtest("query base DNS records"):
                machine.succeed("dig @127.0.0.1 ${testDomain} | grep ^${testDomain}")
                machine.succeed("dig @127.0.0.1 ns1.${testDomain} | grep ^ns1.${testDomain}")
                machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

            # ensure webnsupdate managed records are missing
            with subtest("query webnsupdate DNS records (fail)"):
                machine.fail("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.fail("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.fail("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            with subtest("update webnsupdate DNS records (invalid auth)"):
                machine.fail("curl --fail --silent -u test1:test1 -X GET http://localhost:5353/update")
                machine.fail("cat /var/lib/webnsupdate/last-ip") # no last-ip set yet

            # ensure webnsupdate managed records are missing
            with subtest("query webnsupdate DNS records (fail)"):
                machine.fail("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.fail("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.fail("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            with subtest("update webnsupdate DNS records (valid auth)"):
                machine.succeed("curl --fail --silent -u test:test -X GET http://localhost:5353/update")
                machine.succeed("cat /var/lib/webnsupdate/last-ip")

            # ensure webnsupdate managed records are available
            with subtest("query webnsupdate DNS records (succeed)"):
                machine.succeed("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.succeed("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.succeed("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            machine.reboot()
            machine.succeed("cat /var/lib/webnsupdate/last-ip")
            machine.wait_for_unit("webnsupdate.service")
            machine.succeed("cat /var/lib/webnsupdate/last-ip")

            # ensure base DNS records area available after a reboot
            with subtest("query base DNS records"):
                machine.succeed("dig @127.0.0.1 ${testDomain} | grep ^${testDomain}")
                machine.succeed("dig @127.0.0.1 ns1.${testDomain} | grep ^ns1.${testDomain}")
                machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

            # ensure webnsupdate managed records are available after a reboot
            with subtest("query webnsupdate DNS records (succeed)"):
                machine.succeed("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.succeed("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.succeed("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")
          '';
        in
        {
          module-ipv4-test = pkgs.testers.runNixOSTest {
            name = "webnsupdate-ipv4-module";
            nodes.machine = webnsupdate-ipv4-machine;
            inherit testScript;
          };
          module-ipv6-test = pkgs.testers.runNixOSTest {
            name = "webnsupdate-ipv6-module";
            nodes.machine = webnsupdate-ipv6-machine;
            inherit testScript;
          };
        };
    };
}
