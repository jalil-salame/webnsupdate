{ self, ... }:
{
  perSystem =
    { pkgs, self', ... }:
    {
      checks =
        let
          testDomain = "webnstest.example";
          lastIPPath = "/var/lib/webnsupdate/last-ip.json";

          zoneFile = pkgs.writeText "${testDomain}.zoneinfo" ''
            $TTL 60 ; 1 minute
            $ORIGIN ${testDomain}.
            @         IN SOA    ns1.${testDomain}. admin.${testDomain}. (
                          1            ; serial
                          6h           ; refresh
                          1h           ; retry
                          1w           ; expire
                          1d)          ; negative caching TTL

                      IN  NS    ns1.${testDomain}.
            @         IN  A     127.0.0.1
            ns1       IN  A     127.0.0.1
            nsupdate  IN  A     127.0.0.1
            @         IN  AAAA  ::1
            ns1       IN  AAAA  ::1
            nsupdate  IN  AAAA  ::1
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

          webnsupdate-nginx-machine =
            { lib, config, ... }:
            {
              imports = [
                webnsupdate-ipv4-machine
              ];

              config.services = {
                # Use default IP Source
                webnsupdate.extraArgs = lib.mkForce [ "-vvv" ]; # debug messages

                nginx = {
                  enable = true;
                  recommendedProxySettings = true;

                  virtualHosts.webnsupdate.locations."/".proxyPass =
                    "http://${config.services.webnsupdate.bindIp}:${builtins.toString config.services.webnsupdate.bindPort}";
                };
              };
            };

          webnsupdate-ipv4-only-machine = {
            imports = [ webnsupdate-nginx-machine ];
            config.services.webnsupdate.allowedIPVersion = "ipv4-only";
          };

          webnsupdate-ipv6-only-machine = {
            imports = [ webnsupdate-nginx-machine ];
            config.services.webnsupdate.allowedIPVersion = "ipv6-only";
          };

          testScript = ''
            machine.start(allow_reboot=True)
            machine.wait_for_unit("bind.service")
            machine.wait_for_unit("webnsupdate.service")

            # ensure base DNS records area available
            with subtest("query base DNS records"):
                machine.succeed("dig @127.0.0.1 ${testDomain}          | grep ^${testDomain}")
                machine.succeed("dig @127.0.0.1 ns1.${testDomain}      | grep ^ns1.${testDomain}")
                machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

            # ensure webnsupdate managed records are missing
            with subtest("query webnsupdate DNS records (fail)"):
                machine.fail("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.fail("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.fail("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            with subtest("update webnsupdate DNS records (invalid auth)"):
                machine.fail("curl --fail --silent -u test1:test1 -X GET http://localhost:5353/update")
                machine.fail("cat ${lastIPPath}") # no last-ip set yet

            # ensure webnsupdate managed records are missing
            with subtest("query webnsupdate DNS records (fail)"):
                machine.fail("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.fail("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.fail("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            with subtest("update webnsupdate DNS records (valid auth)"):
                machine.succeed("curl --fail --silent -u test:test -X GET http://localhost:5353/update")
                machine.succeed("cat ${lastIPPath}")

            # ensure webnsupdate managed records are available
            with subtest("query webnsupdate DNS records (succeed)"):
                machine.succeed("dig @127.0.0.1 test1.${testDomain} A test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                machine.succeed("dig @127.0.0.1 test2.${testDomain} A test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                machine.succeed("dig @127.0.0.1 test3.${testDomain} A test3.${testDomain} AAAA | grep ^test3.${testDomain}")

            machine.reboot()
            machine.succeed("cat ${lastIPPath}")
            machine.wait_for_unit("webnsupdate.service")
            machine.succeed("cat ${lastIPPath}")

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
          module-nginx-test = pkgs.testers.runNixOSTest {
            name = "webnsupdate-nginx-module";
            nodes.machine = webnsupdate-nginx-machine;
            testScript = ''
              machine.start(allow_reboot=True)
              machine.wait_for_unit("bind.service")
              machine.wait_for_unit("webnsupdate.service")

              # ensure base DNS records area available
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain}          | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain}      | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate DNS records (invalid auth)"):
                  machine.fail("curl --fail --silent -u test1:test1 -X GET http://127.0.0.1/update")
                  machine.fail("cat ${lastIPPath}") # no last-ip set yet

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv4 DNS records (valid auth)"):
                  machine.succeed("curl --fail --silent -u test:test -X GET http://127.0.0.1/update")
                  machine.succeed("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv4 records are available
              with subtest("query webnsupdate IPv4 DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} A | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} A | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} A | grep ^test3.${testDomain}")

              # ensure webnsupdate managed IPv6 records are missing
              with subtest("query webnsupdate IPv6 DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv6 DNS records (valid auth)"):
                  machine.succeed("curl --fail --silent -u test:test -X GET http://[::1]/update")
                  machine.succeed("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv6 records are missing
              with subtest("query webnsupdate IPv6 DNS records (fail)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              machine.reboot()
              machine.succeed("cat ${lastIPPath}")
              machine.wait_for_unit("webnsupdate.service")
              machine.succeed("cat ${lastIPPath}")

              # ensure base DNS records area available after a reboot
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain} | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain} | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are available after a reboot
              with subtest("query webnsupdate DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")
            '';
          };
          module-ipv4-only-test = pkgs.testers.runNixOSTest {
            name = "webnsupdate-ipv4-only-module";
            nodes.machine = webnsupdate-ipv4-only-machine;
            testScript = ''
              machine.start(allow_reboot=True)
              machine.wait_for_unit("bind.service")
              machine.wait_for_unit("webnsupdate.service")

              # ensure base DNS records area available
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain}          | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain}      | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate DNS records (invalid auth)"):
                  machine.fail("curl --fail --silent -u test1:test1 -X GET http://127.0.0.1/update")
                  machine.fail("cat ${lastIPPath}") # no last-ip set yet

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv6 DNS records (valid auth)"):
                  machine.fail("curl --fail --silent -u test:test -X GET http://[::1]/update")
                  machine.fail("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv6 records are missing
              with subtest("query webnsupdate IPv6 DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv4 DNS records (valid auth)"):
                  machine.succeed("curl --fail --silent -u test:test -X GET http://127.0.0.1/update")
                  machine.succeed("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv4 records are available
              with subtest("query webnsupdate IPv4 DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} A | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} A | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} A | grep ^test3.${testDomain}")

              # ensure webnsupdate managed IPv6 records are missing
              with subtest("query webnsupdate IPv6 DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              machine.reboot()
              machine.succeed("cat ${lastIPPath}")
              machine.wait_for_unit("webnsupdate.service")
              machine.succeed("cat ${lastIPPath}")

              # ensure base DNS records area available after a reboot
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain} | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain} | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are available after a reboot
              with subtest("query webnsupdate DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} A | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} A | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} A | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")
            '';
          };
          module-ipv6-only-test = pkgs.testers.runNixOSTest {
            name = "webnsupdate-ipv6-only-module";
            nodes.machine = webnsupdate-ipv6-only-machine;
            testScript = ''
              machine.start(allow_reboot=True)
              machine.wait_for_unit("bind.service")
              machine.wait_for_unit("webnsupdate.service")

              # ensure base DNS records area available
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain}          | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain}      | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate DNS records (invalid auth)"):
                  machine.fail("curl --fail --silent -u test1:test1 -X GET http://127.0.0.1/update")
                  machine.fail("cat ${lastIPPath}") # no last-ip set yet

              # ensure webnsupdate managed records are missing
              with subtest("query webnsupdate DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A    | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A    | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A    | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv4 DNS records (valid auth)"):
                  machine.fail("curl --fail --silent -u test:test -X GET http://127.0.0.1/update")
                  machine.fail("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv4 records are missing
              with subtest("query webnsupdate IPv4 DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A | grep ^test3.${testDomain}")

              with subtest("update webnsupdate IPv6 DNS records (valid auth)"):
                  machine.succeed("curl --fail --silent -u test:test -X GET http://[::1]/update")
                  machine.succeed("cat ${lastIPPath}")

              # ensure webnsupdate managed IPv6 records are available
              with subtest("query webnsupdate IPv6 DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")

              # ensure webnsupdate managed IPv4 records are missing
              with subtest("query webnsupdate IPv4 DNS records (fail)"):
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A | grep ^test3.${testDomain}")

              machine.reboot()
              machine.succeed("cat ${lastIPPath}")
              machine.wait_for_unit("webnsupdate.service")
              machine.succeed("cat ${lastIPPath}")

              # ensure base DNS records area available after a reboot
              with subtest("query base DNS records"):
                  machine.succeed("dig @127.0.0.1 ${testDomain} | grep ^${testDomain}")
                  machine.succeed("dig @127.0.0.1 ns1.${testDomain} | grep ^ns1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 nsupdate.${testDomain} | grep ^nsupdate.${testDomain}")

              # ensure webnsupdate managed records are available after a reboot
              with subtest("query webnsupdate DNS records (succeed)"):
                  machine.succeed("dig @127.0.0.1 test1.${testDomain} AAAA | grep ^test1.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test2.${testDomain} AAAA | grep ^test2.${testDomain}")
                  machine.succeed("dig @127.0.0.1 test3.${testDomain} AAAA | grep ^test3.${testDomain}")
                  machine.fail("dig @127.0.0.1 test1.${testDomain} A       | grep ^test1.${testDomain}")
                  machine.fail("dig @127.0.0.1 test2.${testDomain} A       | grep ^test2.${testDomain}")
                  machine.fail("dig @127.0.0.1 test3.${testDomain} A       | grep ^test3.${testDomain}")
            '';
          };
        };
    };
}
