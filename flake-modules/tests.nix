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

          # "A" for IPv4, "AAAA" for IPv6, "ANY" for any
          testTemplate =
            {
              ipv4 ? false,
              ipv6 ? false,
              nginx ? false,
              exclusive ? false,
            }:
            if exclusive && (ipv4 == ipv6) then
              builtins.throw "exclusive means one of ipv4 or ipv6 must be set, but not both"
            else
              ''
                IPV4: bool = ${if ipv4 then "True" else "False"}
                IPV6: bool = ${if ipv6 then "True" else "False"}
                NGINX: bool = ${if nginx then "True" else "False"}
                EXCLUSIVE: bool = ${if exclusive then "True" else "False"}
                print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")

                CURL: str = "curl --fail --no-progress-meter --show-error"

                machine.start(allow_reboot=True)
                machine.wait_for_unit("bind.service")
                machine.wait_for_unit("webnsupdate.service")

                STATIC_DOMAINS: list[str] = ["${testDomain}", "ns1.${testDomain}", "nsupdate.${testDomain}"]
                DYNAMIC_DOMAINS: list[str] = ["test1.${testDomain}", "test2.${testDomain}", "test3.${testDomain}"]

                def dig_cmd(domain: str, record: str, ip: str | None) -> str:
                    match_ip = "" if ip is None else f"\\s\\+60\\s\\+IN\\s\\+{record}\\s\\+{ip}$"
                    return f"dig @localhost {record} {domain} +noall +answer | grep '^{domain}.{match_ip}'"

                def curl_cmd(domain: str, identity: str, path: str, query: dict[str, str]) -> str:
                    from urllib.parse import urlencode
                    q= f"?{urlencode(query)}" if query else ""
                    return f"{CURL} -u {identity} -X GET 'http://{domain}{"" if NGINX else ":5353"}/{path}{q}'"

                def domain_available(domain: str, record: str, ip: str | None=None):
                    machine.succeed(dig_cmd(domain, record, ip))

                def domain_missing(domain: str, record: str, ip: str | None=None):
                    machine.fail(dig_cmd(domain, record, ip))

                def update_records(domain: str="localhost", /, *, path: str="update", **kwargs):
                    machine.succeed(curl_cmd(domain, "test:test", path, kwargs))
                    machine.succeed("cat ${lastIPPath}")

                def update_records_fail(domain: str="localhost", /, *, identity: str="test:test", path: str="update", **kwargs):
                    machine.fail(curl_cmd(domain, identity, path, kwargs))
                    machine.fail("cat ${lastIPPath}")

                def invalid_update(domain: str="localhost"):
                    update_records_fail(domain, identity="bad_user:test")
                    update_records_fail(domain, identity="test:bad_pass")

                # Tests

                with subtest("static DNS records are available"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    for domain in STATIC_DOMAINS:
                        domain_available(domain, "A", "127.0.0.1") # IPv4
                        domain_available(domain, "AAAA", "::1")    # IPv6

                with subtest("dynamic DNS records are missing"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    for domain in DYNAMIC_DOMAINS:
                        domain_missing(domain, "A")    # IPv4
                        domain_missing(domain, "AAAA") # IPv6

                with subtest("invalid auth fails to update records"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    invalid_update()
                    for domain in DYNAMIC_DOMAINS:
                        domain_missing(domain, "A")    # IPv4
                        domain_missing(domain, "AAAA") # IPv6

                if EXCLUSIVE:
                    with subtest("exclusive IP version fails to update with invalid version"):
                        print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                        if IPV6:
                            update_records_fail("127.0.0.1")
                        if IPV4:
                            update_records_fail("[::1]")

                with subtest("valid auth updates records"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    if IPV4:
                        update_records("127.0.0.1")
                    if IPV6:
                        update_records("[::1]")

                    for domain in DYNAMIC_DOMAINS:
                        if IPV4:
                            domain_available(domain, "A", "127.0.0.1")
                        elif IPV6 and EXCLUSIVE:
                            domain_missing(domain, "A")

                        if IPV6:
                            domain_available(domain, "AAAA", "::1")
                        elif IPV4 and EXCLUSIVE:
                            domain_missing(domain, "AAAA")

                with subtest("valid auth fritzbox compatible updates records"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    if IPV4 and IPV6:
                        update_records("127.0.0.1", domain="test", ipv4="1.2.3.4", ipv6="::1234")
                    elif IPV4:
                        update_records("127.0.0.1", ipv4="1.2.3.4")
                    elif IPV6:
                        update_records("[::1]", ipv6="::1234")

                    for domain in DYNAMIC_DOMAINS:
                        if IPV4:
                            domain_available(domain, "A", "1.2.3.4")
                        elif IPV6 and EXCLUSIVE:
                            domain_missing(domain, "A")

                        if IPV6:
                            domain_available(domain, "AAAA", "::1234")
                        elif IPV4 and EXCLUSIVE:
                            domain_missing(domain, "AAAA")

                with subtest("valid auth replaces records"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    if IPV4:
                        update_records("127.0.0.1")
                    if IPV6:
                        update_records("[::1]")

                    for domain in DYNAMIC_DOMAINS:
                        if IPV4:
                            domain_available(domain, "A", "127.0.0.1")
                        elif IPV6 and EXCLUSIVE:
                            domain_missing(domain, "A")

                        if IPV6:
                            domain_available(domain, "AAAA", "::1")
                        elif IPV4 and EXCLUSIVE:
                            domain_missing(domain, "AAAA")

                machine.reboot()
                machine.succeed("cat ${lastIPPath}")
                machine.wait_for_unit("webnsupdate.service")
                machine.succeed("cat ${lastIPPath}")

                with subtest("static DNS records are available after reboot"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    for domain in STATIC_DOMAINS:
                        domain_available(domain, "A", "127.0.0.1") # IPv4
                        domain_available(domain, "AAAA", "::1")    # IPv6

                with subtest("dynamic DNS records are available after reboot"):
                    print(f"{IPV4=} {IPV6=} {EXCLUSIVE=}")
                    for domain in DYNAMIC_DOMAINS:
                        if IPV4:
                            domain_available(domain, "A", "127.0.0.1")
                        elif IPV6 and EXCLUSIVE:
                            domain_missing(domain, "A")

                        if IPV6:
                            domain_available(domain, "AAAA", "::1")
                        elif IPV4 and EXCLUSIVE:
                            domain_missing(domain, "AAAA")
              '';
        in
        {
          module-ipv4-test = pkgs.testers.nixosTest {
            name = "webnsupdate-ipv4-module";
            nodes.machine = webnsupdate-ipv4-machine;
            testScript = testTemplate { ipv4 = true; };
          };
          module-ipv6-test = pkgs.testers.nixosTest {
            name = "webnsupdate-ipv6-module";
            nodes.machine = webnsupdate-ipv6-machine;
            testScript = testTemplate { ipv6 = true; };
          };
          module-nginx-test = pkgs.testers.nixosTest {
            name = "webnsupdate-nginx-module";
            nodes.machine = webnsupdate-nginx-machine;
            testScript = testTemplate {
              ipv4 = true;
              ipv6 = true;
              nginx = true;
            };
          };
          module-ipv4-only-test = pkgs.testers.nixosTest {
            name = "webnsupdate-ipv4-only-module";
            nodes.machine = webnsupdate-ipv4-only-machine;
            testScript = testTemplate {
              ipv4 = true;
              nginx = true;
              exclusive = true;
            };
          };
          module-ipv6-only-test = pkgs.testers.nixosTest {
            name = "webnsupdate-ipv6-only-module";
            nodes.machine = webnsupdate-ipv6-only-machine;
            testScript = testTemplate {
              ipv6 = true;
              nginx = true;
              exclusive = true;
            };
          };
        };
    };
}
