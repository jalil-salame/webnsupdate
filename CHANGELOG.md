# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.4.4](https://git.salame.cl/jalil/webnsupdate/compare/v0.4.3...v0.4.4) - 2026-02-11


### <!-- 1 -->🐛 Bug Fixes

- *(changelog)* regenerate with new configuration
- *(changelog)* add links to tag comparisons

### <!-- 3 -->📚 Documentation

- *(README)* link to Fritz!BOX's docs on DynDNS

## [0.4.3](https://git.salame.cl/jalil/webnsupdate/compare/v0.4.2...v0.4.3) - 2025-11-07


### <!-- 7 -->⚙️ Miscellaneous Tasks

- *(github)* fix release action (hopefully)
- release v0.4.3


## [0.4.2](https://git.salame.cl/jalil/webnsupdate/compare/v0.4.1...v0.4.2) - 2025-10-12


### <!-- 1 -->🐛 Bug Fixes

- allow publishing to crates.io
- remove categories

### <!-- 7 -->⚙️ Miscellaneous Tasks

- add GH Ci to publish to crates.io
- release v0.4.2


## [0.4.1](https://git.salame.cl/jalil/webnsupdate/compare/v0.4.0...v0.4.1) - 2025-10-07


### <!-- 1 -->🐛 Bug Fixes

- *(update)* deduplicate updates
- *(test)* nextest tests were not being run

### <!-- 2 -->🚜 Refactor

- *(deps)* reduce direct dependencies

### <!-- 6 -->🧪 Testing

- collect coverage data

### <!-- 7 -->⚙️ Miscellaneous Tasks

- release v0.4.1


## [0.4.0](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.7...v0.4.0) - 2025-09-18


### <!-- 1 -->🐛 Bug Fixes

- *(package)* don't include extra files

### <!-- 2 -->🚜 Refactor

- *(config)* tidy up the code
- *(config)* [**breaking**] change config format to support multiple domains

### <!-- 6 -->🧪 Testing

- *(router_domain)* ensure router_domain is updated properly

### <!-- 7 -->⚙️ Miscellaneous Tasks

- *(manifest)* explicitly set the versions to the lockfile versions
- *(renovate)* don't pin dev dependencies in the Cargo.toml
- *(rust)* configure rustfmt to wrap comments
- *(rust)* configure rustfmt to split long strings
- *(rust)* configure rustfmt to group imports
- *(rust)* configure rustfmt to split each import out
- *(rust)* add more clippy lints
- *(rust)* remove direct dependency on the http crate
- *(rust)* even more clippy lints
- release v0.3.8


## [0.3.7](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.6...v0.3.7) - 2025-08-29


### <!-- 0 -->🚀 Features

- *(webnsupdate)* add support for fritzbox style updates
- *(webnsupdate)* parse IPv6 prefixes
- add config file to webnsupdate
- use rust-overlay to get the rust binaries
- upgrade to edition 2024

### <!-- 1 -->🐛 Bug Fixes

- *(deps)* update rust crate serde_json to v1.0.138
- *(webnsupdate)* make IP none when query is empty
- *(tests)* add case for when query has empty string
- *(webnsupdate)* updating IPv6 in ipv4-only mode
- *(deps)* update rust crate miette to v7.5.0
- *(deps)* update rust crate clap to v4.5.28
- *(deps)* update rust crate clap to v4.5.29
- *(deps)* update rust crate ring to v0.17.9
- *(deps)* update rust crate clap to v4.5.30
- *(deps)* update rust crate serde_json to v1.0.139
- *(deps)* update rust crate serde to v1.0.218
- *(deps)* update rust crate ring to v0.17.10
- *(deps)* update rust crate ring to v0.17.11
- *(deps)* update rust crate clap to v4.5.31
- *(deps)* update rust crate serde_json to v1.0.140
- *(typo)* typos corrected typ to typo
- *(deps)* update rust crate ring to v0.17.12
- *(deps)* update rust crate ring to v0.17.13
- *(deps)* update rust crate tokio to v1.44.0
- *(deps)* update rust crate serde to v1.0.219
- *(deps)* update rust crate clap to v4.5.32
- *(deps)* update rust crate http to v1.3.0
- *(deps)* update rust crate ring to v0.17.14
- *(deps)* update rust crate http to v1.3.1
- *(deps)* update rust crate tokio to v1.44.1
- *(deps)* update rust crate clap to v4.5.33
- *(deps)* update rust crate clap to v4.5.34
- *(deps)* update rust crate axum to v0.8.3
- *(deps)* update rust crate clap to v4.5.35
- *(deps)* update rust crate axum-client-ip to v1
- *(deps)* update rust crate tokio to v1.44.2
- *(cargo)* properly declare license
- *(deps)* update rust crate clap to v4.5.36
- *(deps)* update rust crate clap to v4.5.37
- *(deps)* update rust crate miette to v7.6.0
- *(treefmt)* respect the packages edition
- *(deps)* update rust crate axum to v0.8.4
- *(deps)* update rust crate tokio to v1.45.0
- *(deps)* update rust crate tower-http to v0.6.3
- *(deps)* update rust crate clap to v4.5.38
- switch from the gh tarball to the nixpkgs channel
- remove license-file since license is standard
- *(deps)* update rust crate clap-verbosity-flag to v3.0.3
- *(deps)* update rust crate tokio to v1.45.1
- *(renovate)* simplify config
- *(deps)* update rust crate clap to v4.5.39
- *(deps)* update rust crate axum-client-ip to v1.1.0
- *(deps)* update rust crate tower-http to v0.6.5
- *(deps)* update rust crate axum-client-ip to v1.1.2
- *(deps)* update rust crate axum-client-ip to v1.1.3
- *(deps)* update rust crate tower-http to v0.6.6
- *(clippy)* split code a bit 
- *(deps)* update rust crate clap to v4.5.40
- *(deps)* update rust crate tokio to v1.46.0
- *(deps)* update rust crate tokio to v1.46.1
- *(deps)* update rust crate clap to v4.5.41
- *(deps)* update rust crate serde_json to v1.0.141
- *(deps)* update rust crate tokio to v1.47.0
- *(deps)* update rust crate clap to v4.5.42
- *(deps)* update rust crate serde_json to v1.0.142
- *(deps)* update rust crate tokio to v1.47.1
- *(deps)* update rust crate clap to v4.5.43
- *(deps)* update rust crate clap to v4.5.44
- *(deps)* update rust crate thiserror to v2.0.13
- *(deps)* update rust crate thiserror to v2.0.14
- *(deps)* update rust crate clap to v4.5.45
- *(deps)* update rust crate thiserror to v2.0.15
- *(deps)* update rust crate serde_json to v1.0.143
- *(deps)* update rust crate clap-verbosity-flag to v3.0.4
- *(deps)* update rust crate thiserror to v2.0.16
- *(deps)* update rust crate clap to v4.5.46
- *(deps)* update rust crate tracing-subscriber to v0.3.20
- *(treefmt)* exclude auto-generated files

### <!-- 2 -->🚜 Refactor

- *(module)* NixOS tests
- *(nsupdate)* send all commands at once
- *(package)* share more stuff

### <!-- 7 -->⚙️ Miscellaneous Tasks

- *(renovate)* don't overlap schedules
- validate renovaterc
- *(config)* migrate config .renovaterc.json
- use nix-fast-build to speedup checks
- pin nix-flake-outputs-size
- split up check-renovaterc
- *(fix)* rename .renovaterc.json to renovate.json
- split out checks into one job per check
- run cargo-deny to ensure I agree to all license terms
- configure release-plz
- fix release use correct devShell
- trigger on pull_request instead of push
- fix release-plz
- *(release)* fix typo
- *(release)* fetch full git history
- *(release)* add actual release command
- *(report-size)* only report package size
- release v0.3.7
- *(release)* fix typo in cargo registry token


## [0.3.6](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.5...v0.3.6) - 2025-01-26


### <!-- 0 -->🚀 Features

- *(webnsupdate)* allow running in IPv4/6 only mode
- *(module)* add option for setting --ip-type
- *(flake)* add tests for new allowedIPVersion option


## [0.3.5](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.4...v0.3.5) - 2025-01-23


### <!-- 0 -->🚀 Features

- *(renovate)* enable lockFileMaintenance
- *(webnsupdate)* add handling for multiple IPs
- tune compilation for size
- *(tests)* add nginx integration test

### <!-- 1 -->🐛 Bug Fixes

- *(flake)* switch to github ref
- *(renovate)* switch automergeStrategy to auto
- *(ci)* remove update workflow
- *(typos)* typos caught more typos :3
- *(renovate)* branch creation before automerge
- *(renovaterc)* invalid cron syntax
- *(deps)* update rust crate clap to v4.5.24
- *(deps)* update rust crate tokio to v1.43.0
- *(deps)* update rust crate clap to v4.5.25
- *(deps)* update rust crate clap to v4.5.26
- *(flake)* switch overlay to callPackage
- *(deps)* update rust crate clap to v4.5.27
- *(deps)* update rust crate axum to v0.8.2
- *(module)* test both IPv4 and IPv6

### <!-- 2 -->🚜 Refactor

- setup renovate to manage dependencies

### <!-- 7 -->⚙️ Miscellaneous Tasks

- update to axum 0.8
- parallelize checks


## [0.3.4](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.3...v0.3.4) - 2024-12-26


### <!-- 1 -->🐛 Bug Fixes

- *(main)* add more logging and default to info


## [0.3.3](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.2...v0.3.3) - 2024-12-22


### <!-- 0 -->🚀 Features

- *(ci)* generate package size report
- add git-cliff to generate changelogs

### <!-- 1 -->🐛 Bug Fixes

- *(webnsupdate)* reduce binary size
- *(ci)* remove tea

### <!-- 7 -->⚙️ Miscellaneous Tasks

- bump version to dev
- *(flake.lock)* update inputs
- cargo update
- generate base changelog


## [0.3.2](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.1...v0.3.2) - 2024-11-23


### <!-- 0 -->🚀 Features

- *(ci)* check depends on build
- upgrade clap_verbosity_flag
- replace axum-auth with tower_http
- release new version

### <!-- 1 -->🐛 Bug Fixes

- *(clippy)* enable more lints and fix issues

### <!-- 2 -->🚜 Refactor

- reorganize main.rs

### <!-- 7 -->⚙️ Miscellaneous Tasks

- bump version
- cargo update
- update flake inputs


## [0.3.1](https://git.salame.cl/jalil/webnsupdate/compare/v0.3.0...v0.3.1) - 2024-10-28


### <!-- 1 -->🐛 Bug Fixes

- overlay was broken T-T

### <!-- 7 -->⚙️ Miscellaneous Tasks

- next dev version


## [0.3.0](https://git.salame.cl/jalil/webnsupdate/compare/v0.2.0...v0.3.0) - 2024-10-28


### <!-- 0 -->🚀 Features

- *(ci)* auto-update rust deps
- refactor and add ip saving
- add -v verbosity flag
- use treefmt-nix and split up flake.nix
- add NixOS VM tests
- switch to crane

### <!-- 1 -->🐛 Bug Fixes

- *(fmt)* use nixfmt-rfc-style
- *(default.nix)* small issues here and there
- *(ci)* do not use a name when logging in

### <!-- 2 -->🚜 Refactor

- *(flake)* use flake-parts

### <!-- 7 -->⚙️ Miscellaneous Tasks

- updarte deps
- *(flake.lock)* update inputs
- cargo update
- cargo update
- cargo update
- bump version


## 0.2.0 - 2024-06-02


### <!-- 10 -->💼 Other

- Init at version 0.1.0
