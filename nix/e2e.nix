# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# End-to-end tests: a headless browser drives the site against Knot DNS
# through dows. `nix develop .#e2e --command node test/e2e/run.mjs`
{ inputs, ... }:
{
  perSystem =
    {
      config,
      lib,
      pkgs,
      system,
      ...
    }:
    lib.mkIf pkgs.stdenv.isLinux {
      # Knot DNS module silently dropping updates of `ignore-me.*` names,
      # see test/e2e/knot/ignoreme.c.
      packages.knot-mod-ignoreme = pkgs.stdenv.mkDerivation {
        pname = "knot-mod-ignoreme";
        version = "0.1.0";
        src = ../test/e2e/knot;
        buildInputs = [ pkgs.knot-dns ];
        buildPhase = ''
          runHook preBuild
          $CC -O2 -Wall -Wextra -Werror -shared -fPIC \
            -o ignoreme.so ignoreme.c -lknot -ldnssec
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          install -Dm755 ignoreme.so $out/lib/knot/ignoreme.so
          runHook postInstall
        '';
      };

      # The test setup (site, dows, Knot with the catalog and its zones)
      # for manual use, until Ctrl-C: `nix run .#test-env`
      apps.test-env = {
        type = "app";
        program = lib.getExe (
          pkgs.writeShellApplication {
            name = "admin2136-test-env";
            runtimeInputs = [
              pkgs.nodejs_latest
              pkgs.knot-dns
              inputs.dows.packages.${system}.dows
            ];
            text =
              let
                src = lib.fileset.toSource {
                  root = ../.;
                  fileset = lib.fileset.unions [
                    ../index.html
                    ../style.css
                    ../js
                    ../test/e2e
                  ];
                };
              in
              ''
                export ADMIN2136_KNOT_MODULE=${config.packages.knot-mod-ignoreme}/lib/knot/ignoreme.so
                exec node ${src}/test/e2e/serve.mjs "$@"
              '';
          }
        );
        meta.description = "admin2136 test setup: site, dows and Knot DNS";
      };

      devshells.e2e = {
        devshell.packages = [
          pkgs.nodejs_latest
          pkgs.knot-dns
          pkgs.chromium
          inputs.dows.packages.${system}.dows
        ];
        env = [
          {
            name = "ADMIN2136_KNOT_MODULE";
            value = "${config.packages.knot-mod-ignoreme}/lib/knot/ignoreme.so";
          }
          {
            # Headless Chromium aborts without any font configuration.
            name = "FONTCONFIG_FILE";
            value = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
          }
        ];
      };
    };
}
