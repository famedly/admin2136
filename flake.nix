# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{
  description = "AXFR / RFC 2136 zone editor";

  inputs = {
    famedly-engineering-standards.url = "github:famedly/engineering-standards";

    nixpkgs.follows = "famedly-engineering-standards/nixpkgs";
    flake-parts.follows = "famedly-engineering-standards/flake-parts";
  };

  outputs =
    { famedly-engineering-standards, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        famedly-engineering-standards.flakeModules.default

        ./nix/package.nix
        ./nix/workflows/build.nix
        ./nix/workflows/tests.nix
      ];

      systems = famedly-engineering-standards.lib.famedlySystems;

      perSystem =
        { config, pkgs, ... }:
        {
          # This is a plain JavaScript project without a build step, so
          # the standards devshell is all we need -- plus Node.js to run
          # the smoke tests.
          devShells.default = config.devShells.standards;
          devshells.standards.devshell.packages = [ pkgs.nodejs ];

          famedly.standards = {
            nix.projects."." = { };
          };

          # Hard-wrap markdown prose at 80 columns. mdformat runs
          # through the treefmt pre-commit hook, so violations are
          # fixed automatically.
          treefmt = {
            programs.mdformat = {
              enable = true;
              settings.wrap = 80;
            };

            # Refer to the binary by name so that the generated
            # treefmt.toml does not contain nix store paths. The package
            # is put on PATH through the prek wrapper and the devshell.
            settings.formatter.mdformat.command = "mdformat";
          };

          # Check licensing information (SPDX headers and REUSE.toml)
          # against the REUSE specification. This runs in CI through
          # the check-pre-commit-hooks workflow.
          prek-pre-commit = {
            package.runtimePkgs = [ pkgs.reuse ];

            workspaces.".".repos = [
              {
                repo = "local";
                hooks = [
                  {
                    id = "reuse";
                    name = "reuse";
                    description = "Check licensing info for REUSE compliance";
                    pass_filenames = false;

                    entry = "reuse lint";
                    language = "system";
                  }
                ];
              }
            ];
          };
        };
    };
}
