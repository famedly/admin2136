# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{ config, ... }:
let
  allowed-actions = config.famedly.standards.allowed-action-versions;
in
{
  perSystem.githubActions.workflows.tests = {
    name = "Run tests";

    on.pullRequest = {
      branches = [ "**" ];
      types = [
        "opened"
        "reopened"
        "synchronize"
        "ready_for_review"
      ];
    };
    on.mergeGroup = { };

    concurrency = {
      group = "\${{ github.workflow }}-\${{ github.ref }}";
      cancelInProgress = true;
    };

    jobs.smoke = {
      runsOn = "ubuntu-latest";

      steps = [
        { uses = allowed-actions."actions/checkout".uses; }
        { uses = allowed-actions."cachix/install-nix-action".uses; }

        {
          name = "Run tests";
          shell = "nix develop --command bash {0}";
          run = "node test/smoke.mjs";
        }
      ];
    };

    # Headless Chromium against Knot DNS (with an interpreted catalog zone)
    # through dows; also runs the smoke tests to report the coverage of
    # both together.
    jobs.e2e = {
      runsOn = "ubuntu-latest";

      steps = [
        { uses = allowed-actions."actions/checkout".uses; }
        { uses = allowed-actions."cachix/install-nix-action".uses; }

        {
          name = "Run end-to-end tests and report coverage";
          shell = "nix develop .#e2e --command bash {0}";
          run = "node test/coverage.mjs --details";
        }
      ];
    };
  };
}
