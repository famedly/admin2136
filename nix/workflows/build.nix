# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{ config, ... }:
let
  allowed-actions = config.famedly.standards.allowed-action-versions;

  # Not (yet) part of the engineering standards' allow-list
  # (`standards/allowed-github-actions.toml`), so we pin them here the
  # same way: by full commit SHA.
  #
  # rev = "v7.0.1"
  upload-artifact = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
  # rev = "v8.0.1"
  download-artifact = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
in
{
  perSystem.githubActions.workflows.build = {
    name = "Build";

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
    on.push = {
      branches = [ "main" ];
      tags = [ "v*" ];
    };

    concurrency = {
      group = "\${{ github.workflow }}-\${{ github.ref }}";
      cancelInProgress = true;
    };

    jobs.build = {
      strategy.matrix.include = [
        {
          arch = "x86_64";
          runner = "ubuntu-26.04";
        }
        {
          arch = "aarch64";
          runner = "ubuntu-26.04-arm";
        }
      ];

      steps = [
        { uses = allowed-actions."actions/checkout".uses; }
        { uses = allowed-actions."cachix/install-nix-action".uses; }

        {
          name = "Build static site";
          run = "nix build .#admin2136 --print-build-logs -o result-site";
        }

        {
          # The image is the existing upstream Alpine-based
          # static-web-server image with the site files layered on top;
          # static-web-server itself is not built with nix.
          name = "Build Docker image";
          run = "nix build .#docker-image --print-build-logs";
        }

        {
          name = "Upload Docker image as artifact";
          uses = upload-artifact;
          with_ = {
            name = "docker-image-\${{ matrix.arch }}";
            path = "result";
            if-no-files-found = "error";
          };
        }
      ];
    };

    # Push images for all builds: version tags go to the release
    # registry (docker-oss), everything else (PRs, main) goes to the
    # nightly registry (docker-nightly). The per-architecture images
    # are combined into a single multi-arch manifest.
    #
    # The registry authenticates the workflow with a GitHub Actions
    # OIDC token (JWT). GitHub never grants id-token: write to pull
    # requests from forks, so the job is skipped for them.
    jobs.docker = {
      runsOn = "ubuntu-latest";
      if_ = "github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)";
      needs = [ "build" ];

      permissions = {
        # Required for the runner to expose
        # ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN.
        id-token = "write";
        contents = "read";
      };

      steps = [
        {
          # Instead of `podman login` (which writes the token to an auth
          # file), install a credential helper. Podman invokes it on
          # demand and it mints a fresh OIDC token each time, so nothing
          # is persisted and token expiry during long jobs is a
          # non-issue.
          name = "Install OIDC credential helper for registry.famedly.net";
          run = ''
            set -euo pipefail

            bin="$RUNNER_TEMP/bin/docker-credential-gha-oidc"
            mkdir -p "$(dirname "$bin")"
            cat > "$bin" <<'EOF'
            #!/usr/bin/env bash
            # Docker credential helper, also understood by podman
            # https://github.com/docker/docker-credential-helpers#development
            set -euo pipefail
            if [[ "''${1:-}" != get ]]; then
              echo "unsupported operation: ''${1:-<none>}" >&2
              exit 1
            fi
            IFS= read -r server || [[ -n "$server" ]]
            curl -sSfG --data-urlencode "audience=https://$server" \
              -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL" |
            jq --arg s "$server" \
              '{ServerURL: $s, Username: "__jwt", Secret: (.value // error("response has no .value"))}'
            EOF
            chmod +x "$bin"
            echo "$(dirname "$bin")" >> "$GITHUB_PATH"

            # Podman looks up credential helpers in its auth file
            # (containers-auth.json(5)).
            auth="$RUNNER_TEMP/containers-auth.json"
            jq -n '.credHelpers["registry.famedly.net"] = "gha-oidc"' > "$auth"
            echo "REGISTRY_AUTH_FILE=$auth" >> "$GITHUB_ENV"
          '';
        }

        {
          name = "Download Docker images";
          uses = download-artifact;
          with_ = {
            pattern = "docker-image-*";
            path = "artifacts";
          };
        }

        {
          name = "Push multi-arch Docker manifest to registry";
          env = {
            TAG = "\${{ github.head_ref || github.ref_name || 'latest' }}";
          };
          run = ''
            if [[ "$GITHUB_REF_NAME" =~ v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
              registry=registry.famedly.net/docker-oss
            else
              registry=registry.famedly.net/docker-nightly
            fi

            image="$registry/admin2136"
            # Branch names may contain slashes, which are not valid in
            # Docker tags.
            tag="''${TAG//\//-}"

            # Combine the per-arch images into a multi-arch manifest.
            # Every `podman load` overwrites `admin2136:latest`, so retag
            # each image with an arch suffix before loading the next.
            podman manifest create admin2136-multiarch
            for arch in x86_64 aarch64; do
              podman load < "artifacts/docker-image-$arch/result"
              podman tag admin2136:latest "admin2136:$arch"
              podman manifest add admin2136-multiarch "containers-storage:localhost/admin2136:$arch"
            done

            # `--all` pushes the per-arch images along with the
            # manifest (by digest only, so no arch-specific tags show
            # up in the registry). Publish under both the branch/tag
            # name and the commit SHA.
            podman manifest push --all admin2136-multiarch "docker://$image:$tag"
            podman manifest push --all admin2136-multiarch "docker://$image:$GITHUB_SHA"
          '';
        }
      ];
    };
  };
}
