# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{ inputs, ... }:
{
  perSystem =
    { config, pkgs, ... }:
    let
      rev = inputs.self.rev;

      # The existing upstream Alpine-based static-web-server image;
      # static-web-server is deliberately not built with nix. Pinned by
      # digest, so update imageDigest and hash together (e.g. with
      # nix-prefetch-docker).
      static-web-server-image = pkgs.dockerTools.pullImage {
        imageName = "ghcr.io/static-web-server/static-web-server";
        finalImageTag = "2-alpine";
        imageDigest = "sha256:9ddec0e5fb0320cbba2ded016fc96179c5a891feec1b2049a331bc190c08008f";
        hash = "sha256-LrLfLRcqOJKfTudCbvx4TcG/Q7cVVlXOiW2NOuj/+2M=";
        os = "linux";
      };
    in
    {
      packages = {
        admin2136 = pkgs.stdenvNoCC.mkDerivation {
          nativeBuildInputs = [ pkgs.mustache-go ];
          data = builtins.toJSON { git_commit_hash = rev; };
          passAsFile = [ "data" ];

          pname = "admin2136";
          version = "0.1.0";

          src = pkgs.lib.fileset.toSource {
            root = ../.;
            fileset = pkgs.lib.fileset.unions [
              ../style.css
              ../js
            ];
          };

          dontBuild = true;

          installPhase = ''
            runHook preInstall

            mkdir -p $out
            mustache "$dataPath" ${../index.html} > $out/index.html
            cp -r style.css js $out/

            runHook postInstall
          '';

          meta.description = "AXFR / RFC 2136 zone editor";
        };

        default = config.packages.admin2136;

        docker-image = pkgs.dockerTools.buildLayeredImage {
          name = "admin2136";
          tag = "latest";

          fromImage = static-web-server-image;

          # Add the site as a real directory (not a /nix/store
          # symlink), so the image stays nothing but the upstream image
          # plus one layer of static files.
          fakeRootCommands = ''
            mkdir -p ./public
            cp -r ${config.packages.admin2136}/. ./public/
          '';

          # buildLayeredImage does not inherit the base image
          # configuration, so restate it (see docker/alpine/Dockerfile
          # and docker/alpine/entrypoint.sh upstream), pointing the
          # server at the site directory.
          config = {
            User = "sws:sws";
            WorkingDir = "/home/sws";
            Entrypoint = [ "/usr/local/bin/entrypoint.sh" ];
            Cmd = [ "static-web-server" ];
            Env = [
              "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
              "SERVER_ROOT=/public"
            ];
            ExposedPorts."80/tcp" = { };
            StopSignal = "SIGQUIT";
          };
        };
      };
    };
}
