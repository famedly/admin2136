<!--
SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# admin2136 (AXFR / RFC 2136 zone editor)

admin2136 is a standalone web frontend for DNS zone management via AXFR and RFC
2136 dynamic updates, authenticated with TSIG.

The browser cannot speak to port 53 directly, so all DNS messages travel through
a DoWS (DNS over WebSocket) proxy such as
[dows](https://github.com/famedly/dows).

Editing is supported for A, AAAA, CNAME, TXT and SSHFP records; other record
types are shown read-only (unknown types as raw RFC 3597 `\# len hex` data).

## Run

The site is fully static and can be served by any web server. A Docker image
that layers the site on top of the existing upstream Alpine-based
[static-web-server](https://static-web-server.net/) image can be built with the
nix flake:

```console
$ nix build .#docker-image
$ docker load < result
$ docker run --rm -p 8080:80 admin2136
```

The site is then available at `http://localhost:8080`.

## Tests

The DOM-independent modules are covered by smoke tests:

```console
$ node test/smoke.mjs
```
