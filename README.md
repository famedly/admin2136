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

Records are shown and edited in their zone file presentation format. This is
supported for A, AAAA, AFSDB, CAA, CDNSKEY, CDS, CERT, CNAME, DHCID, DNAME,
DNSKEY, DS, HINFO, HTTPS, KX, MX, NAPTR, NS, NSEC3PARAM, OPENPGPKEY, PTR, RP,
RT, SMIMEA, SPF, SRV, SSHFP, SVCB, TLSA, TXT, URI and ZONEMD records. The SOA
record can be edited as well, except for its serial, which is incremented
automatically; concurrent updates of the SOA are detected with an RFC 2136
prerequisite and merged. Other record types are shown read-only as raw RFC 3597
`\# len hex` data. DNSSEC records maintained by the signer (RRSIG, NSEC, NSEC3)
are hidden.

Catalog zones (RFC 9432) are detected automatically and shown as a list of their
member zones with their SOA records and further apex NS records (the SOA's
primary nameserver has one anyway), which can be filtered, opened and removed.
The SOA and NS records are queried with normal queries, only for the zones on
screen. A new zone is entered in a row added at the end of the list, with its
group, SOA and nameservers; the checkmark adds it to the catalog and creates it
with these records. Member zones without any records yet (a transfer fails with
SERVFAIL, and so does a normal SOA query) get the same inputs. If the server
signs a new zone, the DS records to enter at the parent zone are shown. A toggle
in the toolbar switches to the raw records of the catalog zone. Each opened
member zone gets its own browser history entry, so the back button returns to
the catalog. The toolbar shows the path from the catalog to the member zone;
clicking the catalog goes back to it, and clicking admin2136 goes back to the
login form.

The TSIG key given at login is used for all zone transfers and updates. If the
server rejects an update (for example because the key only grants transfers), a
separate key for updates of that zone can be entered. Likewise, if the server
refuses the transfer of a member zone opened from a catalog with the catalog's
key, another key for that zone can be entered.

Zones are loaded with AXFR. Refreshing a zone requests only the changes since
the last transfer with IXFR (RFC 1995). If the server cannot provide them with
IXFR, it sends the full zone (AXFR) instead.

Logging in to a zone without any records yet shows it as a single row like in
the catalog view, with the same inputs for its SOA and apex NS records.

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

End-to-end tests drive the site in headless Chromium against Knot DNS through
[dows](https://github.com/famedly/dows). Knot serves an interpreted catalog zone
whose member zones are configured in three groups by what the catalog's TSIG key
may do there (nothing, transfers only, or transfers and updates). A Knot test
module (`test/e2e/knot/ignoreme.c`) silently drops the updates of names whose
leftmost label is `ignore-me`, to check that the site shows the server's zone
contents even then. The nix devshell `e2e` provides all of it:

```console
$ nix develop .#e2e --command node test/e2e/run.mjs
```

The same setup (site, dows and Knot with the catalog zone, its groups and the
initial zones) can be started for manual use. It prints the ports and the
randomly generated TSIG keys, and runs until Ctrl-C:

```console
$ nix run .#test-env
```

The services listen on the loopback interface only and are shown as `localhost`.
Inside a Docker container (or with `ADMIN2136_DOCKER=1`), they listen on all
interfaces and are shown with the container's IP address instead. Browsers only
provide Web Crypto, which TSIG needs, on `localhost` and HTTPS, so use port
forwarding to log in with a key from the host.

The coverage of both test suites together, with `--details` listing uncovered
branches:

```console
$ nix develop .#e2e --command node test/coverage.mjs --details
```

It also writes `coverage/lcov.info` (paths relative to the repository), which
editors can show: in Zed, the
[Coverage LSP](https://zed.dev/extensions/coverage-lsp) extension finds it in
the workspace and highlights covered and uncovered lines (no branches).
