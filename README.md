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
