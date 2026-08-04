# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# admin2136 is a fully static site, so serving it is delegated to the
# upstream Alpine-based static-web-server image; only the site files are
# added on top. static-web-server serves /public on port 80 by default.
FROM ghcr.io/static-web-server/static-web-server:2-alpine

COPY index.html style.css /public/
COPY js /public/js
