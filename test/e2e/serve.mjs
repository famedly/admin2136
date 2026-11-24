// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Start the end-to-end test setup for manual use: the site, dows and Knot
// DNS with the catalog zone, its member groups and the initial zones (see
// env.mjs). Runs until interrupted (Ctrl-C), then stops all services.
//
//   nix run .#test-env [-- --root DIR]
//
// --root DIR serves the site from DIR (e.g. a working copy) instead of
// the directory this script belongs to.
//
// Normally the services only listen on the loopback interface and are
// shown as "localhost". Inside a Docker container they listen on all
// interfaces and are shown with the container's IP address, so they can
// be reached from the host.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startEnv, MEMBERS } from "./env.mjs";

const args = process.argv.slice(2);
const rootIdx = args.indexOf("--root");
const root = path.resolve(
  rootIdx >= 0
    ? args[rootIdx + 1]
    : path.join(path.dirname(fileURLToPath(import.meta.url)), "../.."),
);
if (!fs.existsSync(path.join(root, "index.html"))) {
  console.error(`no index.html in ${root}`);
  process.exit(2);
}

const read = (file) => {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (e) {
    return "";
  }
};

// Docker creates /.dockerenv; otherwise the cgroup (v1) or the mounts of
// the container's own files (v2) tell. ADMIN2136_DOCKER=1 or =0 overrides
// the detection (e.g. for other container runtimes).
function inDocker() {
  const force = process.env.ADMIN2136_DOCKER;
  if (force === "1" || force === "0") return force === "1";
  return (
    fs.existsSync("/.dockerenv") ||
    /docker|containerd|kubepods/.test(read("/proc/1/cgroup")) ||
    /\/docker\/containers\//.test(read("/proc/self/mountinfo"))
  );
}

// The container's primary address: eth0 (or the first other interface),
// IPv4 preferred.
function primaryAddress() {
  const ifaces = Object.entries(os.networkInterfaces()).sort(
    ([a], [b]) => (b === "eth0") - (a === "eth0"),
  );
  const all = ifaces.flatMap(([, addrs]) => addrs).filter((a) => !a.internal);
  return (all.find((a) => a.family === "IPv4") ?? all[0])?.address ?? null;
}

const hasIPv6 = () =>
  Object.values(os.networkInterfaces())
    .flat()
    .some((a) => a.family === "IPv6");

const docker = inDocker();
let net;
if (docker) {
  const ip = primaryAddress();
  if (!ip) {
    console.error("inside Docker, but no network address found");
    process.exit(1);
  }
  net = {
    bind: hasIPv6() ? "::" : "0.0.0.0",
    host: ip,
    aliases: ["localhost", "127.0.0.1"],
    local: ["127.0.0.1", "::1", ip],
    // The site may be opened through any address or forwarded port.
    anyOrigin: true,
  };
} else {
  net = { bind: "127.0.0.1", host: "localhost", aliases: ["127.0.0.1"] };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "admin2136-env-"));
let env;
try {
  env = await startEnv(root, dir, net);
} catch (err) {
  console.error("failed to start: " + err.message);
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(1);
}

const keyLine = (id, what) => `  ${id}  ${env.spec(id)}\n      ${what}`;
console.log(`admin2136 test setup${docker ? ` (Docker: listening on ${net.bind})` : ""}

Site:        ${env.origin}/  (from ${root})
dows:        ${env.proxyUrl}  (port ${env.ports.dows})
Knot DNS:    ${env.nameserver}  (port ${env.ports.knot})
Slow relay:  ${env.slowNameserver}  (port ${env.ports.relay}, Knot behind a throttle)

TSIG keys (as entered at login):
${keyLine("kc", "catalog key: catalog.test (transfer, update); groups full, axfr-only")}
${keyLine("kz", "zones of group own-key (transfer, update)")}
${keyLine("ku", "updates in group axfr-only; transfer of catalog.test")}

Zones:
  catalog.test   interpreted catalog zone (key kc)
${MEMBERS.map(([zone, group]) => `  ${zone.padEnd(14)} member, group ${group}`).join("\n")}
  open.example   standalone, no TSIG

Updates of names whose leftmost label is "ignore-me" are silently ignored.${
  docker
    ? `

Note: browsers provide Web Crypto (needed for TSIG keys) only on localhost
or HTTPS, not on http://${net.host}. Forward the ports to localhost on the
host, or let the browser treat ${env.origin} as secure (Chromium:
chrome://flags/#unsafely-treat-insecure-origin-as-secure). The nameserver
${env.nameserver} is resolved inside the container.`
    : ""
}
Data and logs: ${dir}
Press Ctrl-C to stop.`);

let stopping = false;
const stop = async (signal) => {
  if (stopping) return;
  stopping = true;
  console.log(`\n${signal}: stopping…`);
  await env.stop();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log("stopped.");
  process.exit(0);
};
process.on("SIGINT", () => stop("SIGINT"));
process.on("SIGTERM", () => stop("SIGTERM"));
process.on("SIGHUP", () => stop("SIGHUP"));
