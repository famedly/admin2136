// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test environment: Knot DNS with an interpreted catalog zone, dows, and a
// static web server for the site.
//
// The catalog zone catalog.test. is interpreted by Knot: its member zones
// are configured from templates selected by their group property. The
// groups differ in what the catalog's TSIG key (kc) may do:
//
//   own-key    nothing; the zones only accept their own key kz
//   axfr-only  transfers; updates need the key ku
//   full       transfers and updates (the default template)
//
// The key ku may also transfer (but not update) the catalog zone itself.
// open.example. is a standalone zone without TSIG (address-based ACL).
//
// All zones load the test module mod-ignoreme (see knot/ignoreme.c),
// which silently drops updates of names whose leftmost label is
// "ignore-me".

import { spawn, execFile } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer, connect } from "node:net";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// Member zones of the catalog when the tests start: [zone, group, id].
export const MEMBERS = [
  ["own.example", "own-key", "own"],
  ["xfr.example", "axfr-only", "xfr"],
  ["full.example", "full", "full"],
  ["big.example", "full", "big"],
];

const SOA = (zone) =>
  `@ 3600 SOA ns1.${zone}. hostmaster.${zone}. 1 3600 600 86400 300\n` +
  `@ 3600 NS ns1.${zone}.\nns1 3600 A 192.0.2.1\n`;

function zoneFiles() {
  const big = [];
  for (let i = 0; i < 30000; i++) {
    big.push(`host${i} 300 A 10.0.${i >> 8}.${i & 255}`);
  }
  return {
    "catalog.test":
      "@ 0 SOA invalid. invalid. 1 3600 600 86400 0\n" +
      '@ 0 NS invalid.\nversion 0 TXT "2"\n',
    "own.example": SOA("own.example") + "www 3600 A 192.0.2.10\n",
    "xfr.example": SOA("xfr.example") + "www 3600 A 192.0.2.20\n",
    "full.example":
      SOA("full.example") +
      [
        "www 3600 A 192.0.2.30",
        "www 3600 AAAA 2001:db8::30",
        "@ 3600 MX 10 mail.full.example.",
        "mail 3600 A 192.0.2.31",
        '@ 3600 TXT "v=spf1 -all"',
        '@ 3600 CAA 0 issue "letsencrypt.org"',
        '@ 3600 HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.30',
        "_443._tcp.www 3600 TLSA 3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6",
        "loc 3600 LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        // pre-existing: deleting it is silently ignored by mod-ignoreme
        "ignore-me 3600 A 192.0.2.99",
      ].join("\n") +
      "\n",
    "big.example": SOA("big.example") + big.join("\n") + "\n",
    "open.example": SOA("open.example") + "www 3600 A 192.0.2.40\n",
  };
}

function knotConf(dir, port, keys, module) {
  const key = (id) =>
    `  - id: ${id}\n    algorithm: hmac-sha256\n    secret: ${keys[id]}\n`;
  const tpl = (id, acl) =>
    `  - id: ${id}\n    storage: ${dir}/zones\n    zonefile-sync: -1\n` +
    `    journal-content: changes\n    module: mod-ignoreme\n` +
    (acl ? `    acl: [${acl}]\n` : "");
  return (
    `server:\n    listen: 127.0.0.1@${port}\n    rundir: ${dir}/run\n` +
    `log:\n  - target: ${dir}/knot.log\n    any: info\n` +
    `database:\n    storage: ${dir}/db\n` +
    `key:\n${key("kc")}${key("kz")}${key("ku")}` +
    "acl:\n" +
    "  - id: catalog\n    key: kc\n    action: [transfer, update]\n" +
    "  - id: kc-transfer\n    key: kc\n    action: transfer\n" +
    "  - id: kc-update\n    key: kc\n    action: update\n" +
    "  - id: kz-all\n    key: kz\n    action: [transfer, update]\n" +
    "  - id: ku-update\n    key: ku\n    action: update\n" +
    "  - id: ku-transfer\n    key: ku\n    action: transfer\n" +
    "  - id: local\n    address: 127.0.0.1\n    action: [transfer, update]\n" +
    `module:\n  - id: mod-ignoreme\n    file: ${module}\n` +
    "template:\n" +
    tpl("default") +
    tpl("full", "kc-transfer, kc-update") +
    tpl("own-key", "kz-all") +
    tpl("axfr-only", "kc-transfer, ku-update") +
    "zone:\n" +
    "  - domain: catalog.test\n    acl: [catalog, ku-transfer]\n" +
    "    catalog-role: interpret\n" +
    "    catalog-template: [full, own-key, axfr-only]\n" +
    "  - domain: open.example\n    acl: local\n"
  );
}

// Static file server for the site (repository root).
function webServer(root, port) {
  const types = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
  };
  const srv = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    let file = path.join(root, decodeURIComponent(url.pathname));
    if (!file.startsWith(root)) file = root;
    if (file.endsWith("/")) file += "index.html";
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404, { connection: "close" });
        res.end();
        return;
      }
      res.writeHead(200, {
        "content-type": types[path.extname(file)] || "application/octet-stream",
        "cache-control": "no-store",
        connection: "close",
      });
      res.end(data);
    });
  });
  return new Promise((resolve) =>
    srv.listen(port, "127.0.0.1", () => resolve(srv)),
  );
}

// TCP relay in front of Knot that passes the server's replies on slowly
// (32 KiB per 50 ms) and can cut all its connections, to interrupt
// transfers. It reads from Knot at full speed (Knot drops clients that do
// not read), so it buffers.
function slowRelay(port, upstreamPort) {
  const conns = new Set();
  const srv = createNetServer((client) => {
    const up = connect(upstreamPort, "127.0.0.1");
    let buf = Buffer.alloc(0);
    let upDone = false;
    const conn = {
      close() {
        clearInterval(timer);
        client.destroy();
        up.destroy();
        conns.delete(conn);
      },
    };
    conns.add(conn);
    const timer = setInterval(() => {
      if (buf.length) {
        client.write(buf.subarray(0, 32768));
        buf = buf.subarray(32768);
      } else if (upDone) {
        conn.close(); // everything from Knot passed on
      }
    }, 50);
    client.on("error", () => conn.close()).on("close", () => conn.close());
    up.on("error", () => conn.close()).on("close", () => (upDone = true));
    up.on("data", (data) => (buf = Buffer.concat([buf, data])));
    client.pipe(up);
  });
  srv.cut = () => {
    for (const c of [...conns]) c.close();
  };
  return new Promise((resolve) =>
    srv.listen(port, "127.0.0.1", () => resolve(srv)),
  );
}
function startProcess(cmd, args, opts, logFile) {
  const log = fs.openSync(logFile, "a");
  const child = spawn(cmd, args, { ...opts, stdio: ["ignore", log, log] });
  child.on("error", (e) => fs.appendFileSync(logFile, "spawn error: " + e));
  return child;
}

export async function startEnv(root, dir) {
  const module = process.env.ADMIN2136_KNOT_MODULE;
  if (!module) {
    throw new Error(
      "ADMIN2136_KNOT_MODULE is not set; run in `nix develop .#e2e`",
    );
  }
  for (const d of ["zones", "run", "db"]) {
    fs.mkdirSync(path.join(dir, d), { recursive: true });
  }
  const ports = {
    knot: await freePort(),
    dows: await freePort(),
    web: await freePort(),
    relay: await freePort(),
  };
  const keys = {};
  for (const k of ["kc", "kz", "ku"]) {
    keys[k] = randomBytes(32).toString("base64");
  }
  const spec = (k) => "hmac-sha256:" + k + ":" + keys[k];

  for (const [zone, text] of Object.entries(zoneFiles())) {
    fs.writeFileSync(path.join(dir, "zones", zone + ".zone"), text);
  }
  const confFile = path.join(dir, "knot.conf");
  fs.writeFileSync(confFile, knotConf(dir, ports.knot, keys, module));

  const procs = [];
  const env = {
    dir,
    ports,
    keys,
    spec,
    origin: `http://127.0.0.1:${ports.web}`,
    proxyUrl: `ws://127.0.0.1:${ports.dows}`,
    nameserver: `127.0.0.1:${ports.knot}`,
    // the same nameserver through slowRelay()
    slowNameserver: `127.0.0.1:${ports.relay}`,
  };

  // Plain knsupdate / kdig / knotc wrappers.
  env.knsupdate = async (zone, lines, key = "kc") => {
    const input =
      `server 127.0.0.1 ${ports.knot}\nzone ${zone}.\n` +
      lines.join("\n") +
      "\nsend\nanswer\n";
    const child = spawn("knsupdate", key ? ["-y", spec(key)] : []);
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.stdin.end(input);
    const code = await new Promise((r) => child.on("close", r));
    if (code !== 0 || !/status: NOERROR/.test(out)) {
      throw new Error("knsupdate failed: " + out);
    }
    return out;
  };
  env.kdig = async (args, key = "kc") => {
    const { stdout } = await run("kdig", [
      "@127.0.0.1",
      "-p",
      String(ports.knot),
      ...(key ? ["-y", spec(key)] : []),
      ...args,
    ]);
    return stdout;
  };
  env.knotc = (...args) => run("knotc", ["-c", confFile, ...args]);

  // The zone as the server has it: [name, ttl, type, data] records
  // (relative names, "@" for the apex), the SOA once. `generic` gives the
  // rdata in RFC 3597 form.
  env.records = async (zone, key = "kc", generic = false) => {
    const out = await env.kdig(
      ["AXFR", zone, "+noall", "+answer", ...(generic ? ["+generic"] : [])],
      key,
    );
    const seen = new Set();
    const recs = [];
    for (const line of out.trim().split("\n")) {
      const f = line.trim().split(/\s+/);
      if (f.length < 5 || f[3] === "TSIG") continue;
      let name = f[0].toLowerCase();
      name = name === zone + "." ? "@" : name.slice(0, -(zone.length + 2));
      const rec = [name, f[1], f[3], f.slice(4).join(" ")];
      const soa = f[3] === "SOA" || f[3] === "TYPE6";
      if (soa && seen.has("SOA")) continue;
      if (soa) seen.add("SOA");
      recs.push(rec);
    }
    return recs;
  };
  env.serial = async (zone, key = "kc") => {
    const out = await env.kdig(["SOA", zone, "+short"], key);
    return Number(out.trim().split(/\s+/)[2]);
  };

  env.stop = async () => {
    for (const p of procs) p.kill("SIGTERM");
    if (env.relay) {
      env.relay.cut();
      env.relay.close();
    }
    if (env.web) await new Promise((r) => env.web.close(r));
    await sleep(200);
  };

  try {
    const knot = startProcess(
      "knotd",
      ["-c", confFile],
      {},
      path.join(dir, "knotd.out"),
    );
    procs.push(knot);
    await waitFor(async () => (await env.serial("catalog.test")) === 1, 15000);

    // Members: added to the catalog zone with knsupdate, which makes Knot
    // configure (and load) them according to their group.
    const lines = [];
    for (const [zone, group, id] of MEMBERS) {
      lines.push(`update add ${id}.zones.catalog.test. 0 PTR ${zone}.`);
      lines.push(`update add group.${id}.zones.catalog.test. 0 TXT "${group}"`);
    }
    await env.knsupdate("catalog.test", lines);
    const memberKey = { "own-key": "kz", "axfr-only": "kc", full: "kc" };
    for (const [zone, group] of MEMBERS) {
      await waitFor(
        async () => (await env.serial(zone, memberKey[group])) === 1,
        15000,
      );
    }
    // Some history for the zones, as after earlier edits.
    await env.knsupdate("full.example", [
      'update add seeded.full.example. 300 TXT "via knsupdate"',
    ]);
    await env.knsupdate(
      "xfr.example",
      ['update add seeded.xfr.example. 300 TXT "via knsupdate"'],
      "ku",
    );
    await env.knsupdate(
      "own.example",
      ['update add seeded.own.example. 300 TXT "via knsupdate"'],
      "kz",
    );

    // dows; restartDows() drops all WebSocket connections.
    const startDows = async () => {
      env.dows = startProcess(
        "dows",
        [`127.0.0.1:${ports.dows}`],
        {
          env: {
            ...process.env,
            DOWS_ALLOWED_UPSTREAMS: env.nameserver + "," + env.slowNameserver,
            DOWS_ALLOWED_ORIGINS: env.origin,
          },
        },
        path.join(dir, "dows.out"),
      );
      procs.push(env.dows);
      await waitFor(async () => {
        try {
          await fetch(`http://127.0.0.1:${ports.dows}/`);
          return true;
        } catch (e) {
          return false;
        }
      }, 10000);
    };
    env.stopDows = async () => {
      const old = env.dows;
      const exited = new Promise((r) => old.on("exit", r));
      old.kill("SIGKILL");
      await exited;
    };
    env.startDows = startDows;
    env.restartDows = async () => {
      await env.stopDows();
      await startDows();
    };
    await startDows();
    env.relay = await slowRelay(ports.relay, ports.knot);
    env.web = await webServer(root, ports.web);
  } catch (err) {
    await env.stop();
    throw new Error(
      err.message +
        "\nknot log:\n" +
        readTail(path.join(dir, "knot.log")) +
        readTail(path.join(dir, "knotd.out")),
    );
  }
  return env;
}

function readTail(file) {
  try {
    return fs.readFileSync(file, "utf8").split("\n").slice(-30).join("\n");
  } catch (e) {
    return "";
  }
}

async function waitFor(cond, timeout) {
  const t0 = Date.now();
  let last = null;
  for (;;) {
    try {
      if (await cond()) return;
    } catch (e) {
      last = e;
    }
    if (Date.now() - t0 > timeout) {
      throw new Error("timeout" + (last ? ": " + last.message : ""));
    }
    await sleep(100);
  }
}
