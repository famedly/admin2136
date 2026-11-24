// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// End-to-end tests: headless Chromium drives the site, which talks to
// Knot DNS through dows. Run in the e2e devshell:
//
//   nix develop .#e2e --command node test/e2e/run.mjs [options] [filter]
//
// Options:
//   --coverage DIR  write the V8 coverage of the site's scripts to DIR
//                   (see test/coverage.mjs)
//   --keep          keep the temporary directory (logs, screenshots)
// A filter runs only the tests whose name contains it.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startEnv } from "./env.mjs";
import { Browser } from "./browser.mjs";
import tests from "./tests.mjs";
import { textToRdata, parseGeneric, genericToText } from "../../js/rdata.js";
import { nameToType } from "../../js/dnswire.js";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  if (i < 0) return null;
  args.splice(i, 1);
  return name === "--keep" ? true : args.splice(i, 1)[0];
};
const coverageDir = opt("--coverage");
const keep = opt("--keep");
const filter = args[0] ?? null;

class AssertionError extends Error {}

// Helpers handed to every test as `t`.
function helpers(b, env) {
  let page = 0;
  const t = {
    b,
    env,
    ok(cond, what) {
      if (!cond) throw new AssertionError("expected: " + what);
    },
    eq(actual, expected, what) {
      const a = JSON.stringify(actual);
      const e = JSON.stringify(expected);
      if (a !== e) {
        throw new AssertionError(what + ": got " + a + ", expected " + e);
      }
    },
    text: (id) =>
      b.ev(
        `return document.getElementById(${JSON.stringify(id)}).textContent;`,
      ),
    value: (id) =>
      b.ev(`return document.getElementById(${JSON.stringify(id)}).value;`),
    visible: (id) =>
      b.ev(`const e = document.getElementById(${JSON.stringify(id)});
            return !!e && !e.hidden && e.offsetParent !== null;`),
    set: (id, value) =>
      b.ev(`const e = document.getElementById(${JSON.stringify(id)});
            e.value = ${JSON.stringify(value)};
            e.dispatchEvent(new Event("input", { bubbles: true }));
            e.dispatchEvent(new Event("change", { bubbles: true }));`),
    click: (id) =>
      b.ev(`document.getElementById(${JSON.stringify(id)}).click();`),
    status: () => t.text("status-bar"),
    // Wait for the status bar to match `re` (a RegExp source string).
    waitStatus: (re, what = re) =>
      b.wait(
        `/${re}/.test(document.getElementById("status-bar").textContent)
              && document.getElementById("status-bar").textContent`,
        what,
      ),

    // A fresh document of the site.
    async open() {
      await b.goto(`${env.origin}/?page=${++page}`);
      await b.wait(
        `document.getElementById("edit-type").options.length > 0`,
        "app ready",
      );
    },

    // Fill in and submit the login form; does not wait for the result.
    async submitLogin({
      zone,
      key = "kc",
      proxy = env.proxyUrl,
      ns = env.nameserver,
    }) {
      await t.set("proxy-url", proxy);
      await t.set("nameserver", ns);
      await t.set("zone", zone);
      await t.set("tsig", key ? env.spec(key) : "");
      await t.click("login-btn");
    },

    // Open a fresh page and log in to `zone`, waiting until it is loaded.
    async login(zone, key = "kc") {
      await t.open();
      await t.submitLogin({ zone, key });
      await b.wait(
        `document.getElementById("zone-name").textContent === ${JSON.stringify(zone + ".")}`,
        "zone view of " + zone,
      );
      await t.waitStatus("Zone loaded", "zone " + zone + " loaded");
    },

    // Rows of a list as [name, ttl, type, data] (records) or [zone,
    // group, id] (catalog zones). All rows are rendered for this.
    async rows(list = "record-list") {
      return b.ev(`
        const list = document.getElementById(${JSON.stringify(list)});
        const style = document.createElement("style");
        style.textContent = "#" + list.id + " { flex: none !important; height: 200000px !important; }";
        document.head.appendChild(style);
        await new Promise((r) => setTimeout(r, 50));
        const rows = [...list.querySelectorAll(".vlist-row")]
          .filter((r) => r.style.display !== "none")
          .sort((a, b) => parseInt(a.style.top) - parseInt(b.style.top))
          .map((r) => [...r.children].slice(0, ${list === "record-list" ? 4 : 3}).map((c) => c.textContent));
        style.remove();
        await new Promise((r) => setTimeout(r, 50));
        return rows;`);
    },

    // Click a button (by class) in the first visible row matching.
    async rowAction(list, match, cls) {
      const ok = await b.ev(`
        const list = document.getElementById(${JSON.stringify(list)});
        const style = document.createElement("style");
        style.textContent = "#" + list.id + " { flex: none !important; height: 200000px !important; }";
        document.head.appendChild(style);
        await new Promise((r) => setTimeout(r, 50));
        const match = ${JSON.stringify(match)};
        const row = [...list.querySelectorAll(".vlist-row")]
          .filter((r) => r.style.display !== "none")
          .find((r) => match.every((m, i) => m === null || r.children[i].textContent === m));
        style.remove();
        if (!row) return false;
        row.querySelector(${JSON.stringify("." + cls)}).click();
        return true;`);
      if (!ok)
        throw new AssertionError(
          "no row " + JSON.stringify(match) + " in " + list,
        );
    },

    // Record editing through the dialog. `data` etc. undefined = unchanged.
    async fillEditor({ name, ttl, type, data }) {
      if (name !== undefined) await t.set("edit-name", name);
      if (ttl !== undefined) await t.set("edit-ttl", String(ttl));
      if (type !== undefined) await t.set("edit-type", type);
      if (data !== undefined) await t.set("edit-data", data);
      await t.click("edit-save");
    },
    // Actions waiting for a status first clear it, so that the status of
    // an earlier action cannot satisfy the wait.
    clearStatus: () =>
      b.ev(`document.getElementById("status-bar").textContent = "";`),
    async addRecord(rec, expect = "^Added ") {
      await t.clearStatus();
      await t.click("add-btn");
      await t.fillEditor(rec);
      if (expect) await t.waitStatus(expect, "record added");
    },
    async editRecord(match, rec, expect = "^Updated ") {
      await t.clearStatus();
      await t.rowAction("record-list", match, "row-edit");
      await t.fillEditor(rec);
      if (expect) await t.waitStatus(expect, "record updated");
    },
    async deleteRecord(match, expect = "^Deleted ") {
      await t.clearStatus();
      await t.rowAction("record-list", match, "row-del");
      if (expect) await t.waitStatus(expect, "record deleted");
    },
    async refresh() {
      await t.clearStatus();
      await t.click("refresh-btn");
      return t.waitStatus("up to date|Updated|reloaded|✗", "refresh");
    },

    // The app shows exactly the records the server has. Both sides are
    // compared in RFC 3597 generic form, so presentation does not matter.
    // The SOA is only compared with `withSoa`: the app learns the serials
    // the server assigns to its updates with the next refresh.
    async expectInSync(zone, key = "kc", { withSoa = false } = {}) {
      const abs = (n) =>
        n === "@" ? zone + "." : n.endsWith(".") ? n : n + "." + zone + ".";
      const norm = ([name, ttl, type, data], parse) => {
        const t = nameToType(type);
        return [
          abs(name).toLowerCase(),
          String(ttl),
          t,
          genericToText(parse(t, data)),
        ].join(" ");
      };
      const keep = (r) => withSoa || nameToType(r[2]) !== 6;
      const shown = (await t.rows())
        .filter(keep)
        .map((r) => norm(r, (type, data) => textToRdata(type, data, abs)));
      const server = (await env.records(zone, key, true))
        .filter(keep)
        .map((r) => norm(r, (type, data) => parseGeneric(data)));
      shown.sort();
      server.sort();
      t.eq(shown, server, "records of " + zone + " shown vs. on the server");
    },
  };
  return t;
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "admin2136-e2e-"));
let env = null;
let b = null;
let failed = 0;
let ran = 0;
try {
  env = await startEnv(root, dir);
  b = await Browser.launch(dir);
  const t = helpers(b, env);
  for (const [name, fn] of tests) {
    if (filter && !name.includes(filter)) continue;
    ran++;
    b.errors = [];
    b.dialogs = [];
    b.acceptDialogs = true;
    const t0 = Date.now();
    try {
      await fn(t);
      if (b.errors.length)
        throw new Error("page errors:\n  " + b.errors.join("\n  "));
      console.log(`ok   ${name} (${Date.now() - t0} ms)`);
    } catch (err) {
      failed++;
      console.log(`FAIL ${name}\n     ${err.stack.replace(/\n/g, "\n     ")}`);
      await b.screenshot(path.join(dir, `fail-${ran}.png`)).catch(() => {});
    }
  }
} finally {
  if (b) await b.close();
  if (env) await env.stop();
  if (coverageDir && b) {
    // Same format as NODE_V8_COVERAGE, with the scripts' file URLs.
    fs.mkdirSync(coverageDir, { recursive: true });
    const result = b.coverage
      .filter((s) => s.url.startsWith(env.origin + "/js/"))
      .map((s) => ({
        ...s,
        url: "file://" + root + s.url.slice(env.origin.length),
      }));
    fs.writeFileSync(
      path.join(coverageDir, `browser-${process.pid}.json`),
      JSON.stringify({ result }),
    );
  }
  if (keep || failed) console.log("logs and screenshots: " + dir);
  else fs.rmSync(dir, { recursive: true, force: true });
}
console.log(`\n${ran - failed}/${ran} end-to-end tests passed`);
process.exitCode = failed ? 1 : 0;
