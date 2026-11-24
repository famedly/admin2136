// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Minimal headless Chromium driver over the DevTools protocol, without
// dependencies (Node's built-in WebSocket client). Collects V8 precise
// coverage of the page's scripts.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Browser {
  static async launch(dir) {
    const profile = path.join(dir, "chromium");
    fs.mkdirSync(profile, { recursive: true });
    const log = fs.openSync(path.join(dir, "chromium.out"), "a");
    const proc = spawn(
      process.env.CHROMIUM || "chromium",
      [
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        // Fresh compilation per document: V8 would otherwise reuse the
        // scripts (and their coverage counters) across navigations, and
        // block coverage goes missing after the counters are reset.
        "--js-flags=--no-compilation-cache",
        "--remote-debugging-port=0",
        "--user-data-dir=" + profile,
        "--window-size=1200,800",
        "about:blank",
      ],
      { stdio: ["ignore", log, log] },
    );
    // Chromium writes the port it picked into the profile directory.
    const portFile = path.join(profile, "DevToolsActivePort");
    let port = null;
    for (let i = 0; i < 300 && port === null; i++) {
      try {
        port = Number(fs.readFileSync(portFile, "utf8").split("\n")[0]);
      } catch (e) {
        await sleep(100);
      }
    }
    if (!port) throw new Error("Chromium did not start");
    let page = null;
    for (let i = 0; i < 100 && !page; i++) {
      try {
        const targets = await (
          await fetch(`http://127.0.0.1:${port}/json/list`)
        ).json();
        page = targets.find((t) => t.type === "page");
      } catch (e) {
        // not ready yet
      }
      if (!page) await sleep(100);
    }
    const b = new Browser(proc, new WebSocket(page.webSocketDebuggerUrl));
    await new Promise((r, j) => {
      b.ws.addEventListener("open", r);
      b.ws.addEventListener("error", j);
    });
    await b.send("Runtime.enable");
    await b.send("Page.enable");
    await b.send("Profiler.enable");
    await b.send("Profiler.startPreciseCoverage", {
      callCount: true,
      detailed: true,
    });
    return b;
  }

  constructor(proc, ws) {
    this.proc = proc;
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.errors = []; // uncaught page exceptions
    this.dialogs = []; // [type, message] of JS dialogs shown
    this.acceptDialogs = true;
    this.coverage = []; // Profiler.takePreciseCoverage results
    this.onLoad = null;
    ws.addEventListener("message", (ev) => this._message(JSON.parse(ev.data)));
  }

  _message(m) {
    if (m.id && this.pending.has(m.id)) {
      this.pending.get(m.id)(m);
      this.pending.delete(m.id);
    } else if (m.method === "Runtime.exceptionThrown") {
      const d = m.params.exceptionDetails;
      this.errors.push(d.exception?.description ?? d.text);
    } else if (m.method === "Page.javascriptDialogOpening") {
      this.dialogs.push([m.params.type, m.params.message]);
      this.send("Page.handleJavaScriptDialog", {
        accept: this.acceptDialogs,
      });
    } else if (m.method === "Page.loadEventFired" && this.onLoad) {
      this.onLoad();
      this.onLoad = null;
    }
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const timer = setTimeout(
        () => reject(new Error("DevTools timeout: " + method)),
        20000,
      );
      this.pending.set(id, (m) => {
        clearTimeout(timer);
        if (m.error) reject(new Error(method + ": " + m.error.message));
        else resolve(m.result);
      });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  // Keep the coverage of the current document before it goes away.
  async takeCoverage() {
    const { result } = await this.send("Profiler.takePreciseCoverage");
    this.coverage.push(...result);
  }

  async goto(url) {
    await this.takeCoverage();
    const loaded = new Promise((r) => (this.onLoad = r));
    await this.send("Page.navigate", { url });
    await Promise.race([loaded, sleep(10000)]);
  }

  async reload() {
    await this.takeCoverage();
    const loaded = new Promise((r) => (this.onLoad = r));
    await this.send("Page.reload");
    await Promise.race([loaded, sleep(10000)]);
  }

  // Evaluate the body of an async function in the page.
  async ev(body) {
    const r = await this.send("Runtime.evaluate", {
      expression: "(async () => {\n" + body + "\n})()",
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error(
        "page: " +
          (r.exceptionDetails.exception?.description ??
            r.exceptionDetails.text),
      );
    }
    return r.result.value;
  }

  // Wait until the expression is truthy; returns its value.
  async wait(expr, what = expr, timeout = 10000) {
    const t0 = Date.now();
    for (;;) {
      const v = await this.ev("return (" + expr + ");").catch(() => null);
      if (v) return v;
      if (Date.now() - t0 > timeout) {
        throw new Error("timeout waiting for " + what);
      }
      await sleep(50);
    }
  }

  // Slow down the page by `rate` (1 = normal speed).
  async throttle(rate) {
    await this.send("Emulation.setCPUThrottlingRate", { rate });
  }

  async screenshot(file) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(file, Buffer.from(r.data, "base64"));
  }

  async close() {
    try {
      await this.takeCoverage();
    } catch (e) {
      // browser already gone
    }
    this.ws.close();
    this.proc.kill("SIGTERM");
  }
}
