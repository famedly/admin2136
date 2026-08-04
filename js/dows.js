// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// DoWS (DNS over WebSocket) transport.
//
// The nameserver (with optional port) is appended as the last path component
// of the proxy URL. Each DNS message travels in exactly one WebSocket frame,
// in both directions -- there is *no* 16-bit length prefix as in DNS over TCP;
// the WebSocket framing delimits messages.

export class DowsConnection {
  constructor(proxyUrl, nameserver) {
    this.url = proxyUrl.replace(/\/*$/, "/") + encodeURIComponent(nameserver);
    this.ws = null;
    this.closed = false;
    this.closeReason = null;
    this.queue = []; // received frames not yet consumed
    this.waiters = []; // pending recv() promises
  }

  get connected() {
    return this.ws !== null && !this.closed;
  }

  connect() {
    return new Promise((resolve, reject) => {
      let ws;
      try {
        ws = new WebSocket(this.url);
      } catch (e) {
        reject(new Error('invalid WebSocket URL "' + this.url + '"'));
        return;
      }
      ws.binaryType = "arraybuffer";
      let settled = false;
      ws.onopen = () => {
        settled = true;
        this.ws = ws;
        resolve();
      };
      ws.onclose = (ev) => {
        this.closed = true;
        this.closeReason = ev.reason || "code " + ev.code;
        this._rejectWaiters(
          new Error("connection closed (" + this.closeReason + ")"),
        );
        if (!settled) {
          settled = true;
          reject(new Error("could not connect to " + this.url));
        }
      };
      ws.onmessage = (ev) => {
        if (typeof ev.data === "string") {
          console.warn("[dows] received unexpected TEXT frame:", ev.data);
          return;
        }
        const data = new Uint8Array(ev.data);
        const w = this.waiters.shift();
        console.log(
          "[dows] frame received:",
          data.length,
          "bytes,",
          w ? "delivered to waiter" : "queued (no waiter pending)",
        );
        if (w) w.resolve(data);
        else this.queue.push(data);
      };
    });
  }

  send(bytes) {
    if (!this.connected) throw new Error("not connected");
    console.log("[dows] frame sent:", bytes.length, "bytes");
    this.ws.send(bytes);
  }

  // Receive the next DNS message (one WebSocket frame).
  recv(timeoutMs = 30000) {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.closed) {
      return Promise.reject(
        new Error("connection closed (" + this.closeReason + ")"),
      );
    }
    return new Promise((resolve, reject) => {
      const w = {};
      const timer = setTimeout(() => {
        const i = this.waiters.indexOf(w);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error("timeout waiting for DNS response"));
      }, timeoutMs);
      w.resolve = (v) => {
        clearTimeout(timer);
        resolve(v);
      };
      w.reject = (e) => {
        clearTimeout(timer);
        reject(e);
      };
      this.waiters.push(w);
    });
  }

  _rejectWaiters(err) {
    const ws = this.waiters;
    this.waiters = [];
    for (const w of ws) w.reject(err);
  }

  close() {
    if (this.ws && !this.closed) this.ws.close();
  }
}
