// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// admin2136 application glue: login, record list, editing via RFC 2136,
// catalog zone browsing.

import { DowsConnection } from "./dows.js";
import {
  axfr,
  ixfr,
  query,
  sendUpdate,
  isRejection,
  DnsError,
  RCODE_FORMERR,
  RCODE_NOTIMP,
  RCODE_NXRRSET,
} from "./dnsops.js";
import { parseTsigSpec } from "./tsig.js";
import { ZoneStore } from "./zonestore.js";
import { VirtualList } from "./vlist.js";
import {
  rdataToText,
  textToRdata,
  soaSerial,
  isEditableType,
  typeHint,
  ADDABLE_TYPES,
  soaFields,
  soaRdata,
  mergeSoa,
} from "./rdata.js";
import {
  parseCatalog,
  newMemberId,
  memberRecords,
  addUpdates,
  deleteMemberUpdates,
} from "./catalog.js";
import {
  nameToWire,
  typeToName,
  nameToType,
  TYPE_SOA,
  CLASS_IN,
  CLASS_NONE,
} from "./dnswire.js";

const $ = (id) => document.getElementById(id);

const ROW_HEIGHT = 30;
const SETTINGS_KEY = "admin2136-settings";

let conn = null; // DowsConnection shared by all zone sessions
let connecting = null; // pending reconnect, see getConn()
let settings = { proxy: "", ns: "" };
let vlist = null; // VirtualList of records
let zlist = null; // VirtualList of catalog member zones
// The record being edited as returned by ZoneStore.get() (not its index: a
// refresh may move or replace the records while the dialog is open; the
// rdata view stays valid), or null for "add".
let editOld = null;

// One session per opened zone. The zone opened at login has depth 0, a
// zone opened from a catalog one more than the catalog. A session's depth
// is also its index in `sessions` and identifies its history entry.
let sessions = [];
let cur = null; // session shown in the zone view

function newSession(zone, tsigKey, depth) {
  return {
    depth,
    store: new ZoneStore(zone),
    tsigKey, // parsed TSIG key or null
    updateKey: undefined, // separate key for updates; undefined = tsigKey
    order: new Uint32Array(0), // display order -> arena record index
    view: null, // null = show all of `order`, else filtered record indices
    catalog: null, // parseCatalog() result, null if not a catalog zone
    zoneView: [], // catalog members matching the filter
    showRaw: false, // show raw records instead of the catalog's zones
    filter: "",
    loadingSerial: null, // serial shown while the initial load runs
    opening: false, // a member zone is being opened from this catalog
    status: { text: "", cls: "" },
    scroll: { records: 0, zones: 0 },
  };
}

// ---- helpers ----

// Set the status bar text of session `s`; shown right away if `s` is the
// current session, otherwise when it is navigated to.
function setStatus(s, text, cls = "") {
  s.status = { text, cls };
  if (s !== cur) return;
  const el = $("status-bar");
  el.textContent = text;
  el.className = cls;
}

function displayName(rel) {
  return rel === "" ? "@" : rel;
}

function showsZones(s) {
  return s.catalog !== null && !s.showRaw;
}

// Map a DoWS proxy WebSocket URL to the corresponding HTTP(S) URL where the
// proxy serves its info page, or null if it is not a valid ws:// / wss:// URL.
function proxyHttpUrl(wsUrl) {
  let u;
  try {
    u = new URL(wsUrl);
  } catch (e) {
    return null;
  }
  if (u.protocol === "ws:") u.protocol = "http:";
  else if (u.protocol === "wss:") u.protocol = "https:";
  else return null;
  return u.href;
}

// ---- connection ----

// The shared connection, reconnecting if it was closed in the meantime.
function getConn() {
  if (conn && conn.connected) return Promise.resolve(conn);
  if (!connecting) {
    const c = new DowsConnection(settings.proxy, settings.ns);
    connecting = c
      .connect()
      .then(() => {
        conn = c;
        return c;
      })
      .finally(() => {
        connecting = null;
      });
  }
  return connecting;
}

// Run `fn(c)` on connection `c` once all operations queued on it before
// have finished. Responses are matched to requests by reading the next
// messages from the connection, so two operations must never overlap.
function runOn(c, fn) {
  const p = (c.opQueue ?? Promise.resolve()).then(() => fn(c));
  c.opQueue = p.catch(() => {});
  return p;
}

async function withConn(fn) {
  return runOn(await getConn(), fn);
}

// ---- TSIG keys ----

// Parse a "hmac-sha256:keyname:base64secret" input; empty means no key.
function parseKeyInput(spec) {
  spec = spec.trim();
  if (!spec) return null;
  if (!(crypto && crypto.subtle)) {
    throw new Error(
      "Web Crypto unavailable; serve this page via https:// or from localhost",
    );
  }
  return parseTsigSpec(spec);
}

let keyPrompt = null; // { attempt, resolve } of the open key dialog
let keyTrying = false; // an attempt of the key dialog is in flight

// Ask for a TSIG key and call `attempt(key)` with it until that succeeds
// (resolves true) or the user gives up (resolves false). Errors thrown by
// `attempt` are shown in the dialog, which stays open for another try.
function askKey({ title, message, submit, attempt }) {
  if (keyPrompt) return Promise.resolve(false);
  return new Promise((resolve) => {
    keyPrompt = { attempt, resolve };
    $("key-title").textContent = title;
    $("key-message").textContent = message;
    $("key-submit").textContent = submit;
    $("key-input").value = "";
    $("key-status").textContent = "";
    $("key-dialog").showModal();
  });
}

// Close the key dialog and settle its prompt.
function endKeyPrompt(ok) {
  const prompt = keyPrompt;
  keyPrompt = null;
  if ($("key-dialog").open) $("key-dialog").close();
  if (prompt) prompt.resolve(ok);
}

$("key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = $("key-status");
  try {
    keyTrying = true;
    $("key-submit").disabled = true;
    $("key-cancel").disabled = true;
    const key = parseKeyInput($("key-input").value);
    status.textContent = "Trying…";
    await keyPrompt.attempt(key);
    endKeyPrompt(true);
  } catch (err) {
    status.textContent = "✗ " + err.message;
  } finally {
    keyTrying = false;
    $("key-submit").disabled = false;
    $("key-cancel").disabled = false;
  }
});

$("key-cancel").addEventListener("click", () => endKeyPrompt(false));

// Escape gives up as well, but not while an attempt is in flight: its
// outcome is still to be reported to the caller.
$("key-dialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  if (!keyTrying) endKeyPrompt(false);
});

// Closed by history navigation (which closes all dialogs): give up. The
// event is dispatched asynchronously, so the dialog may already have been
// reopened for another prompt by now; that one must not be affected.
$("key-dialog").addEventListener("close", () => {
  if (!$("key-dialog").open) endKeyPrompt(false);
});

function updateKeyOf(s) {
  return s.updateKey !== undefined ? s.updateKey : s.tsigKey;
}

// Send an RFC 2136 update for the zone of session `s`. If the server
// rejects it (the key used for the transfer may lack update permission),
// offer to enter a separate TSIG key for updates of this zone; on success
// that key is used for all further updates of the zone.
async function performUpdate(s, updates, prereqs = []) {
  const zone = s.store.zoneFqdn;
  const send = (key) =>
    withConn((c) => sendUpdate(c, zone, key, updates, prereqs));
  try {
    await send(updateKeyOf(s));
  } catch (err) {
    if (!isRejection(err)) throw err;
    // An error that is not a rejection means the key was accepted; it
    // ends the prompt and is reported like any other update failure.
    let failure = null;
    const ok = await askKey({
      title: "Update rejected",
      message:
        "The server rejected the update of " +
        zone +
        " (" +
        err.message +
        "). Enter a TSIG key for updates of this zone to retry.",
      submit: "Retry update",
      attempt: async (key) => {
        try {
          await send(key);
        } catch (e) {
          if (isRejection(e)) throw e;
          failure = e;
        }
        s.updateKey = key;
      },
    });
    if (!ok) throw err;
    if (failure) throw failure;
  }
}

// ---- loading ----

// Transfer the zone of session `s` into a fresh store; the session's store
// is only replaced on success so a failed reload does not lose the working
// copy. Uses connection `c` if given, else the shared one.
async function transferZone(s, progress, c = null) {
  const fresh = new ZoneStore(s.store.zone);
  let n = 0;
  const run = (c) =>
    axfr(c, fresh.zoneFqdn, s.tsigKey, (rr) => {
      fresh.add(fresh.relativize(rr.name), rr.type, rr.ttl, rr.rdata);
      if (rr.type === TYPE_SOA) {
        fresh.serial = soaSerial(rr.rdata);
        fresh.syncSoa = { ttl: rr.ttl, rdata: rr.rdata };
      }
      // Report the very first record immediately (it signals that the
      // server accepted the request), then every 1024 records. The serial
      // is known from the first record on, since an AXFR starts with the
      // SOA.
      if (++n === 1 || (n & 1023) === 0) progress(n, fresh.serial);
    });
  await (c ? runOn(c, run) : withConn(run));
  fresh.markSynced();
  s.store = fresh;
}

// Start the initial load of session `s`. The returned promise resolves as
// soon as the first record arrived, right after `onStarted()` was called
// (which typically switches to the zone view), and rejects if the transfer
// fails before that. Later failures and the completion are reported in the
// session's status bar.
function startLoad(s, onStarted, c = null) {
  return new Promise((resolve, reject) => {
    let started = false;
    const start = () => {
      if (started) return;
      started = true;
      onStarted();
      resolve();
    };
    transferZone(
      s,
      (n, serial) => {
        s.loadingSerial = serial;
        start();
        if (s === cur) updateMeta();
        setStatus(s, "Transferring zone… " + n + " records");
      },
      c,
    ).then(
      () => {
        start();
        s.loadingSerial = null;
        rebuild(s);
        setStatus(
          s,
          "Zone loaded via AXFR (" + s.store.count + " records).",
          "ok",
        );
      },
      (err) => {
        if (!started) {
          reject(err);
          return;
        }
        s.loadingSerial = null;
        setStatus(s, "✗ zone transfer failed: " + err.message, "error");
      },
    );
  });
}

// ---- views ----

// Rebuild the indirection array used for display: it starts as the identity
// sequence 0..n over the arena records and is sorted with the store's
// comparator (revname, type, ttl). Rows never move in the arena; only this
// array determines what the list shows where. Must be called after every
// store mutation (load, add, edit, delete), see rebuild().
function rebuildOrder(s) {
  const n = s.store.count;
  const order = new Uint32Array(n);
  for (let i = 0; i < n; i++) order[i] = i;
  order.sort((a, b) => s.store.compareRecords(a, b));
  s.order = order;
}

// Recompute everything derived from the store of session `s`.
function rebuild(s) {
  rebuildOrder(s);
  s.catalog = parseCatalog(s.store);
  applyFilter(s);
}

// Apply the session's filter to the list it currently shows.
function applyFilter(s) {
  const q = s.filter.trim().toLowerCase();
  if (showsZones(s)) {
    s.zoneView = !q
      ? s.catalog.members
      : s.catalog.members.filter(
          (m) =>
            m.zone.toLowerCase().includes(q) ||
            m.id.toLowerCase().includes(q) ||
            (m.group ?? "").toLowerCase().includes(q),
        );
  } else if (!q) {
    s.view = null;
  } else {
    // Filter in display order so `view` stays sorted as well.
    const v = [];
    for (const idx of s.order) {
      const r = s.store.get(idx);
      if (
        displayName(r.name).toLowerCase().includes(q) ||
        typeToName(r.type).toLowerCase().includes(q) ||
        rdataToText(r.type, r.rdata).toLowerCase().includes(q)
      ) {
        v.push(idx);
      }
    }
    s.view = v;
  }
  if (s === cur) render();
}

function updateMeta() {
  const s = cur;
  let meta;
  if (s.loadingSerial !== null) {
    meta = "serial " + s.loadingSerial;
  } else {
    meta = "serial " + (s.store.serial ?? "?") + " · ";
    meta += s.catalog
      ? "catalog of " + s.catalog.members.length + " zones"
      : s.store.count + " records";
  }
  $("zone-meta").textContent = meta;
}

// Bring the zone view in line with the current session.
function render() {
  const s = cur;
  const zones = showsZones(s);
  $("zone-view").classList.toggle("catalog-mode", zones);
  $("raw-btn").hidden = s.catalog === null;
  $("raw-btn").setAttribute("aria-pressed", String(s.showRaw));
  $("add-btn").textContent = zones ? "+ Add zone" : "+ Add record";
  $("filter").placeholder = zones ? "Filter zones…" : "Filter records…";
  updateMeta();
  if (zones) zlist.setCount(s.zoneView.length);
  else vlist.setCount(s.view ? s.view.length : s.order.length);
}

// Show session `s` in the zone view.
function showSession(s) {
  if (cur) {
    cur.scroll = {
      records: $("record-list").scrollTop,
      zones: $("zone-list").scrollTop,
    };
  }
  cur = s;
  if (!vlist) {
    vlist = new VirtualList($("record-list"), ROW_HEIGHT, renderRow);
    zlist = new VirtualList($("zone-list"), ROW_HEIGHT, renderZoneRow);
  }
  $("zone-name").textContent = s.store.zoneFqdn;
  $("filter").value = s.filter;
  render();
  $("record-list").scrollTop = s.scroll.records;
  $("zone-list").scrollTop = s.scroll.zones;
  setStatus(s, s.status.text, s.status.cls);
}

// Switch to session `s` and give it its own history entry, so the browser
// back button returns to where it was opened from (and forward returns
// here). Sessions deeper than `s` are dropped, as are their (now
// unreachable) forward history entries by pushState().
function enterSession(s) {
  sessions.length = s.depth;
  sessions.push(s);
  showZoneView();
  showSession(s);
  history.pushState({ view: "zone", depth: s.depth }, "");
}

// ---- record list ----

function buildRow(el) {
  el.classList.add("record-grid");
  const mk = (cls) => {
    const s = document.createElement("span");
    s.className = cls;
    el.appendChild(s);
    return s;
  };
  const c = {
    name: mk("c-name"),
    ttl: mk("c-ttl"),
    type: mk("c-type"),
    data: mk("c-data"),
    actions: mk("c-actions"),
  };
  c.edit = document.createElement("button");
  c.edit.className = "row-edit";
  c.edit.textContent = "✎";
  c.edit.title = "Edit record";
  c.edit.addEventListener("click", () => openEditor(el._rec));
  c.del = document.createElement("button");
  c.del.className = "row-del";
  c.del.textContent = "✕";
  c.del.title = "Delete record";
  c.del.addEventListener("click", () => deleteRecord(el._rec));
  c.actions.append(c.edit, c.del);
  el._c = c;
}

function renderRow(i, el) {
  if (!el._c) buildRow(el);
  // Translate the DOM row index to an arena record index via the sorted
  // indirection array (or the filtered subset of it).
  const rec = cur.view ? cur.view[i] : cur.order[i];
  el._rec = rec;
  const r = cur.store.get(rec);
  const c = el._c;
  const data = rdataToText(r.type, r.rdata);
  c.name.textContent = displayName(r.name);
  c.ttl.textContent = r.ttl;
  c.type.textContent = typeToName(r.type);
  c.data.textContent = data;
  c.data.title = data;
  const editable = isEditableType(r.type);
  c.edit.disabled = !editable;
  c.del.disabled = r.type === TYPE_SOA;
  el.classList.toggle("readonly", !editable);
}

// ---- catalog zone list ----

function buildZoneRow(el) {
  el.classList.add("zone-grid");
  const mk = (tag, cls) => {
    const s = document.createElement(tag);
    s.className = cls;
    el.appendChild(s);
    return s;
  };
  const c = {
    zone: mk("button", "c-zone"),
    group: mk("span", "c-group"),
    id: mk("span", "c-id"),
    actions: mk("span", "c-actions"),
  };
  c.zone.title = "Open zone";
  c.zone.addEventListener("click", () => openMember(el._member));
  c.open = document.createElement("button");
  c.open.className = "row-open";
  c.open.textContent = "→";
  c.open.title = "Open zone";
  c.open.addEventListener("click", () => openMember(el._member));
  c.del = document.createElement("button");
  c.del.className = "row-del";
  c.del.textContent = "✕";
  c.del.title = "Remove zone from catalog";
  c.del.addEventListener("click", () => deleteMember(el._member));
  c.actions.append(c.open, c.del);
  el._c = c;
}

function renderZoneRow(i, el) {
  if (!el._c) buildZoneRow(el);
  const m = cur.zoneView[i];
  el._member = m;
  const c = el._c;
  c.zone.textContent = m.zone;
  c.group.textContent = m.group ?? "";
  c.group.title = m.group ?? "";
  c.id.textContent = m.id;
  c.id.title = m.id;
}

$("raw-btn").addEventListener("click", () => {
  cur.showRaw = !cur.showRaw;
  applyFilter(cur);
});

// Open a member zone of the current (catalog) session in a new session.
// The view switches once the zone transfer got going; until then the
// catalog stays visible. The member zone is first tried with the
// catalog's transfer key; if the server refuses the transfer, the user may
// enter another one. Other failures (e.g. no connection) do not depend on
// the key and are only reported.
async function openMember(m) {
  const parent = cur;
  if (parent.opening) return;
  parent.opening = true;
  const s = newSession(m.zone, parent.tsigKey, parent.depth + 1);
  const onStarted = () => {
    // Do not navigate away if the user left the catalog meanwhile.
    if (cur !== parent || $("zone-view").hidden) return;
    setStatus(parent, "");
    enterSession(s);
  };
  setStatus(parent, "Opening " + m.zone + "…");
  try {
    await startLoad(s, onStarted);
  } catch (err) {
    setStatus(
      parent,
      "✗ opening " + m.zone + " failed: " + err.message,
      "error",
    );
    if (!isRejection(err)) return;
    await askKey({
      title: "Transfer refused",
      message:
        "The server refused the transfer of " +
        m.zone +
        " (" +
        err.message +
        "). Enter a TSIG key for this zone to retry.",
      submit: "Open zone",
      attempt: async (key) => {
        s.tsigKey = key;
        await startLoad(s, onStarted);
      },
    });
  } finally {
    parent.opening = false;
  }
}

async function deleteMember(m) {
  const s = cur;
  if (!confirm("Remove " + m.zone + " from the catalog?")) return;
  try {
    setStatus(s, "Removing " + m.zone + "…");
    const updates = deleteMemberUpdates(s.store, m);
    await performUpdate(s, updates);
    // A refresh during the update may have moved the records, or replaced
    // s.store; find each deleted record again by its contents.
    const store = s.store;
    for (const u of updates) {
      const i = store.indexOf(store.relativize(u.name), u.type, u.rdata);
      if (i >= 0) store.remove(i);
    }
    rebuild(s);
    setStatus(s, "Removed " + m.zone + " from the catalog.", "ok");
  } catch (err) {
    setStatus(s, "✗ removing " + m.zone + " failed: " + err.message, "error");
  }
}

function openZoneDialog() {
  $("zone-status").textContent = "";
  $("zone-new-name").value = "";
  $("zone-new-group").value = "";
  $("zone-dialog").showModal();
}

$("zone-cancel").addEventListener("click", () => $("zone-dialog").close());

$("zone-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const s = cur;
  const status = $("zone-status");
  const btn = $("zone-save");
  try {
    btn.disabled = true;
    status.textContent = "";
    const zone =
      $("zone-new-name").value.trim().toLowerCase().replace(/\.+$/, "") + ".";
    if (zone === ".") throw new Error("zone name must not be empty");
    nameToWire(zone); // validate
    if (s.catalog.members.some((m) => m.zone.toLowerCase() === zone)) {
      throw new Error(zone + " is already in the catalog");
    }
    const group = $("zone-new-group").value.trim();
    const recs = memberRecords(zone, newMemberId(s.catalog), group);
    const updates = addUpdates(s.store, recs);

    status.textContent = "Sending update…";
    await performUpdate(s, updates);
    for (const r of recs) s.store.add(r.name, r.type, r.ttl, r.rdata);

    $("zone-dialog").close();
    rebuild(s);
    setStatus(s, "Added " + zone + " to the catalog.", "ok");
  } catch (err) {
    status.textContent = "✗ " + err.message;
  } finally {
    btn.disabled = false;
  }
});

// ---- login ----

// Keep the "About proxy" link under the proxy URL field in sync with the
// input; without a valid ws(s):// URL the link is hidden (an <a> without
// href is not focusable, and CSS hides it while reserving its space).
function updateProxyAboutLink() {
  const link = $("proxy-about-link");
  const url = proxyHttpUrl($("proxy-url").value.trim());
  if (url) link.href = url;
  else link.removeAttribute("href");
}

$("proxy-url").addEventListener("input", updateProxyAboutLink);

function validateNameserver() {
  const input = $("nameserver");
  let msg = "Expected host[:port]";
  try {
    let url = new URL("test://" + input.value);
    if (decodeURIComponent(url.host) == input.value) {
      msg = "";
    }
  } catch (e) {
    // ignore the error
  }
  input.setCustomValidity(msg);
}

$("nameserver").addEventListener("input", validateNameserver);

function restoreSettings() {
  try {
    const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    if (s.proxy) $("proxy-url").value = s.proxy;
    if (s.ns) $("nameserver").value = s.ns;
    if (s.zone) $("zone").value = s.zone;
  } catch (e) {
    /* ignore */
  }
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = $("login-status");
  const btn = $("login-btn");
  const proxy = $("proxy-url").value.trim();
  const ns = $("nameserver").value.trim();
  const zone = $("zone").value.trim().toLowerCase().replace(/\.$/, "");

  // A fresh connection; the sessions of a previous login (still reachable
  // via the forward button) keep theirs until this login succeeded.
  let c = null;
  try {
    btn.disabled = true;
    status.textContent = "";
    const tsigKey = parseKeyInput($("tsig").value);
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ proxy, ns, zone }));

    status.textContent = "Connecting to " + ns + "…";
    c = new DowsConnection(proxy, ns);
    await c.connect();

    status.textContent = "Transferring zone…";
    const s = newSession(zone, tsigKey, 0);
    // The login conceptually ends with the first successful DNS message:
    // switch to the zone view right away and let the rest of the AXFR
    // report its progress in the bottom status bar, like a reload does.
    await startLoad(
      s,
      () => {
        if (conn && conn !== c) conn.close();
        conn = c;
        settings = { proxy, ns };
        enterSession(s);
      },
      c,
    );
  } catch (err) {
    status.textContent = "✗ " + err.message;
    if (c && c !== conn) c.close();
  } finally {
    btn.disabled = false;
  }
});

// Toggle between the login form and the zone view without touching any
// state (connection, sessions, form inputs); used both by login and by
// history navigation.
function showZoneView() {
  $("login-view").hidden = true;
  $("zone-view").hidden = false;
  $("toolbar").classList.add("zone-active");
}

function showLoginView() {
  $("zone-view").hidden = true;
  $("login-view").hidden = false;
  $("toolbar").classList.remove("zone-active");
}

// ---- history navigation ----

const LOGIN_FIELDS = ["proxy-url", "nameserver", "zone", "tsig"];

// Login form input values captured when the user navigates back from the
// zone view; navigating forward restores exactly this snapshot.
let loginSnapshot = null;

window.addEventListener("popstate", (e) => {
  // Dialogs belong to the view being left.
  for (const d of document.querySelectorAll("dialog[open]")) d.close();
  if (e.state && e.state.view === "zone") {
    // Forward to a zone view, or back to a catalog. The connection and
    // sessions are kept alive while on the login screen, so nothing needs
    // to be reloaded.
    const s = sessions[e.state.depth];
    if (!s) {
      // No session behind this entry (it belongs to a previous page load);
      // bounce off it so the back button keeps working past it.
      history.forward();
      return;
    }
    if (loginSnapshot && !$("login-view").hidden) {
      for (const id of LOGIN_FIELDS) $(id).value = loginSnapshot[id];
      updateProxyAboutLink();
      validateNameserver();
    }
    showZoneView();
    showSession(s);
  } else {
    // Back to the login form: keep all inputs as they are, but remember
    // them so forward can undo any edits made in the meantime.
    if ($("login-view").hidden) {
      loginSnapshot = {};
      for (const id of LOGIN_FIELDS) loginSnapshot[id] = $(id).value;
    }
    $("login-status").textContent = "";
    showLoginView();
  }
});

// ---- refresh ----

// Bring the store of session `s` up to date with the server: incrementally
// via IXFR (RFC 1995) from the version last transferred, else by a full
// transfer. Returns a description of what happened.
async function refreshZone(s, progress) {
  const old = s.store;
  const full = async (how) => {
    await transferZone(s, progress);
    return (
      "Zone reloaded " +
      how +
      " (" +
      s.store.count +
      " records, serial " +
      s.store.serial +
      ")."
    );
  };
  if (!old.syncSoa) return full("via AXFR");

  const fresh = new ZoneStore(old.zone);
  let res;
  try {
    res = await withConn((c) =>
      ixfr(
        c,
        old.zoneFqdn,
        s.tsigKey,
        old.syncSoa,
        (rr) => fresh.add(fresh.relativize(rr.name), rr.type, rr.ttl, rr.rdata),
        progress,
      ),
    );
  } catch (err) {
    // Servers without IXFR support answer NOTIMP or FORMERR.
    const unsupported =
      err instanceof DnsError &&
      (err.rcode === RCODE_NOTIMP || err.rcode === RCODE_FORMERR);
    if (!unsupported) throw err;
    return full("via AXFR, IXFR is not supported");
  }

  const from = soaSerial(old.syncSoa.rdata);
  const to = soaSerial(res.soa.rdata);
  switch (res.kind) {
    case "uptodate":
      // A server whose version is older than ours (e.g. after the zone
      // was recreated) answers like this as well; only a full transfer
      // gets us back in sync then.
      if (to !== from) return full("via AXFR, server serial went back");
      // Nothing changed on the server since the last transfer, so any
      // local edit is one the server acknowledged but did not apply.
      return old.revertToSynced()
        ? "Zone is up to date (serial " +
            to +
            "); discarded local changes the server did not apply."
        : "Zone is up to date (serial " + to + ").";
    case "full":
      fresh.serial = to;
      fresh.syncSoa = { ttl: res.soa.ttl, rdata: res.soa.rdata };
      fresh.markSynced();
      s.store = fresh;
      return (
        "Zone reloaded, the server sent the full zone (" +
        fresh.count +
        " records, serial " +
        to +
        ")."
      );
    default: {
      // The differences are applied to the zone contents of the last
      // transfer, not to the locally edited store, see applyChanges().
      if (!old.applyChanges(res.changes, res.soa)) {
        return full("via AXFR, the IXFR did not match the last transfer");
      }
      const added = res.changes.filter((c) => c.op === "add").length;
      const deleted = res.changes.length - added;
      const records = (n) => n + (n === 1 ? " record" : " records");
      return (
        "Updated via IXFR (serial " +
        from +
        " → " +
        to +
        "): " +
        (res.changes.length
          ? records(added) + " added, " + records(deleted) + " deleted."
          : "only the SOA changed.")
      );
    }
  }
}

$("refresh-btn").addEventListener("click", async () => {
  const s = cur;
  const btn = $("refresh-btn");
  try {
    btn.disabled = true;
    setStatus(s, "Reloading zone…");
    const msg = await refreshZone(s, (n) =>
      setStatus(s, "Reloading zone… " + n + " records"),
    );
    rebuild(s);
    setStatus(s, msg, "ok");
  } catch (err) {
    setStatus(s, "✗ reload failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

// ---- filtering ----

let filterTimer = null;
$("filter").addEventListener("input", () => {
  const s = cur;
  s.filter = $("filter").value;
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => applyFilter(s), 150);
});

// ---- editing ----

// The SOA can only be edited in place: it is not offered for adding, and
// its owner name and type are locked while it is edited.
const soaOption = document.createElement("option");
soaOption.textContent = "SOA";

function openEditor(rec) {
  editOld = rec === null ? null : cur.store.get(rec);
  $("edit-status").textContent = "";
  const isSoa = editOld !== null && editOld.type === TYPE_SOA;
  if (isSoa) $("edit-type").appendChild(soaOption);
  else soaOption.remove();
  $("edit-name").disabled = isSoa;
  $("edit-type").disabled = isSoa;
  if (rec === null) {
    $("edit-title").textContent = "Add record";
    $("edit-name").value = "";
    $("edit-ttl").value = "3600";
    $("edit-type").value = "A";
    $("edit-data").value = "";
  } else {
    const r = editOld;
    $("edit-title").textContent = isSoa ? "Edit SOA record" : "Edit record";
    $("edit-name").value = displayName(r.name);
    $("edit-ttl").value = r.ttl;
    $("edit-type").value = typeToName(r.type);
    $("edit-data").value = rdataToText(r.type, r.rdata);
  }
  updateDataHint();
  $("edit-dialog").showModal();
}

function updateDataHint() {
  $("edit-data").placeholder = typeHint(nameToType($("edit-type").value));
}

for (const t of ADDABLE_TYPES) {
  const opt = document.createElement("option");
  opt.textContent = typeToName(t);
  $("edit-type").appendChild(opt);
}
$("edit-type").addEventListener("change", updateDataHint);

$("add-btn").addEventListener("click", () => {
  if (showsZones(cur)) openZoneDialog();
  else openEditor(null);
});
$("edit-cancel").addEventListener("click", () => $("edit-dialog").close());

$("edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const s = cur;
  const old = editOld;
  // For parsing only: after an await, s.store may be another store.
  const store = s.store;
  const status = $("edit-status");
  const btn = $("edit-save");
  try {
    btn.disabled = true;
    status.textContent = "";

    const rawName = $("edit-name").value.trim();
    const nameRel =
      rawName === "" || rawName === "@"
        ? ""
        : store.relativize(store.absolutize(rawName));
    const ttl = parseInt($("edit-ttl").value, 10);
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 0x7fffffff) {
      throw new Error("invalid TTL");
    }
    const type = nameToType($("edit-type").value);
    if (type === null) throw new Error("unknown record type");
    const rdata = textToRdata(type, $("edit-data").value, (n) =>
      store.absolutize(n),
    );
    const nameAbs = store.absolutize(nameRel);

    if (type === TYPE_SOA) {
      status.textContent = "Sending update…";
      const soa = await updateSoa(s, old, ttl, rdata);
      $("edit-dialog").close();
      if (!soa) {
        setStatus(s, "SOA record unchanged.");
        return;
      }
      const live = s.store;
      const i = live.findName("").find((i) => live.get(i).type === TYPE_SOA);
      if (i === undefined) live.add("", TYPE_SOA, soa.ttl, soa.rdata);
      else live.replace(i, "", TYPE_SOA, soa.ttl, soa.rdata);
      live.serial = soaSerial(soa.rdata);
      rebuild(s);
      setStatus(s, "Updated SOA record (serial " + live.serial + ").", "ok");
      return;
    }

    const updates = [];
    if (old !== null) {
      updates.push({
        name: store.absolutize(old.name),
        type: old.type,
        cls: CLASS_NONE,
        ttl: 0,
        rdata: old.rdata,
      });
    }
    updates.push({ name: nameAbs, type, cls: CLASS_IN, ttl, rdata });

    status.textContent = "Sending update…";
    await performUpdate(s, updates);

    // Apply the same change to the current store, by contents: a refresh
    // may have moved the old record or dropped it, and the new one may
    // already be present.
    const live = s.store;
    if (old !== null) {
      const i = live.indexOf(old.name, old.type, old.rdata);
      if (i >= 0) live.remove(i);
    }
    const j = live.indexOf(nameRel, type, rdata);
    if (j >= 0) live.replace(j, nameRel, type, ttl, rdata);
    else live.add(nameRel, type, ttl, rdata);

    $("edit-dialog").close();
    rebuild(s);
    setStatus(
      s,
      (old !== null ? "Updated " : "Added ") +
        displayName(nameRel) +
        " " +
        typeToName(type) +
        " record.",
      "ok",
    );
  } catch (err) {
    status.textContent = "✗ " + err.message;
  } finally {
    btn.disabled = false;
  }
});

const SOA_ATTEMPTS = 5;

// Change the SOA record `old` ({ ttl, rdata } as the user saw it) of
// session `s` to `ttl` and `rdata`, whose serial must be left as is: the
// serial is incremented here, since servers
// silently ignore SOA updates that do not increase it. A concurrent update
// may have increased the serial meanwhile, which would also make this
// update be ignored silently. Hence the update carries the SOA it is based
// on as prerequisite (RFC 2136 Section 2.4.2, "RRset exists (value
// dependent)"); if that fails, the current SOA is fetched, the user's
// changes are merged onto it and the update is retried.
//
// Returns the new { ttl, rdata }, or null if nothing was changed.
async function updateSoa(s, old, ttl, rdata) {
  const base = soaFields(old.rdata);
  const edited = soaFields(rdata);
  if (edited.serial !== base.serial) {
    throw new Error(
      "the serial is incremented automatically; leave it at " + base.serial,
    );
  }
  if (ttl === old.ttl && soaRdata(edited).join() === soaRdata(base).join()) {
    return null;
  }
  const apex = s.store.zoneFqdn;
  let current = { ttl: old.ttl, rdata: old.rdata.slice() };
  for (let attempt = 1; ; attempt++) {
    const next = {
      ttl: ttl !== old.ttl ? ttl : current.ttl,
      rdata: soaRdata(mergeSoa(base, edited, soaFields(current.rdata))),
    };
    const updates = [{ name: apex, type: TYPE_SOA, cls: CLASS_IN, ...next }];
    const prereqs = [
      {
        name: apex,
        type: TYPE_SOA,
        cls: CLASS_IN,
        ttl: 0,
        rdata: current.rdata,
      },
    ];
    try {
      await performUpdate(s, updates, prereqs);
      return next;
    } catch (err) {
      const raced = err instanceof DnsError && err.rcode === RCODE_NXRRSET;
      if (!raced || attempt === SOA_ATTEMPTS) throw err;
      const answers = await withConn((c) =>
        query(c, apex, TYPE_SOA, s.tsigKey),
      );
      const soa = answers.find((rr) => rr.type === TYPE_SOA);
      if (!soa) throw new Error("the zone has no SOA record");
      current = { ttl: soa.ttl, rdata: soa.rdata };
    }
  }
}

async function deleteRecord(rec) {
  const s = cur;
  const r = s.store.get(rec); // rec is stale after an await, r is not
  const what = displayName(r.name) + " " + typeToName(r.type);
  if (
    !confirm("Delete " + what + " record?\n\n" + rdataToText(r.type, r.rdata))
  )
    return;
  try {
    setStatus(s, "Deleting " + what + "…");
    const updates = [
      {
        name: s.store.absolutize(r.name),
        type: r.type,
        cls: CLASS_NONE,
        ttl: 0,
        rdata: r.rdata,
      },
    ];
    await performUpdate(s, updates);
    // A refresh during the update may have moved the record, or replaced
    // s.store; find it again by its contents.
    const i = s.store.indexOf(r.name, r.type, r.rdata);
    if (i >= 0) s.store.remove(i);
    rebuild(s);
    setStatus(s, "Deleted " + what + " record.", "ok");
  } catch (err) {
    setStatus(s, "✗ delete failed: " + err.message, "error");
  }
}

// ---- about ----

$("about-btn").addEventListener("click", () => {
  // Once logged in, link to the info page of the connected proxy; the
  // connection URL includes the nameserver endpoint path segment.
  const url = $("login-view").hidden && conn ? proxyHttpUrl(conn.url) : null;
  $("about-proxy").hidden = url === null;
  if (url) $("about-proxy-link").href = url;
  $("about-dialog").showModal();
});
$("about-close").addEventListener("click", () => $("about-dialog").close());

// ---- init ----

// Absence of history state marks the login view, which the page always
// starts on. A (re)load can land in an entry carrying zone state from a
// previous session; navigate back to the login entry, since that session
// no longer exists. On a bfcache restore the sessions survive, so the zone
// view stays usable.
window.addEventListener("pageshow", () => {
  if (history.state && !sessions.length) {
    history.go(-(history.state.depth + 1));
  }
});
restoreSettings();
updateProxyAboutLink();
validateNameserver();
