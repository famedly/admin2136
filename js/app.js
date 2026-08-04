// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// admin2136 application glue: login, record list, editing via RFC 2136.

import { DowsConnection } from "./dows.js";
import { axfr, sendUpdate } from "./dnsops.js";
import { parseTsigSpec } from "./tsig.js";
import { ZoneStore } from "./zonestore.js";
import { VirtualList } from "./vlist.js";
import { rdataToText, textToRdata, soaSerial } from "./rdata.js";
import {
  typeToName,
  nameToType,
  TYPE_A,
  TYPE_AAAA,
  TYPE_CNAME,
  TYPE_TXT,
  TYPE_SSHFP,
  TYPE_SOA,
  CLASS_IN,
  CLASS_NONE,
} from "./dnswire.js";

const $ = (id) => document.getElementById(id);

const EDITABLE_TYPES = new Set([
  TYPE_A,
  TYPE_AAAA,
  TYPE_CNAME,
  TYPE_TXT,
  TYPE_SSHFP,
]);
const ROW_HEIGHT = 30;
const SETTINGS_KEY = "admin2136-settings";

let conn = null; // DowsConnection
let store = null; // ZoneStore
let tsigKey = null; // parsed TSIG key or null
let order = new Uint32Array(0); // display order -> arena record index
let view = null; // null = show all of `order`, else filtered record indices
let vlist = null; // VirtualList
let editRec = null; // record index being edited, or null for "add"
let settings = { proxy: "", ns: "" };

// ---- helpers ----

function setStatus(text, cls = "") {
  const el = $("status-bar");
  el.textContent = text;
  el.className = cls;
}

function displayName(rel) {
  return rel === "" ? "@" : rel;
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

// Rebuild the indirection array used for display: it starts as the identity
// sequence 0..n over the arena records and is sorted with the store's
// comparator (revname, type, ttl). Rows never move in the arena; only this
// array determines what the list shows where. Must be called after every
// store mutation (load, add, edit, delete).
function rebuildOrder() {
  const n = store ? store.count : 0;
  order = new Uint32Array(n);
  for (let i = 0; i < n; i++) order[i] = i;
  order.sort((a, b) => store.compareRecords(a, b));
}

async function ensureConn() {
  if (conn && conn.connected) return;
  conn = new DowsConnection(settings.proxy, settings.ns);
  await conn.connect();
}

// Transfer the zone into a fresh store; the current store is only replaced
// on success so a failed reload does not lose the working copy.
async function transferZone(progress) {
  await ensureConn();
  const fresh = new ZoneStore(store ? store.zone : $("zone").value.trim());
  let n = 0;
  await axfr(conn, fresh.zoneFqdn, tsigKey, (rr) => {
    fresh.add(fresh.relativize(rr.name), rr.type, rr.ttl, rr.rdata);
    if (rr.type === TYPE_SOA) fresh.serial = soaSerial(rr.rdata);
    // Report the very first record immediately (it signals that the server
    // accepted the request), then every 1024 records. The serial is known
    // from the first record on, since an AXFR starts with the SOA.
    if (progress && (++n === 1 || (n & 1023) === 0)) progress(n, fresh.serial);
  });
  store = fresh;
}

function updateMeta() {
  $("zone-meta").textContent =
    "serial " + (store.serial ?? "?") + " · " + store.count + " records";
}

function refreshList() {
  vlist.setCount(view ? view.length : order.length);
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
  const rec = view ? view[i] : order[i];
  el._rec = rec;
  const r = store.get(rec);
  const c = el._c;
  const data = rdataToText(r.type, r.rdata);
  c.name.textContent = displayName(r.name);
  c.ttl.textContent = r.ttl;
  c.type.textContent = typeToName(r.type);
  c.data.textContent = data;
  c.data.title = data;
  const editable = EDITABLE_TYPES.has(r.type);
  c.edit.disabled = !editable;
  c.del.disabled = r.type === TYPE_SOA;
  el.classList.toggle("readonly", !editable);
}

function applyFilter() {
  const q = $("filter").value.trim().toLowerCase();
  if (!q) {
    view = null;
  } else {
    // Filter in display order so `view` stays sorted as well.
    const v = [];
    for (const idx of order) {
      const r = store.get(idx);
      if (
        displayName(r.name).toLowerCase().includes(q) ||
        typeToName(r.type).toLowerCase().includes(q) ||
        rdataToText(r.type, r.rdata).toLowerCase().includes(q)
      ) {
        v.push(idx);
      }
    }
    view = v;
  }
  refreshList();
}

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
  const tsigSpec = $("tsig").value.trim();

  try {
    btn.disabled = true;
    status.textContent = "";
    if (tsigSpec && !(crypto && crypto.subtle)) {
      throw new Error(
        "Web Crypto unavailable; serve this page via https:// or from localhost",
      );
    }
    tsigKey = tsigSpec ? parseTsigSpec(tsigSpec) : null;
    settings = { proxy, ns };
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ proxy, ns, zone }));

    status.textContent = "Connecting to " + ns + "…";
    if (conn) conn.close();
    conn = new DowsConnection(proxy, ns);
    await conn.connect();

    status.textContent = "Transferring zone…";
    store = new ZoneStore(zone);

    // The login conceptually ends with the first successful DNS message:
    // switch to the zone view right away and let the rest of the AXFR
    // report its progress in the bottom status bar, like a reload does.
    let inZoneView = false;
    try {
      await transferZone((n, serial) => {
        if (!inZoneView) {
          inZoneView = true;
          enterZoneView();
        }
        if (serial !== null) $("zone-meta").textContent = "serial " + serial;
        setStatus("Transferring zone… " + n + " records");
      });
    } catch (err) {
      if (!inZoneView) throw err; // login itself failed
      setStatus("✗ zone transfer failed: " + err.message, "error");
      return;
    }
    if (!inZoneView) enterZoneView();
    rebuildOrder();
    updateMeta();
    refreshList();
    setStatus("Zone loaded via AXFR (" + store.count + " records).", "ok");
  } catch (err) {
    status.textContent = "✗ " + err.message;
    if (conn) {
      conn.close();
      conn = null;
    }
  } finally {
    btn.disabled = false;
  }
});

// Toggle between the login form and the zone view without touching any
// state (connection, store, form inputs); used both by login and by
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

// Switch from the login form to the (possibly still loading) zone view.
function enterZoneView() {
  showZoneView();
  $("zone-name").textContent = store.zoneFqdn;
  $("zone-meta").textContent = "";
  $("filter").value = "";
  view = null;
  if (!vlist) vlist = new VirtualList($("record-list"), ROW_HEIGHT, renderRow);
  rebuildOrder();
  refreshList();
  if (history.state?.view != "zone") {
    // Make the zone view a history entry so the browser back button returns
    // to the login form (and forward returns here).
    history.pushState({ view: "zone" }, "");
  }
}

// ---- history navigation ----

const LOGIN_FIELDS = ["proxy-url", "nameserver", "zone", "tsig"];

// Login form input values captured when the user navigates back from the
// zone view; navigating forward restores exactly this snapshot.
let loginSnapshot = null;

window.addEventListener("popstate", (e) => {
  if (e.state && e.state.view === "zone") {
    // Forward to the zone view. The connection and store are kept alive
    // while on the login screen, so nothing needs to be reloaded.
    if (!store) {
      // No session behind this entry (it belongs to a previous page load);
      // bounce off it so the back button keeps working past it.
      history.forward();
      return;
    }
    if (loginSnapshot) {
      for (const id of LOGIN_FIELDS) $(id).value = loginSnapshot[id];
      updateProxyAboutLink();
      validateNameserver();
    }
    showZoneView();
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

$("refresh-btn").addEventListener("click", async () => {
  const btn = $("refresh-btn");
  try {
    btn.disabled = true;
    setStatus("Reloading zone via AXFR…");
    // TODO(IXFR): request an incremental transfer based on store.serial.
    await transferZone((n) => setStatus("Reloading zone… " + n + " records"));
    rebuildOrder();
    applyFilter();
    updateMeta();
    setStatus(
      "Zone reloaded (" +
        store.count +
        " records, serial " +
        (store.serial ?? "?") +
        ").",
      "ok",
    );
  } catch (err) {
    setStatus("✗ reload failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

// ---- filtering ----

let filterTimer = null;
$("filter").addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, 150);
});

// ---- editing ----

function openEditor(rec) {
  editRec = rec;
  $("edit-status").textContent = "";
  if (rec === null) {
    $("edit-title").textContent = "Add record";
    $("edit-name").value = "";
    $("edit-ttl").value = "3600";
    $("edit-type").value = "A";
    $("edit-data").value = "";
  } else {
    const r = store.get(rec);
    $("edit-title").textContent = "Edit record";
    $("edit-name").value = displayName(r.name);
    $("edit-ttl").value = r.ttl;
    $("edit-type").value = typeToName(r.type);
    $("edit-data").value = rdataToText(r.type, r.rdata);
  }
  $("edit-dialog").showModal();
}

$("add-btn").addEventListener("click", () => openEditor(null));
$("edit-cancel").addEventListener("click", () => $("edit-dialog").close());

$("edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
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

    const updates = [];
    if (editRec !== null) {
      const old = store.get(editRec);
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
    await ensureConn();
    await sendUpdate(conn, store.zoneFqdn, tsigKey, updates);

    if (editRec !== null) store.replace(editRec, nameRel, type, ttl, rdata);
    else store.add(nameRel, type, ttl, rdata);

    $("edit-dialog").close();
    rebuildOrder();
    applyFilter();
    updateMeta();
    setStatus(
      (editRec !== null ? "Updated " : "Added ") +
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

async function deleteRecord(rec) {
  const r = store.get(rec);
  const what = displayName(r.name) + " " + typeToName(r.type);
  if (
    !confirm("Delete " + what + " record?\n\n" + rdataToText(r.type, r.rdata))
  )
    return;
  try {
    setStatus("Deleting " + what + "…");
    await ensureConn();
    await sendUpdate(conn, store.zoneFqdn, tsigKey, [
      {
        name: store.absolutize(r.name),
        type: r.type,
        cls: CLASS_NONE,
        ttl: 0,
        rdata: r.rdata,
      },
    ]);
    store.remove(rec);
    rebuildOrder();
    applyFilter();
    updateMeta();
    setStatus("Deleted " + what + " record.", "ok");
  } catch (err) {
    setStatus("✗ delete failed: " + err.message, "error");
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
// no longer exists. On a bfcache restore the store survives, so the zone
// view stays usable.
window.addEventListener("pageshow", () => {
  if (history.state && !store) history.back();
});
restoreSettings();
updateProxyAboutLink();
validateNameserver();
