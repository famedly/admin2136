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
  queryAll,
  sendUpdate,
  isRejection,
  isUnsetZoneResponse,
  rcodeName,
  DnsError,
  RCODE_FORMERR,
  RCODE_SERVFAIL,
  RCODE_NOTIMP,
  RCODE_REFUSED,
  RCODE_YXRRSET,
  RCODE_NXRRSET,
} from "./dnsops.js";
import { dsRdata, dsKeys } from "./dnssec.js";
import { parseTsigSpec } from "./tsig.js";
import { ZoneStore } from "./zonestore.js";
import { VirtualList } from "./vlist.js";
import { resizableColumns } from "./colresize.js";
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
  readName,
  typeToName,
  nameToType,
  TYPES,
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
    // the zone's own row (like a catalog member's) if it has no records
    // yet and was logged in to directly, see enterSetup()
    setup: null,
    // catalog view: SOA and NS records of member zones by lowercase name
    // ({ state: "loading" | "ok" | "unset" | "error", ... }), see
    // fetchZoneInfo(); zones to be added; input kept across refreshes
    zoneInfo: new Map(),
    drafts: [],
    keptEdits: new Map(),
    infoQueue: new Set(), // zones on screen to query, see queueZoneInfo()
    infoTimer: null,
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
  return s.setup !== null || (s.catalog !== null && !s.showRaw);
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
      if (rr.type === TYPES.SOA) {
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
        if (s === cur) renderPath();
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
  if (s.setup) {
    s.zoneView = [s.setup];
  } else if (showsZones(s)) {
    s.zoneView = !q
      ? s.catalog.members
      : s.catalog.members.filter((m) => {
          const info = s.zoneInfo.get(zkey(m.zone));
          return [
            m.zone,
            m.id,
            m.group ?? "",
            info?.soaText ?? "",
            ...(info?.additional ?? []),
          ]
            .join(" ")
            .toLowerCase()
            .includes(q);
        });
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

// The line under a zone name in the toolbar path: serial and size.
function metaText(s) {
  if (s.setup) return "no records yet";
  if (s.loadingSerial !== null) return "serial " + s.loadingSerial;
  return (
    "serial " +
    (s.store.serial ?? "?") +
    " · " +
    (s.catalog && !s.showRaw
      ? "catalog of " + s.catalog.members.length + " zones"
      : s.store.count + " records")
  );
}

// The toolbar path: app / catalog / zone. The catalog view shows the
// catalog only, a member zone opened from it is added after it, and the
// raw records of a catalog (or a zone logged in to) show it as a zone.
function renderPath() {
  const s = cur;
  const asCatalog = s.catalog !== null && !s.showRaw && !s.setup;
  const catalog = asCatalog ? s : s.depth > 0 ? sessions[s.depth - 1] : null;
  $("catalog-sep").hidden = $("catalog-title").hidden = !catalog;
  $("zone-sep").hidden = $("zone-title").hidden = asCatalog;
  if (catalog) {
    $("catalog-name").textContent = catalog.store.zoneFqdn;
    $("catalog-meta").textContent = metaText(catalog);
    $("catalog-title").classList.toggle("link", catalog !== s);
  }
  if (!asCatalog) {
    $("zone-name").textContent = s.store.zoneFqdn;
    $("zone-meta").textContent = metaText(s);
  }
}

// The catalog in the path leads back to it from a member zone, through
// the history so that forward returns.
$("catalog-title").addEventListener("click", () => {
  if ($("catalog-title").classList.contains("link")) history.back();
});

// Bring the zone view in line with the current session.
function render() {
  const s = cur;
  $("toolbar").classList.toggle("setup-active", s.setup !== null);
  const zones = showsZones(s);
  $("zone-view").classList.toggle("catalog-mode", zones);
  $("raw-btn").hidden = s.catalog === null;
  $("raw-btn").setAttribute("aria-pressed", String(s.showRaw));
  $("add-btn").textContent = zones ? "+ Add zone" : "+ Add record";
  $("filter").placeholder = zones ? "Filter zones…" : "Filter records…";
  renderPath();
  if (zones) zlist.setCount(s.zoneView.length + s.drafts.length);
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
  $("filter").value = s.filter;
  render();
  $("record-list").scrollTop = s.scroll.records;
  $("zone-list").scrollTop = s.scroll.zones;
  setStatus(s, s.status.text, s.status.cls);
}

// The brand leads back to the login screen.
$("brand").addEventListener("click", () => {
  if (!$("zone-view").hidden) history.go(-(cur.depth + 1));
});

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

// The columns before the data column (records) or the NS column (catalog
// zones) can be resized; that column takes the remaining width.
resizableColumns({
  header: $("list-header"),
  scope: $("zone-view"),
  name: "--record-cols",
  count: 3,
  flexMin: 200,
  tail: "76px",
  storageKey: "admin2136-record-cols",
});
resizableColumns({
  header: $("zone-header"),
  scope: $("zone-view"),
  name: "--zone-cols",
  count: 3,
  flexMin: 120,
  tail: "76px",
  storageKey: "admin2136-zone-cols",
});

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
  c.del.disabled = r.type === TYPES.SOA;
  el.classList.toggle("readonly", !editable);
}

// ---- catalog zone list ----

// The catalog view lists the member zones with their SOA and apex NS
// records. These come from normal queries, made only for the rows on
// screen (see queueZoneInfo()). Zones without these records (they have no
// records yet) and zones to be added (see addDraft()) get inputs instead,
// and a checkmark that creates the zone (see createZone()).

const zkey = (zone) => zone.toLowerCase();

// The rows of the catalog view: the members matching the filter, then the
// zones to be added.
function zoneRows(s) {
  return s.zoneView.concat(s.drafts);
}

function buildZoneRow(el) {
  el.classList.add("zone-grid");
  const cell = (cls) => {
    const c = document.createElement("span");
    c.className = cls;
    el.appendChild(c);
    return c;
  };
  const add = (parent, tag, cls) => {
    const e = document.createElement(tag);
    e.className = cls;
    parent.appendChild(e);
    return e;
  };
  // Inputs write straight into the row's edit state (a draft, or the
  // info of a zone without records), which survives scrolling.
  const input = (parent, cls, key, placeholder) => {
    const i = add(parent, "input", cls);
    i.placeholder = placeholder;
    i.spellcheck = false;
    i.addEventListener("input", () => (el._edit[key] = i.value));
    return i;
  };
  const c = {
    zoneCell: cell("c-zone-cell"),
    groupCell: cell("c-group"),
    soaCell: cell("c-soa"),
    nsCell: cell("c-ns"),
    actions: cell("c-actions"),
  };
  c.zone = add(c.zoneCell, "button", "c-zone");
  c.zone.addEventListener("click", () => openMember(el._row));
  c.zoneText = add(c.zoneCell, "span", "c-text");
  c.zoneInput = input(c.zoneCell, "in-zone", "zone", "zone name");
  c.groupText = add(c.groupCell, "span", "c-text");
  c.groupInput = input(c.groupCell, "in-group", "group", "group");
  c.soaText = add(c.soaCell, "span", "c-text");
  c.soaInput = input(
    c.soaCell,
    "in-soa",
    "soa",
    "mname rname serial refresh retry expire minimum",
  );
  c.nsText = add(c.nsCell, "span", "c-text");
  c.nsInput = input(c.nsCell, "in-ns", "ns", "additional nameservers");
  c.open = add(c.actions, "button", "row-open");
  c.open.textContent = "→";
  c.open.title = "Open zone";
  c.open.addEventListener("click", () => openMember(el._row));
  c.check = add(c.actions, "button", "row-check");
  c.check.textContent = "✓";
  c.check.addEventListener("click", () => createZone(cur, el._row));
  c.del = add(c.actions, "button", "row-del");
  c.del.textContent = "✕";
  c.del.addEventListener("click", () => {
    if (el._row.draft) removeDraft(cur, el._row);
    else deleteMember(el._row);
  });
  el._c = c;
}

// Set an input's value unless it has it already (keeps the caret).
function setValue(input, value) {
  if (input.value !== value) input.value = value;
}

function renderZoneRow(i, el) {
  if (!el._c) buildZoneRow(el);
  const s = cur;
  const row = zoneRows(s)[i];
  el._row = row;
  const c = el._c;
  const draft = row.draft === true;
  const info = draft ? null : (s.zoneInfo.get(zkey(row.zone)) ?? null);
  if (!draft && !info) queueZoneInfo(s, row.zone);
  const editing = draft || info?.state === "unset";
  const holder = draft ? row : info;
  el._edit = draft ? row : (info?.edit ?? null);

  c.zone.hidden = editing;
  c.zoneText.hidden = !editing || draft;
  c.zoneInput.hidden = !draft;
  c.groupText.hidden = draft;
  c.groupInput.hidden = !draft;
  c.soaText.hidden = editing;
  c.soaInput.hidden = !editing;
  c.nsText.hidden = editing;
  c.nsInput.hidden = !editing;
  c.open.hidden = editing;
  c.check.hidden = !editing;
  el.classList.toggle("editing", editing);

  // (Hidden elements get no text, so that a row reads as what it shows.)
  const title = draft
    ? ""
    : row.id === null
      ? row.zone
      : row.zone + " (catalog ID " + row.id + ")";
  c.zone.textContent = editing ? "" : row.zone;
  c.zone.title = "Open " + title;
  c.zoneText.textContent = editing && !draft ? row.zone : "";
  c.zoneText.title = title;
  c.groupText.textContent = draft ? "" : (row.group ?? "");
  c.groupText.title = c.groupText.textContent;
  if (draft) {
    setValue(c.zoneInput, row.zone);
    setValue(c.groupInput, row.group);
  }
  if (editing) {
    setValue(c.soaInput, el._edit.soa);
    setValue(c.nsInput, el._edit.ns);
    c.soaText.textContent = c.nsText.textContent = "";
  } else {
    const soa = !info
      ? "…"
      : info.state === "ok"
        ? info.soaText
        : info.state === "loading"
          ? "…"
          : info.error;
    c.soaText.textContent = soa;
    c.soaText.title = soa;
    const ns = info?.state === "ok" ? info.additional.join(" ") : "";
    c.nsText.textContent = ns;
    c.nsText.title = ns;
  }
  c.check.title = draft
    ? "Add the zone to the catalog and create it with these records"
    : "Create the zone with these records";
  c.del.title = draft ? "Discard" : "Remove zone from catalog";
  c.del.hidden = s.setup !== null; // not in a catalog
  c.check.disabled = c.del.disabled = !!holder?.busy;
}

$("raw-btn").addEventListener("click", () => {
  cur.showRaw = !cur.showRaw;
  applyFilter(cur);
});

// Remember that a zone row is on screen without its SOA and NS records;
// they are queried shortly, together with the other rows that appear.
function queueZoneInfo(s, zone) {
  s.infoQueue.add(zone);
  clearTimeout(s.infoTimer);
  s.infoTimer = setTimeout(() => fetchZoneInfo(s), 100);
}

// The zones whose rows are currently rendered (on screen or nearly).
function renderedZones(s) {
  if (s !== cur || !showsZones(s) || $("zone-view").hidden) return new Set();
  return new Set(
    zlist.pool
      .filter((el) => el.style.display !== "none" && el._row && !el._row.draft)
      .map((el) => el._row.zone),
  );
}

// Query the SOA and NS records of the queued zones that are still on
// screen (so that scrolling past rows does not query them), all at once.
async function fetchZoneInfo(s) {
  const rendered = renderedZones(s);
  const zones = [...s.infoQueue].filter(
    (z) => rendered.has(z) && !s.zoneInfo.has(zkey(z)),
  );
  s.infoQueue.clear();
  if (!zones.length) return;
  for (const z of zones) s.zoneInfo.set(zkey(z), { state: "loading" });
  let res;
  try {
    const questions = zones.flatMap((name) => [
      { name, type: TYPES.SOA },
      { name, type: TYPES.NS },
    ]);
    res = await withConn((c) => queryAll(c, questions));
  } catch (err) {
    for (const z of zones) s.zoneInfo.delete(zkey(z));
    setStatus(
      s,
      "✗ querying SOA and NS records failed: " + err.message,
      "error",
    );
    return;
  }
  zones.forEach((z, i) => {
    s.zoneInfo.set(zkey(z), zoneInfo(res[2 * i], res[2 * i + 1]));
  });
  // Zones without records get inputs, prefilled as suggested by the
  // others (or as entered before).
  zones.forEach((z) => {
    const info = s.zoneInfo.get(zkey(z));
    if (info.state === "unset") {
      info.edit = s.keptEdits.get(zkey(z)) ?? suggestion(s);
    }
  });
  if (s === cur && showsZones(s)) render();
}

// The info of a zone from the responses to its SOA and NS queries.
function zoneInfo(soaResp, nsResp) {
  const soa =
    soaResp.rcode === 0 && soaResp.answers.find((rr) => rr.type === TYPES.SOA);
  if (soa) {
    const f = soaFields(soa.rdata);
    const ns =
      nsResp.rcode === 0
        ? nsResp.answers.filter((rr) => rr.type === TYPES.NS)
        : [];
    const names = ns.map((rr) => readName(rr.rdata, 0)[0]).sort();
    return {
      state: "ok",
      soa: f,
      soaTtl: soa.ttl,
      soaText: rdataToText(TYPES.SOA, soa.rdata),
      // The primary nameserver of the SOA has an NS record anyway.
      additional: names.filter((n) => zkey(n) !== zkey(f.mname)),
      nsTtl: ns.length ? ns[0].ttl : soa.ttl,
    };
  }
  if (isUnsetZoneResponse(soaResp)) return { state: "unset", edit: null };
  return { state: "error", error: rcodeName(soaResp.rcode) };
}

// Values for a new zone's records: what at least two of the zones on
// screen share (e.g. the timers, or a provider's nameservers), else
// defaults. Names are relative to the new zone, so they fit any zone.
function suggestion(s) {
  const oks = [...s.zoneInfo.values()].filter((i) => i.state === "ok");
  const common = (values, fallback) => {
    const count = new Map();
    for (const v of values) count.set(v, (count.get(v) ?? 0) + 1);
    const [value, n] = [...count].sort((a, b) => b[1] - a[1])[0] ?? [];
    return n >= 2 ? value : fallback;
  };
  const timers = common(
    oks.map((i) =>
      [i.soa.refresh, i.soa.retry, i.soa.expire, i.soa.minimum].join(" "),
    ),
    "7200 3600 1209600 300",
  );
  return {
    soa:
      common(
        oks.map((i) => i.soa.mname),
        "ns1",
      ) +
      " " +
      common(
        oks.map((i) => i.soa.rname),
        "hostmaster",
      ) +
      " 1 " +
      timers,
    ns: common(
      oks.map((i) => i.additional.join(" ")),
      "",
    ),
    soaTtl: Number(
      common(
        oks.map((i) => String(i.soaTtl)),
        "3600",
      ),
    ),
    nsTtl: Number(
      common(
        oks.map((i) => String(i.nsTtl)),
        "3600",
      ),
    ),
  };
}

// Forget the SOA and NS records of the zones (e.g. after a refresh), so
// that they are queried again when on screen. Input made for zones
// without records is kept.
function forgetZoneInfo(s) {
  for (const [k, info] of s.zoneInfo) {
    if (info.state === "unset" && info.edit) s.keptEdits.set(k, info.edit);
  }
  s.zoneInfo = new Map();
}

// Add a row for a new zone at the bottom of the catalog view, scrolled
// into view.
function addDraft(s) {
  const draft = {
    draft: true,
    zone: "",
    group: "",
    busy: false,
    ...suggestion(s),
  };
  s.drafts.push(draft);
  render();
  const list = $("zone-list");
  const rows = s.zoneView.length + s.drafts.length;
  list.scrollTop = Math.max(0, rows * ROW_HEIGHT - list.clientHeight);
  render(); // the rows for the new scroll position
  zlist.pool.find((el) => el._row === draft)?._c.zoneInput.focus();
}

function removeDraft(s, draft) {
  s.drafts.splice(s.drafts.indexOf(draft), 1);
  render();
}

// The checkmark of a row: create the zone with the SOA and NS records
// entered. A new zone is added to the catalog first; then the server
// configures it (without records), and the records can be added.
async function createZone(s, row) {
  const draft = row.draft === true;
  let holder = draft ? row : s.zoneInfo.get(zkey(row.zone));
  const edit = draft ? row : holder.edit;
  let zone = row.zone;
  try {
    holder.busy = true;
    render();
    if (draft) {
      zone = zone.trim().toLowerCase().replace(/\.+$/, "") + ".";
      if (zone === ".") throw new Error("the zone name must not be empty");
      nameToWire(zone); // validate
      if (s.catalog.members.some((m) => zkey(m.zone) === zone)) {
        throw new Error(zone + " is already in the catalog");
      }
    }
    // The member zone's own key context (tsigKey from the catalog), so
    // that a key entered for it does not replace the catalog's.
    const target = s.setup ? s : newSession(zone, s.tsigKey, s.depth + 1);
    const { updates, prereqs } = zoneSetupUpdates(
      target.store,
      textToRdata(TYPES.SOA, edit.soa, (n) => target.store.absolutize(n)),
      edit.soaTtl,
      edit.ns.split(/\s+/).filter(Boolean),
      edit.nsTtl,
    );
    if (draft) {
      const recs = memberRecords(
        zone,
        newMemberId(s.catalog),
        row.group.trim(),
      );
      setStatus(s, "Adding " + zone + " to the catalog…");
      await performUpdate(s, addUpdates(s.store, recs));
      for (const r of recs) s.store.add(r.name, r.type, r.ttl, r.rdata);
      // From now on a member row; it keeps the input, should the rest fail.
      s.drafts.splice(s.drafts.indexOf(row), 1);
      holder = { state: "unset", busy: true, edit: { ...edit } };
      delete holder.edit.draft;
      s.zoneInfo.set(zkey(zone), holder);
      rebuild(s);
      setStatus(s, "Waiting for the server to configure " + zone + "…");
      await waitForZone(zone);
    }
    setStatus(s, "Creating " + zone + "…");
    // An update key that works for the catalog (possibly just entered for
    // adding the zone) likely works for its zones.
    if (target !== s) target.updateKey = s.updateKey;
    await sendZoneSetup(target, updates, prereqs);
    const dnssec = await dnssecRecords(zone);
    if (dnssec) showDnssec(zone, dnssec);
    if (s.setup) {
      await finishSetup(s);
      return;
    }
    s.zoneInfo.delete(zkey(zone)); // query its records again
    s.keptEdits.delete(zkey(zone));
    setStatus(s, "Created " + zone + ".", "ok");
  } catch (err) {
    setStatus(s, "✗ creating " + zone + " failed: " + err.message, "error");
  } finally {
    holder.busy = false;
    if (s === cur) render();
  }
}

// Wait (up to 10 seconds) until the server has configured a zone just
// added to the catalog: it is unknown (REFUSED) until then.
async function waitForZone(zone) {
  for (let i = 0; ; i++) {
    try {
      await withConn((c) => query(c, zone, TYPES.SOA, null, { edns: true }));
      return; // it even has records already
    } catch (err) {
      if (err instanceof DnsError && isUnsetZoneResponse(err.response)) return;
      if (!(err instanceof DnsError && err.rcode === RCODE_REFUSED)) throw err;
      if (i === 50) throw new Error("the server has not configured the zone");
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

// The update creating a zone: its SOA and apex NS records (the SOA's
// primary nameserver and `additional` ones; relative names are made
// absolute in `store`'s zone), only while it has no SOA.
function zoneSetupUpdates(store, soa, soaTtl, additional, nsTtl) {
  const apex = store.zoneFqdn;
  const mname = soaFields(soa).mname;
  const names = [mname];
  for (const n of additional) {
    const abs = store.absolutize(n);
    nameToWire(abs); // validate
    if (!names.some((x) => zkey(x) === zkey(abs))) names.push(abs);
  }
  return {
    updates: [
      { name: apex, type: TYPES.SOA, cls: CLASS_IN, ttl: soaTtl, rdata: soa },
      ...names.map((n) => ({
        name: apex,
        type: TYPES.NS,
        cls: CLASS_IN,
        ttl: nsTtl,
        rdata: nameToWire(n),
      })),
    ],
    // "RRset does not exist" (RFC 2136 Section 2.4.3): do not overwrite
    // a concurrent setup.
    prereqs: [
      {
        name: apex,
        type: TYPES.SOA,
        cls: CLASS_NONE,
        ttl: 0,
        rdata: new Uint8Array(0),
      },
    ],
  };
}

// Send the update creating a zone; somebody else having created it
// meanwhile is fine as well.
async function sendZoneSetup(s, updates, prereqs) {
  try {
    await performUpdate(s, updates, prereqs);
  } catch (err) {
    if (!(err instanceof DnsError && err.rcode === RCODE_YXRRSET)) throw err;
  }
}

// The DNSKEY records of `zone` and the DS records for its key signing
// keys as master file text, or null if it is not signed.
async function dnssecRecords(apex) {
  let keys = [];
  // A signing server adds the keys with the zone, but give it a moment.
  for (let i = 0; i < 3 && !keys.length; i++) {
    if (i) await new Promise((r) => setTimeout(r, 300));
    const answers = await withConn((c) => query(c, apex, TYPES.DNSKEY, null));
    keys = answers.filter((rr) => rr.type === TYPES.DNSKEY);
  }
  if (!keys.length) return null;
  const line = (rr, type, rdata) =>
    apex +
    " " +
    rr.ttl +
    " IN " +
    typeToName(type) +
    " " +
    rdataToText(type, rdata);
  const ds = [];
  for (const rdata of dsKeys(keys.map((rr) => rr.rdata))) {
    const rr = keys.find((k) => k.rdata === rdata);
    ds.push(line(rr, TYPES.DS, await dsRdata(apex, rdata)));
  }
  return {
    ds: ds.join("\n"),
    dnskey: keys.map((rr) => line(rr, TYPES.DNSKEY, rr.rdata)).join("\n"),
  };
}

function showDnssec(zone, { ds, dnskey }) {
  $("dnssec-zone").textContent = zone;
  $("dnssec-ds").value = ds;
  $("dnssec-dnskey").value = dnskey;
  $("dnssec-dialog").showModal();
}

$("dnssec-close").addEventListener("click", () => $("dnssec-dialog").close());

// Open a member zone of the current (catalog) session in a new session.
// The view switches once the zone transfer got going; until then the
// catalog stays visible. The member zone is first tried with the
// catalog's transfer key; if the server refuses the transfer, the user may
// enter another one. Other failures (e.g. no connection) do not depend on
// the key and are only reported; a zone without records gets inputs for
// them in the catalog view.
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
    if (await isUnsetZone(err, m.zone)) {
      parent.zoneInfo.set(zkey(m.zone), {
        state: "unset",
        edit: parent.keptEdits.get(zkey(m.zone)) ?? suggestion(parent),
      });
      if (parent === cur) render();
      setStatus(
        parent,
        m.zone + " has no records yet: enter its SOA and NS records.",
      );
      return;
    }
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

// ---- zone setup ----

// A zone the server has, but without records (newly created), fails to
// transfer with SERVFAIL; a normal SOA query tells such zones apart.
// `c` is the connection to use, if not the shared one.
async function isUnsetZone(err, zone, c = null) {
  if (!(err instanceof DnsError && err.rcode === RCODE_SERVFAIL)) return false;
  const run = (c) => query(c, zone, TYPES.SOA, null, { edns: true });
  try {
    await (c ? runOn(c, run) : withConn(run));
    return false; // the zone has a SOA after all
  } catch (e) {
    return e instanceof DnsError && isUnsetZoneResponse(e.response);
  }
}

// Logged in to a zone without records (without a catalog): the zone
// view shows its row like the catalog view does, with inputs for its SOA
// and apex NS records.
function enterSetup(s) {
  s.setup = { zone: s.store.zoneFqdn, id: null, group: null };
  s.zoneInfo.set(zkey(s.setup.zone), { state: "unset", edit: suggestion(s) });
  s.zoneView = [s.setup];
  setStatus(s, "The zone has no records yet: enter its SOA and NS records.");
}

// Show the records of the zone just created instead of its row.
async function finishSetup(s) {
  s.setup = null;
  s.zoneInfo = new Map();
  if (s === cur) render();
  try {
    await transferZone(s, (n) =>
      setStatus(s, "Transferring zone… " + n + " records"),
    );
    rebuild(s);
    setStatus(s, "Zone created (serial " + s.store.serial + ").", "ok");
  } catch (err) {
    setStatus(s, "✗ zone transfer failed: " + err.message, "error");
  }
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
    const onStarted = () => {
      if (conn && conn !== c) conn.close();
      conn = c;
      settings = { proxy, ns };
      enterSession(s);
    };
    try {
      await startLoad(s, onStarted, c);
    } catch (err) {
      if (!(await isUnsetZone(err, s.store.zoneFqdn, c))) throw err;
      enterSetup(s);
      onStarted();
    }
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
    forgetZoneInfo(s); // a catalog's zones may have changed as well
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
  const isSoa = editOld !== null && editOld.type === TYPES.SOA;
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
  if (showsZones(cur)) addDraft(cur);
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

    if (type === TYPES.SOA) {
      status.textContent = "Sending update…";
      const soa = await updateSoa(s, old, ttl, rdata);
      $("edit-dialog").close();
      if (!soa) {
        setStatus(s, "SOA record unchanged.");
        return;
      }
      const live = s.store;
      const i = live.findName("").find((i) => live.get(i).type === TYPES.SOA);
      if (i === undefined) live.add("", TYPES.SOA, soa.ttl, soa.rdata);
      else live.replace(i, "", TYPES.SOA, soa.ttl, soa.rdata);
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
    const updates = [{ name: apex, type: TYPES.SOA, cls: CLASS_IN, ...next }];
    const prereqs = [
      {
        name: apex,
        type: TYPES.SOA,
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
        query(c, apex, TYPES.SOA, s.tsigKey),
      );
      const soa = answers.find((rr) => rr.type === TYPES.SOA);
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
