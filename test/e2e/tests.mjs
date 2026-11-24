// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// End-to-end test cases, run in order by run.mjs. Each gets the helpers
// `t` (see run.mjs) and starts from a fresh page. Tests share the Knot
// state, so they use their own record names.

import fs from "node:fs";

import { MEMBERS } from "./env.mjs";

// The name shown last in the toolbar path (the catalog in the catalog
// view, else the zone), as a page expression.
const SHOWN = `[...document.querySelectorAll("#path .path-part:not([hidden]) .path-name")].pop().textContent`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const re = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Fill in a zone row of the catalog view and click its checkmark: the
// newest zone to be added (`zone` null), or the zone without records named
// `zone`. `values` maps input classes (in-zone, in-group, in-soa, in-ns)
// to values.
async function fillZoneRow(t, zone, values, check = true) {
  const ok = await t.b.ev(`
    const rows = [...document.querySelectorAll("#zone-list .vlist-row.editing")]
      .filter((r) => r.style.display !== "none")
      .sort((a, b) => parseInt(a.style.top) - parseInt(b.style.top));
    const zone = ${JSON.stringify(zone)};
    const row = zone === null
      ? rows.filter((r) => !r.querySelector(".in-zone").hidden).pop()
      : rows.find((r) => r.querySelector(".c-zone-cell .c-text").textContent === zone);
    if (!row) return false;
    for (const [cls, v] of Object.entries(${JSON.stringify(values)})) {
      const i = row.querySelector("." + cls);
      i.value = v;
      i.dispatchEvent(new Event("input"));
    }
    if (${check}) row.querySelector(".row-check").click();
    return true;`);
  if (!ok) throw new Error("no zone row " + zone);
}

// Wait until the SOA records of the catalog view's zones are shown.
const soaShown = (b) =>
  b.wait(
    `[...document.querySelectorAll("#zone-list .vlist-row:not(.editing)")]
      .filter((r) => r.style.display !== "none")
      .every((r) => r.querySelector(".c-soa").textContent !== "…")`,
    "SOA records shown",
  );

// The visible parts of the toolbar path as [name, line below].
const path = (b) =>
  b.ev(`return [...document.querySelectorAll("#path .path-part:not([hidden])")]
    .map((p) => [...p.children].map((c) => c.textContent));`);
const catalogBox = (b) =>
  b.ev(`const r = document.getElementById("catalog-name").getBoundingClientRect();
    return [r.x, r.y, r.width, r.height];`);

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
export default tests;

// ---- login ----

test("login: connection and authentication errors", async (t) => {
  const { b, env } = t;
  await t.open();
  const loginError = async (opts, pattern) => {
    await b.ev(`document.getElementById("login-status").textContent = "";`);
    await t.submitLogin(opts);
    return b.wait(
      `/${pattern}/.test(document.getElementById("login-status").textContent)
       && document.getElementById("login-status").textContent`,
      "login error " + pattern,
    );
  };
  await loginError(
    { zone: "catalog.test", proxy: "ws://127.0.0.1:1" },
    "✗ could not connect",
  );
  // dows only proxies to the configured nameserver
  await loginError({ zone: "catalog.test", ns: "127.0.0.1:1" }, "✗ ");
  await loginError(
    { zone: "catalog.test", key: null },
    "✗ AXFR refused: NOTAUTH",
  );
  await loginError({ zone: "own.example" }, "✗ AXFR refused: NOTAUTH");
  await loginError({ zone: "nonexistent.example" }, "✗ AXFR refused: NOTAUTH");
  await t.set("tsig", "garbage");
  await t.click("login-btn");
  await b.wait(
    `document.getElementById("login-status").textContent.includes("TSIG secret must be given")`,
    "invalid TSIG spec",
  );
  // wrong secret for a known key name
  await t.set(
    "tsig",
    "hmac-sha256:kc:" + Buffer.alloc(32, 1).toString("base64"),
  );
  await t.click("login-btn");
  await b.wait(
    `/BADSIG|BADKEY|NOTAUTH/.test(document.getElementById("login-status").textContent)`,
    "bad secret",
  );
  t.ok(await t.visible("login-view"), "still on the login form");

  // invalid nameserver: the form refuses to submit
  await t.set("nameserver", "bad host:x");
  t.eq(
    await b.ev(`return document.getElementById("nameserver").validity.valid;`),
    false,
    "nameserver validity",
  );
  await t.set("nameserver", env.nameserver);
  t.eq(
    await b.ev(`return document.getElementById("nameserver").validity.valid;`),
    true,
    "nameserver validity",
  );
});

test("login: settings are remembered, about dialog", async (t) => {
  const { b, env } = t;
  await t.login("full.example");
  await t.open();
  t.eq(await t.value("proxy-url"), env.proxyUrl, "proxy restored");
  t.eq(await t.value("nameserver"), env.nameserver, "nameserver restored");
  t.eq(await t.value("zone"), "full.example", "zone restored");
  t.eq(
    await b.ev(`return document.getElementById("proxy-about-link").href;`),
    env.proxyUrl.replace("ws:", "http:") + "/",
    "proxy about link",
  );
  await t.set("proxy-url", "nonsense");
  t.eq(
    await b.ev(
      `return document.getElementById("proxy-about-link").hasAttribute("href");`,
    ),
    false,
    "no about link for an invalid URL",
  );
  await t.set("proxy-url", env.proxyUrl.replace("ws:", "wss:"));
  t.ok(
    (
      await b.ev(`return document.getElementById("proxy-about-link").href;`)
    ).startsWith("https:"),
    "https about link for wss",
  );

  // About on the login page: no proxy link
  await t.click("about-btn");
  t.eq(
    await b.ev(`return document.getElementById("about-proxy").hidden;`),
    true,
    "no proxy link",
  );
  await t.click("about-close");
  // About when logged in: link to the connected proxy
  await t.submitLogin({ zone: "full.example" });
  await t.waitStatus("Zone loaded");
  await t.click("about-btn");
  t.eq(
    await b.ev(`return document.getElementById("about-proxy").hidden;`),
    false,
    "proxy link",
  );
  t.ok(
    (
      await b.ev(`return document.getElementById("about-proxy-link").href;`)
    ).startsWith(env.proxyUrl.replace("ws:", "http:")),
    "proxy link target",
  );
  await t.click("about-close");
});

// ---- catalog ----

test("catalog: member zones, filter, raw records", async (t) => {
  const { b } = t;
  await t.login("catalog.test");
  t.ok(
    await b.ev(
      `return document.getElementById("zone-view").classList.contains("catalog-mode");`,
    ),
    "catalog mode",
  );
  await soaShown(b);
  const zones = await t.rows("zone-list");
  const expected = [...MEMBERS]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .map(([zone, group]) => [zone + ".", group]);
  t.eq(
    zones
      .filter((z) => expected.some((e) => e[0] === z[0]))
      .map((z) => z.slice(0, 2)),
    expected,
    "member zones",
  );
  for (const [zone, , soa] of zones.filter((z) =>
    expected.some((e) => e[0] === z[0]),
  )) {
    t.ok(
      soa.startsWith("ns1." + zone + " hostmaster." + zone),
      "SOA of " + zone + ": " + soa,
    );
  }
  t.ok(
    await b.ev(`return [...document.querySelectorAll("#zone-list .vlist-row")]
      .find((r) => r.children[0].textContent === "big.example.")
      .querySelector(".c-zone").title.includes("catalog ID big");`),
    "catalog ID in the tooltip",
  );
  t.ok(
    (await t.text("catalog-meta")).includes("catalog of"),
    "meta: " + (await t.text("catalog-meta")),
  );
  t.eq(await t.text("add-btn"), "+ Add zone", "add button");
  t.eq(
    await b.ev(`return document.getElementById("filter").placeholder;`),
    "Filter zones…",
    "filter placeholder",
  );

  const filtered = async (q) => {
    await t.set("filter", q);
    await sleep(300);
    return (await t.rows("zone-list")).map((r) => r[0]);
  };
  t.eq(await filtered("own"), ["own.example."], "filter by name");
  t.eq(await filtered("AXFR-only"), ["xfr.example."], "filter by group");
  t.eq(await filtered("big"), ["big.example."], "filter by id");
  t.eq(await filtered("hostmaster.own"), ["own.example."], "filter by SOA");
  t.ok((await filtered("")).length >= MEMBERS.length, "filter cleared");

  // raw records of the catalog zone
  await t.click("raw-btn");
  t.eq(
    await b.ev(
      `return document.getElementById("raw-btn").getAttribute("aria-pressed");`,
    ),
    "true",
    "raw pressed",
  );
  t.eq(await t.text("add-btn"), "+ Add record", "add button in raw mode");
  const raw = await t.rows();
  t.ok(
    raw.some((r) => r[0] === "version" && r[2] === "TXT"),
    "version record",
  );
  t.ok(
    raw.some((r) => r[0] === "own.zones" && r[3] === "own.example."),
    "member PTR",
  );
  await t.set("filter", "group.");
  await sleep(300);
  t.ok(
    (await t.rows()).every((r) => r[0].startsWith("group.")),
    "raw filter",
  );
  await t.set("filter", "");
  await t.click("raw-btn");
  t.eq(await t.text("add-btn"), "+ Add zone", "back to zones");
});

test("catalog: add and remove zones", async (t) => {
  const { b, env } = t;
  await t.login("catalog.test");
  await soaShown(b);
  const addZone = async (values, expect) => {
    await t.clearStatus();
    await t.click("add-btn");
    await b.wait(
      `document.activeElement.classList.contains("in-zone")`,
      "new row focused",
    );
    await fillZoneRow(t, null, values);
    return t.waitStatus(expect);
  };
  // prefilled with the settings the other zones share
  await t.click("add-btn");
  t.eq(
    await b.ev(
      `return document.activeElement.closest(".vlist-row").querySelector(".in-soa").value;`,
    ),
    "ns1 hostmaster 1 3600 600 86400 300",
    "suggested SOA",
  );
  await b.ev(
    `document.activeElement.closest(".vlist-row").querySelector(".row-del").click();`,
  );
  t.ok(
    !(await b.ev(
      `return [...document.querySelectorAll("#zone-list .vlist-row")]
        .some((r) => r.style.display !== "none" && !r.querySelector(".in-zone").hidden);`,
    )),
    "row discarded",
  );

  await addZone(
    {
      "in-zone": "Added.Example.",
      "in-group": "full",
      "in-ns": "ns2.example.net.",
    },
    "^Created added\\.example\\.",
  );
  await soaShown(b);
  const added = (await t.rows("zone-list")).find(
    (r) => r[0] === "added.example.",
  );
  t.eq(
    added,
    [
      "added.example.",
      "full",
      "ns1.added.example. hostmaster.added.example. 1 3600 600 86400 300",
    ],
    "new zone listed",
  );
  const catalog = await env.records("catalog.test");
  const ptr = catalog.find((r) => r[2] === "PTR" && r[3] === "added.example.");
  t.ok(ptr, "PTR on the server");
  const id = ptr[0].split(".")[0];
  t.ok(
    catalog.some((r) => r[0] === `group.${id}.zones` && r[3] === '"full"'),
    "group on the server",
  );
  t.eq(
    (await env.records("added.example"))
      .filter((r) => r[2] === "NS")
      .map((r) => r[3])
      .sort(),
    ["ns1.added.example.", "ns2.example.net."],
    "NS records on the server",
  );
  t.ok(
    await b.ev(`return [...document.querySelectorAll("#zone-list .vlist-row")]
      .find((r) => r.children[0].textContent === "added.example.").querySelector(".c-ns").textContent
      === "ns2.example.net.";`),
    "additional NS shown",
  );

  // a zone without group, with its own SOA
  await addZone(
    {
      "in-zone": "nogroup.example",
      "in-soa": "ns.example.net. admin.example.net. 5 3600 600 86400 60",
    },
    "^Created nogroup",
  );
  await soaShown(b);
  t.eq(
    (await t.rows("zone-list")).find((r) => r[0] === "nogroup.example."),
    [
      "nogroup.example.",
      "",
      "ns.example.net. admin.example.net. 5 3600 600 86400 60",
    ],
    "zone without group",
  );
  t.eq(
    (await env.records("nogroup.example"))
      .filter((r) => r[2] === "NS")
      .map((r) => r[3]),
    ["ns.example.net."],
    "the primary nameserver gets its NS record",
  );

  // errors keep the row
  await addZone({ "in-zone": "added.example" }, "already in the catalog");
  for (const [values, error] of [
    [{ "in-zone": "." }, "must not be empty"],
    [{ "in-zone": "a..b" }, "empty label"],
    [
      { "in-zone": "bad.example", "in-soa": "ns1 hostmaster" },
      "invalid SOA data",
    ],
    [{ "in-soa": "ns1 hostmaster 1 2 3 4 5", "in-ns": "x..y" }, "empty label"],
  ]) {
    await t.clearStatus();
    await fillZoneRow(t, null, values);
    await t.waitStatus(error);
  }
  await b.ev(`[...document.querySelectorAll("#zone-list .vlist-row.editing")]
    .find((r) => !r.querySelector(".in-zone").hidden).querySelector(".row-del").click();`);

  // removal: dismissed, then confirmed
  b.acceptDialogs = false;
  await t.rowAction("zone-list", ["added.example."], "row-del");
  await sleep(300);
  t.ok(
    (await t.rows("zone-list")).some((r) => r[0] === "added.example."),
    "removal dismissed",
  );
  b.acceptDialogs = true;
  for (const zone of ["added.example.", "nogroup.example."]) {
    await t.rowAction("zone-list", [zone], "row-del");
    await t.waitStatus("Removed " + re(zone));
  }
  t.eq(
    b.dialogs.map((d) => d[0]),
    ["confirm", "confirm", "confirm"],
    "confirmations",
  );
  t.ok(
    !(await env.records("catalog.test")).some((r) =>
      /added|nogroup/.test(r[3]),
    ),
    "removed on the server",
  );
});

test("catalog: member zones and history navigation", async (t) => {
  const { b } = t;
  await t.login("catalog.test");
  t.eq(
    await b.ev(`return history.state;`),
    { view: "zone", depth: 0 },
    "catalog entry",
  );

  const catalogMeta = await t.text("catalog-meta");
  t.ok(/^serial \d+ · catalog of \d+ zones$/.test(catalogMeta), catalogMeta);
  t.eq(
    (await path(b)).map((p) => p[0]),
    ["admin2136", "catalog.test."],
    "path of the catalog",
  );
  const catalogAt = await catalogBox(b);
  await t.rowAction("zone-list", ["full.example."], "c-zone");
  await b.wait(
    `${SHOWN} === "full.example."`,
    "member",
  );
  await t.waitStatus("Zone loaded");
  t.eq(
    await b.ev(`return history.state;`),
    { view: "zone", depth: 1 },
    "member entry",
  );
  t.ok(
    await b.ev(`return document.getElementById("raw-btn").hidden;`),
    "no raw toggle",
  );
  // the path keeps the catalog (in place) and adds the zone; the catalog
  // leads back
  const memberPath = await path(b);
  t.eq(
    memberPath.slice(0, 2).map((p) => p[0]).concat([memberPath[1][1]]),
    ["admin2136", "catalog.test.", catalogMeta],
    "path of a member zone: the catalog as it was",
  );
  t.eq(memberPath[2][0], "full.example.", "and the zone");
  t.ok(/^serial \d+ · \d+ records$/.test(memberPath[2][1]), memberPath[2][1]);
  t.eq(await catalogBox(b), catalogAt, "the catalog stays in place");
  await b.ev(`document.getElementById("catalog-title").click();`);
  await b.wait(
    `${SHOWN} === "catalog.test."
    && document.getElementById("zone-view").classList.contains("catalog-mode")`,
    "back to catalog",
  );
  t.eq(await b.ev(`return history.state.depth;`), 0, "catalog entry again");
  t.eq((await path(b)).length, 2, "no zone in the path");
  // clicking the catalog in the catalog view does nothing
  await b.ev(`document.getElementById("catalog-title").click();`);
  await sleep(100);
  t.eq(await b.ev(`return history.state.depth;`), 0, "still the catalog");
  // its raw records show it as a zone
  await t.click("raw-btn");
  t.eq(
    (await path(b)).map((p) => p[0]),
    ["admin2136", "catalog.test."],
    "raw records path",
  );
  t.ok(
    await b.ev(`return document.getElementById("catalog-title").hidden
      && !document.getElementById("zone-title").hidden;`),
    "as a zone",
  );
  t.ok(
    (await b.ev(`return document.getElementById("zone-meta").textContent;`))
      .endsWith(" records"),
    "record count",
  );
  await t.click("raw-btn");
  await b.ev(`history.back();`);
  await b.wait(
    `!document.getElementById("login-view").hidden`,
    "back to login",
  );
  // edits on the login form are undone by going forward
  await t.set("zone", "changed.example");
  await b.ev(`history.forward();`);
  await b.wait(
    `${SHOWN} === "catalog.test."
    && !document.getElementById("zone-view").hidden`,
    "forward to catalog",
  );
  await b.ev(`history.forward();`);
  await b.wait(
    `${SHOWN} === "full.example."`,
    "forward to member",
  );
  // the brand leads back to the login form
  await b.ev(`document.getElementById("brand").click();`);
  await b.wait(`!document.getElementById("login-view").hidden`, "login again");
  await b.ev(`document.getElementById("brand").click();`); // no effect here
  await sleep(100);
  t.eq(await b.ev(`return history.state;`), null, "first entry");
  t.eq(await t.value("zone"), "catalog.test", "login form restored");
  await b.ev(`history.forward();`);
  await b.wait(
    `${SHOWN} === "catalog.test."`,
    "catalog again",
  );

  // opening another member replaces the forward history
  await t.rowAction("zone-list", ["big.example."], "row-open");
  await b.wait(
    `${SHOWN} === "big.example."`,
    "big",
  );
  await b.ev(`history.back();`);
  await b.wait(
    `${SHOWN} === "catalog.test."`,
    "catalog",
  );
  await b.ev(`history.forward();`);
  await b.wait(
    `${SHOWN} === "big.example."`,
    "big again",
  );

  // a reload loses the sessions: back to the login form, and stale
  // forward entries are skipped
  await b.reload();
  await b.wait(
    `!document.getElementById("login-view").hidden && history.state === null`,
    "reload lands on login",
  );
  await b.ev(`history.forward();`);
  await sleep(500);
  t.ok(await t.visible("login-view"), "stale entries skipped");
});

// ---- record editing ----

test("records: add, edit and delete records of many types", async (t) => {
  const { b } = t;
  await t.login("full.example");
  const records = [
    ["e2e-a", "A", "192.0.2.50"],
    ["e2e-aaaa", "AAAA", "2001:db8::50"],
    ["e2e-cname", "CNAME", "www"],
    ["e2e-mx", "MX", "10 mail"],
    ["e2e-txt", "TXT", '"hello" "world"'],
    ["e2e-caa", "CAA", '0 issuewild ";"'],
    ["e2e-https", "HTTPS", '1 . alpn="h2" port=8443'],
    ["_sip._udp.e2e", "SRV", "0 5 5060 sip.example.net."],
    ["e2e-tlsa", "TLSA", "3 1 1 aabbcc"],
    ["e2e-sshfp", "SSHFP", "4 2 0123456789abcdef"],
  ];
  for (const [name, type, data] of records) {
    await t.click("add-btn");
    await t.set("edit-type", type);
    t.ok(
      (await b.ev(`return document.getElementById("edit-data").placeholder;`))
        .length > 0,
      type + " hint",
    );
    await t.fillEditor({ name, ttl: 600, data });
    await t.waitStatus(`^Added ${re(name)} ${type} record`);
  }
  await t.expectInSync("full.example");

  // edit: data, TTL and name
  await t.editRecord(["e2e-a", null, "A"], {
    name: "e2e-a2",
    ttl: 120,
    data: "192.0.2.51",
  });
  await t.editRecord(["e2e-txt", null, "TXT"], { data: "unquoted text" });
  await t.expectInSync("full.example");

  // invalid input stays in the dialog
  await t.click("add-btn");
  await t.fillEditor({ name: "bad", type: "A", data: "300.1.2.3" });
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("invalid A data")`,
    "invalid data",
  );
  await t.fillEditor({ type: "MX", data: "10" });
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("too few fields")`,
    "too few fields",
  );
  await t.click("edit-cancel");

  // read-only rows
  const flags = async (q) => {
    await t.set("filter", q);
    await sleep(300);
    return b.ev(`
      return [...document.querySelectorAll("#record-list .vlist-row")]
        .filter((r) => r.style.display !== "none")
        .map((r) => [r.children[2].textContent, r.querySelector(".row-edit").disabled,
                     r.querySelector(".row-del").disabled, r.classList.contains("readonly")]);`);
  };
  t.eq(
    await flags("LOC"),
    [["LOC", true, false, true]],
    "LOC (unsupported) is read-only",
  );
  t.eq(
    await flags("SOA"),
    [["SOA", false, true, false]],
    "SOA editable, not deletable",
  );
  t.ok((await t.rows()).length === 1, "filtered");
  await t.set("filter", "");
  await sleep(300);

  // delete: dismissed, then confirmed
  b.acceptDialogs = false;
  await t.rowAction("record-list", ["e2e-a2", null, "A"], "row-del");
  await sleep(300);
  b.acceptDialogs = true;
  t.ok(
    (await t.rows()).some((r) => r[0] === "e2e-a2"),
    "delete dismissed",
  );
  for (const [name, type] of records.slice(1)) {
    await t.deleteRecord([name, null, type], `^Deleted ${re(name)} ${type}`);
  }
  await t.deleteRecord(["e2e-a2", null, "A"]);
  await t.expectInSync("full.example");

  // filter
  await t.set("filter", "aaaa");
  await sleep(300);
  t.ok(
    (await t.rows()).every((r) => r[2] === "AAAA"),
    "filter by type",
  );
  await t.set("filter", "192.0.2.31");
  await sleep(300);
  t.eq(
    (await t.rows()).map((r) => r[0]),
    ["mail"],
    "filter by data",
  );
  await t.set("filter", "");
});

test("records: SOA edits keep the serial managed", async (t) => {
  const { b, env } = t;
  await t.login("full.example");
  const soaText = async () => (await t.rows()).find((r) => r[2] === "SOA")[3];
  const before = (await soaText()).split(" ");
  const serial = Number(before[2]);

  await t.rowAction("record-list", [null, null, "SOA"], "row-edit");
  t.eq(await t.text("edit-title"), "Edit SOA record", "title");
  t.ok(
    await b.ev(`return document.getElementById("edit-type").disabled
    && document.getElementById("edit-name").disabled;`),
    "name and type locked",
  );
  // the serial must stay
  const changed = [...before];
  changed[2] = String(serial + 10);
  await t.fillEditor({ data: changed.join(" ") });
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("incremented automatically")`,
    "serial change refused",
  );
  // unchanged
  await t.fillEditor({ data: before.join(" ") });
  await t.waitStatus("SOA record unchanged");
  // change rname and minimum
  await t.rowAction("record-list", [null, null, "SOA"], "row-edit");
  const edited = [...before];
  edited[1] = "admin.full.example.";
  edited[6] = "120";
  await t.fillEditor({ data: edited.join(" ") });
  await t.waitStatus(`Updated SOA record \\(serial ${serial + 1}\\)`);
  t.eq(await env.serial("full.example"), serial + 1, "server serial");
  await t.expectInSync("full.example");

  // the add dialog does not offer SOA
  await t.click("add-btn");
  t.ok(
    !(await b.ev(
      `return [...document.getElementById("edit-type").options].some((o) => o.value === "SOA");`,
    )),
    "SOA not addable",
  );
  await t.click("edit-cancel");
});

test("records: concurrent SOA change is merged", async (t) => {
  const { env } = t;
  await t.login("full.example");
  const soa = (await t.rows()).find((r) => r[2] === "SOA")[3].split(" ");
  // another client changes the SOA (retry) and other records meanwhile
  const serial = await env.serial("full.example");
  await env.knsupdate("full.example", [
    "update add race1.full.example. 300 A 192.0.2.61",
  ]);
  await env.knsupdate("full.example", [
    `update add full.example. 3600 SOA ${soa[0]} ${soa[1]} ${serial + 5} ${soa[3]} 900 ${soa[5]} ${soa[6]}`,
  ]);
  const raced = await env.serial("full.example");
  // our edit, based on the old SOA: expire
  await t.rowAction("record-list", [null, null, "SOA"], "row-edit");
  const edited = [...soa];
  edited[5] = "999999";
  await t.fillEditor({ ttl: 1800, data: edited.join(" ") });
  await t.waitStatus(`Updated SOA record \\(serial ${raced + 1}\\)`);
  const server = (await env.records("full.example")).find(
    (r) => r[2] === "SOA",
  );
  t.eq(server[1], "1800", "TTL from our edit");
  const f = server[3].split(" ");
  t.eq(
    [f[4], f[5]],
    ["900", "999999"],
    "retry from the other client, expire from ours",
  );
  await t.refresh();
  await t.expectInSync("full.example", "kc", { withSoa: true });
});

// ---- TSIG keys per zone ----

test("keys: update rejected, separate update key", async (t) => {
  const { b, env } = t;
  await t.login("xfr.example"); // kc: transfer only
  await t.addRecord({ name: "e2e-k1", type: "A", data: "192.0.2.70" }, null);
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  t.eq(await t.text("key-title"), "Update rejected", "prompt title");
  t.ok((await t.text("key-message")).includes("NOTAUTH"), "prompt message");
  // wrong key, malformed key, then the right one
  await t.set("key-input", env.spec("kz"));
  await t.click("key-submit");
  await b.wait(
    `document.getElementById("key-status").textContent.startsWith("✗")`,
    "wrong key",
  );
  await t.set("key-input", "garbage");
  await t.click("key-submit");
  await b.wait(
    `document.getElementById("key-status").textContent.includes("TSIG secret")`,
    "malformed",
  );
  await t.set("key-input", env.spec("ku"));
  await t.click("key-submit");
  await t.waitStatus("^Added e2e-k1 A record");
  t.ok(
    !(await b.ev(`return document.getElementById("key-dialog").open;`)),
    "prompt closed",
  );
  // further updates use the update key right away
  await t.deleteRecord(["e2e-k1", null, "A"]);
  t.ok(
    !(await b.ev(`return document.getElementById("key-dialog").open;`)),
    "no prompt",
  );
  await t.expectInSync("xfr.example");

  // giving up reports the original error
  await t.login("xfr.example");
  await t.addRecord({ name: "e2e-k2", type: "A", data: "192.0.2.71" }, null);
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  await t.click("key-cancel");
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("update failed: NOTAUTH")`,
    "original error",
  );
  await t.click("edit-cancel");
  // Escape gives up as well
  await t.deleteRecord(["www", null, "A"], null);
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  await b.ev(
    `document.getElementById("key-dialog").dispatchEvent(new Event("cancel", { cancelable: true }));`,
  );
  await t.waitStatus("delete failed: update failed: NOTAUTH");
});

test("keys: member zone with its own key", async (t) => {
  const { b, env } = t;
  await t.login("catalog.test");
  await soaShown(b); // before the proxy is gone, so that their failure
  // does not replace the status of opening the zone

  // no response at all (the proxy is gone): another key would not help,
  // so there is no prompt, just the error
  await env.stopDows();
  try {
    await b.ev(`document.getElementById("status-bar").textContent = "";`);
    await t.rowAction("zone-list", ["full.example."], "row-open");
    await t.waitStatus("✗ opening full.example. failed: could not connect");
    await sleep(300);
    t.ok(
      !(await b.ev(`return document.getElementById("key-dialog").open;`)),
      "no key prompt without a response",
    );
  } finally {
    await env.startDows();
  }

  // refused by the server: another key may help
  await t.rowAction("zone-list", ["own.example."], "row-open");
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  t.eq(await t.text("key-title"), "Transfer refused", "title");
  t.ok((await t.status()).includes("opening own.example. failed"), "status");
  await t.click("key-cancel");
  await sleep(200);
  t.eq(await b.ev(`return history.state.depth;`), 0, "still on the catalog");
  // again, with the zone's key
  await t.rowAction("zone-list", ["own.example."], "c-zone");
  await b.wait(
    `document.getElementById("key-dialog").open`,
    "key prompt again",
  );
  await t.set("key-input", env.spec("kz"));
  await t.click("key-submit");
  await b.wait(
    `${SHOWN} === "own.example."`,
    "opened",
  );
  await t.waitStatus("Zone loaded");
  t.eq(await b.ev(`return history.state.depth;`), 1, "member entry");
  // updates use the same key
  await t.addRecord({ name: "e2e-own", type: "TXT", data: "own key" });
  t.ok(
    !(await b.ev(`return document.getElementById("key-dialog").open;`)),
    "no update prompt",
  );
  await t.expectInSync("own.example", "kz");
  await t.deleteRecord(["e2e-own", null, "TXT"]);
});

// ---- refresh ----

test("refresh: up to date, IXFR, full zone", async (t) => {
  const { env } = t;
  await t.login("full.example");
  t.ok(
    /^Zone is up to date \(serial \d+\)\.$/.test(await t.refresh()),
    "up to date",
  );

  await env.knsupdate("full.example", [
    "update add ixfr-1.full.example. 300 A 192.0.2.81",
    'update add ixfr-2.full.example. 300 TXT "two"',
  ]);
  await env.knsupdate("full.example", [
    "update delete ixfr-2.full.example. TXT",
    'update add ixfr-2.full.example. 300 TXT "changed"',
    "update delete www.full.example. AAAA",
    "update add www.full.example. 120 AAAA 2001:db8::30",
  ]);
  const msg = await t.refresh();
  t.ok(
    /^Updated via IXFR \(serial \d+ → \d+\): \d+ records? added, \d+ records? deleted\.$/.test(
      msg,
    ),
    msg,
  );
  await t.expectInSync("full.example", "kc", { withSoa: true });

  // without journal back to our version, the server sends the whole zone
  await env.knsupdate("full.example", [
    "update add ixfr-3.full.example. 300 A 192.0.2.83",
  ]);
  await env.knotc("zone-purge", "-f", "full.example", "+journal");
  await env.knsupdate("full.example", [
    "update add ixfr-4.full.example. 300 A 192.0.2.84",
  ]);
  const full = await t.refresh();
  t.ok(
    full.startsWith("Zone reloaded, the server sent the full zone"),
    "full zone: " + full,
  );
  await t.expectInSync("full.example", "kc", { withSoa: true });
  await env.knsupdate("full.example", [
    "update delete ixfr-1.full.example.",
    "update delete ixfr-2.full.example.",
    "update delete ixfr-3.full.example.",
    "update delete ixfr-4.full.example.",
  ]);
});

test("refresh: catalog follows membership changes", async (t) => {
  const { env } = t;
  await t.login("catalog.test");
  await env.knsupdate("catalog.test", [
    "update add oob.zones.catalog.test. 0 PTR oob.example.",
  ]);
  await t.refresh();
  t.ok(
    (await t.rows("zone-list")).some((r) => r[0] === "oob.example."),
    "new member listed",
  );
  await env.knsupdate("catalog.test", [
    "update delete oob.zones.catalog.test.",
  ]);
  await t.refresh();
  t.ok(
    !(await t.rows("zone-list")).some((r) => r[0] === "oob.example."),
    "member gone",
  );
});

// ---- updates the server acknowledges but ignores (mod-ignoreme) ----

test("ignored updates: refresh shows the server's zone", async (t) => {
  const { b, env } = t;
  await t.login("full.example");
  // ignored: an addition, a deletion, a rename onto an ignored name and
  // a TTL change -- each answered with NOERROR
  await t.addRecord({ name: "ignore-me", type: "TXT", data: "phantom" });
  await t.addRecord({ name: "ignore-me.sub", type: "A", data: "192.0.2.90" });
  await t.deleteRecord(["ignore-me", null, "A"]);
  await t.addRecord({ name: "rename-me", type: "A", data: "192.0.2.91" });
  await t.editRecord(["rename-me", null, "A"], { name: "ignore-me" });
  // plus a real change, by another client
  await env.knsupdate("full.example", [
    "update add real.full.example. 300 A 192.0.2.92",
  ]);
  const shown = await t.rows();
  t.ok(
    shown.some((r) => r[0] === "ignore-me" && r[2] === "TXT"),
    "app shows the phantom",
  );

  const msg = await t.refresh();
  t.ok(msg.startsWith("Updated via IXFR"), msg);
  await t.expectInSync("full.example", "kc", { withSoa: true });
  const rows = await t.rows();
  t.ok(
    rows.some((r) => r[0] === "ignore-me" && r[3] === "192.0.2.99"),
    "ignored deletion undone",
  );
  t.ok(!rows.some((r) => r[0] === "rename-me"), "rename: deletion applied");
  t.ok(!rows.some((r) => r[0] === "ignore-me.sub"), "phantom gone");

  // nothing else changed on the server: up to date, phantoms discarded
  await t.addRecord({ name: "ignore-me", type: "A", data: "192.0.2.93" });
  await t.editRecord(["ignore-me", null, "A"], { ttl: 42 });
  t.ok(
    (await t.refresh()).includes(
      "discarded local changes the server did not apply",
    ),
    "phantoms discarded",
  );
  await t.expectInSync("full.example", "kc", { withSoa: true });
  await env.knsupdate("full.example", ["update delete real.full.example."]);
});

test("ignored updates: catalog raw records", async (t) => {
  await t.login("catalog.test");
  await t.click("raw-btn");
  await t.addRecord({ name: "ignore-me", type: "TXT", data: "phantom" });
  t.ok(
    (await t.rows()).some((r) => r[0] === "ignore-me"),
    "phantom shown",
  );
  t.ok((await t.refresh()).includes("discarded local changes"), "discarded");
  t.ok(!(await t.rows()).some((r) => r[0] === "ignore-me"), "phantom gone");
});

// ---- large zones ----

test("big zone: virtual list scrolling and filter", async (t) => {
  const { b } = t;
  await t.login("big.example");
  t.ok(
    (await t.text("zone-meta")).includes("30003 records"),
    await t.text("zone-meta"),
  );
  // only a window of rows is rendered
  const rendered =
    await b.ev(`return [...document.querySelectorAll("#record-list .vlist-row")]
    .filter((r) => r.style.display !== "none").length;`);
  t.ok(rendered > 5 && rendered < 100, "rendered rows: " + rendered);
  await b.ev(
    `const l = document.getElementById("record-list"); l.scrollTop = l.scrollHeight;`,
  );
  await b.wait(
    `[...document.querySelectorAll("#record-list .vlist-row")]
    .some((r) => r.style.display !== "none" && r.children[0].textContent === "host9999")`,
    "last row after scrolling",
  );
  await t.set("filter", "10.0.11.183");
  await b.wait(
    `document.querySelectorAll("#record-list .vlist-row:not([style*='display: none'])").length === 1`,
    "filtered",
  );
  t.eq(
    (await t.rows()).map((r) => r[0]),
    ["host2999"],
    "filter result",
  );
});

// Widths of the header cells and of the cells of the first row of a list.
const colWidths = (b, header, list) =>
  b.ev(`const w = (el) => [...el.children].map((c) => Math.round(c.getBoundingClientRect().width));
    return [w(document.getElementById(${JSON.stringify(header)})),
      w(document.querySelector("#${list} .vlist-row"))];`);

// Drag the resize handle of column `col` of a header by `dx` pixels with
// real mouse events.
async function dragColumn(b, header, col, dx, button = "left") {
  const [x, y] = await b.ev(`
    const h = document.querySelectorAll("#${header} .col-resize")[${col}];
    const r = h.getBoundingClientRect();
    return [r.x + r.width / 2, r.y + r.height / 2];`);
  const mouse = (type, x, buttons) =>
    b.send("Input.dispatchMouseEvent", {
      type,
      x,
      y,
      button,
      buttons,
      clickCount: 1,
    });
  const buttons = button === "left" ? 1 : 2;
  await mouse("mouseMoved", x, 0);
  await mouse("mousePressed", x, buttons);
  await mouse("mouseMoved", x + dx / 2, buttons);
  await mouse("mouseMoved", x + dx, buttons);
  await mouse("mouseReleased", x + dx, 0);
}

test("columns: resize, clamp, persist and reset", async (t) => {
  const { b } = t;
  await t.login("full.example");
  const [h0, r0] = await colWidths(b, "list-header", "record-list");
  t.eq(r0, h0, "rows follow the header");

  // widen the name column; the data column gives up the width
  await dragColumn(b, "list-header", 0, 100);
  const [h1, r1] = await colWidths(b, "list-header", "record-list");
  t.eq(h1[0], h0[0] + 100, "name column wider");
  t.eq(h1[3], h0[3] - 100, "data column narrower");
  t.eq(r1, h1, "rows follow the resized header");

  // only the left button resizes
  await dragColumn(b, "list-header", 1, 50, "right");
  await dragColumn(b, "list-header", 1, 0, "right");
  t.eq((await colWidths(b, "list-header", "record-list"))[0], h1, "right drag");

  // the data column keeps its minimum width, the others theirs
  await dragColumn(b, "list-header", 2, 5000);
  const [h2] = await colWidths(b, "list-header", "record-list");
  t.eq(h2[3], 200, "data column at its minimum");
  await dragColumn(b, "list-header", 1, -5000);
  const [h3] = await colWidths(b, "list-header", "record-list");
  t.eq(h3[1], 40, "TTL column at its minimum");

  // kept across page loads
  await t.login("full.example");
  t.eq(
    (await colWidths(b, "list-header", "record-list"))[0],
    h3,
    "widths restored",
  );

  // double-click restores the defaults
  await b.ev(
    `document.querySelector("#list-header .col-resize").dispatchEvent(new MouseEvent("dblclick"));`,
  );
  t.eq(
    (await colWidths(b, "list-header", "record-list"))[0],
    h0,
    "widths reset",
  );
  t.eq(
    await b.ev(`return localStorage.getItem("admin2136-record-cols");`),
    null,
    "reset widths not stored",
  );

  // stored garbage is ignored
  await b.ev(`localStorage.setItem("admin2136-record-cols", "[1, 2]");
    localStorage.setItem("admin2136-zone-cols", "{");`);
  await t.login("catalog.test");
  await soaShown(b);
  const [z0, zr0] = await colWidths(b, "zone-header", "zone-list");
  t.eq(zr0, z0, "catalog rows follow the header");

  // the catalog view has its own widths
  await dragColumn(b, "zone-header", 2, -60);
  const [z1, zr1] = await colWidths(b, "zone-header", "zone-list");
  t.eq(z1[2], z0[2] - 60, "SOA column narrower");
  t.eq(z1[3], z0[3] + 60, "NS column wider");
  t.eq(zr1, z1, "catalog rows follow the resized header");
  await t.login("full.example");
  t.eq(
    (await colWidths(b, "list-header", "record-list"))[0],
    h0,
    "record columns unaffected",
  );
  await b.ev(`localStorage.removeItem("admin2136-zone-cols");`);
});

// ---- more branches ----

test("catalog: rejected catalog updates, groupless members", async (t) => {
  const { b, env } = t;
  // ku may transfer the catalog, but not update it
  await t.login("catalog.test", "ku");
  await t.click("add-btn");
  await fillZoneRow(t, null, {
    "in-zone": "keyed.example",
    "in-group": "x".repeat(300),
  });
  await t.waitStatus("exceeds 255 bytes");
  await t.clearStatus();
  await fillZoneRow(t, null, { "in-group": "" });
  await b.wait(
    `document.getElementById("key-dialog").open`,
    "key prompt for the catalog",
  );
  await t.set("key-input", env.spec("kc"));
  await t.click("key-submit");
  // the zone's records are added with the catalog's update key as well
  await t.waitStatus("^Created keyed\\.example\\.");
  t.ok(
    (await t.rows("zone-list")).some(
      (r) => r[0] === "keyed.example." && r[1] === "",
    ),
    "groupless zone listed",
  );
  // the filter also looks at (missing) groups
  await t.set("filter", "zzz-no-match");
  await sleep(300);
  t.eq(await t.rows("zone-list"), [], "nothing matches");
  await t.set("filter", "");

  // removal: the update key of this session is kc now, so use a fresh
  // session and give up at the prompt
  await t.login("catalog.test", "ku");
  await t.rowAction("zone-list", ["keyed.example."], "row-del");
  await b.wait(
    `document.getElementById("key-dialog").open`,
    "key prompt for removal",
  );
  await t.click("key-cancel");
  await t.waitStatus(
    "✗ removing keyed.example. failed: update failed: NOTAUTH",
  );
  await t.rowAction("zone-list", ["keyed.example."], "row-del");
  await b.wait(
    `document.getElementById("key-dialog").open`,
    "key prompt for removal",
  );
  await t.set("key-input", env.spec("kc"));
  await t.click("key-submit");
  await t.waitStatus("Removed keyed.example.");
});

test("keys: concurrent SOA change while asking for the update key", async (t) => {
  const { b, env } = t;
  await t.login("xfr.example"); // kc: transfer only
  const soa = (await t.rows()).find((r) => r[2] === "SOA")[3].split(" ");
  await t.rowAction("record-list", [null, null, "SOA"], "row-edit");
  const edited = [...soa];
  edited[6] = "77";
  await t.fillEditor({ data: edited.join(" ") });
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  // meanwhile, another client raises the serial
  const serial = await env.serial("xfr.example");
  await env.knsupdate(
    "xfr.example",
    [
      `update add xfr.example. 3600 SOA ${soa[0]} ${soa[1]} ${serial + 3} ${soa.slice(3).join(" ")}`,
    ],
    "ku",
  );
  // with the key, the update reaches the server, fails its prerequisite,
  // and is retried on top of the new SOA
  await t.set("key-input", env.spec("ku"));
  await t.click("key-submit");
  await t.waitStatus(`Updated SOA record \\(serial ${serial + 4}\\)`);
  const f = (await env.records("xfr.example"))
    .find((r) => r[2] === "SOA")[3]
    .split(" ");
  t.eq([f[2], f[6]], [String(serial + 4), "77"], "merged SOA on the server");
});

test("unsigned zone: login, edits, SOA race, serial going back", async (t) => {
  const { b, env } = t;
  await t.login("open.example", null);
  await t.addRecord({ name: "u1", type: "A", data: "192.0.2.41" });
  await t.editRecord(["u1", null, "A"], { data: "192.0.2.42" });
  await t.expectInSync("open.example", null);

  // SOA race without TSIG (the current SOA is queried unsigned)
  const soa = (await t.rows()).find((r) => r[2] === "SOA")[3].split(" ");
  const serial = await env.serial("open.example", null);
  await env.knsupdate(
    "open.example",
    [
      `update add open.example. 3600 SOA ${soa[0]} ${soa[1]} ${serial + 2} ${soa.slice(3).join(" ")}`,
    ],
    null,
  );
  await t.rowAction("record-list", [null, null, "SOA"], "row-edit");
  const edited = [...soa];
  edited[3] = "7200";
  await t.fillEditor({ data: edited.join(" ") });
  await t.waitStatus(`Updated SOA record \\(serial ${serial + 3}\\)`);

  // the zone is reset to its zone file: its serial goes back
  t.ok((await t.refresh()).startsWith("Updated via IXFR"), "caught up");
  await env.knotc("zone-purge", "-f", "open.example", "+journal");
  await env.knotc("zone-reload", "-f", "open.example");
  await b.wait("true");
  for (let i = 0; i < 50 && (await env.serial("open.example", null)) !== 1; i++)
    await sleep(100);
  const msg = await t.refresh();
  t.ok(msg.startsWith("Zone reloaded via AXFR, server serial went back"), msg);
  await t.expectInSync("open.example", null, { withSoa: true });
  t.ok(!(await t.rows()).some((r) => r[0] === "u1"), "back to the zone file");

  // an empty key in the prompt means unsigned
  await t.login("xfr.example");
  await t.addRecord(
    { name: "e2e-unsigned", type: "A", data: "192.0.2.43" },
    null,
  );
  await b.wait(`document.getElementById("key-dialog").open`, "key prompt");
  await t.set("key-input", "");
  await t.click("key-submit");
  await b.wait(
    `document.getElementById("key-status").textContent.includes("NOTAUTH")`,
    "unsigned update rejected",
  );
  await t.click("key-cancel");
  await t.click("edit-cancel");
});

test("edge cases: settings, insecure context, bypassed form validation", async (t) => {
  const { b, env } = t;
  // corrupt saved settings are ignored
  await b.ev(`localStorage.setItem("admin2136-settings", "{corrupt");`);
  await t.open();
  t.eq(await t.value("zone"), "", "no zone restored");
  // non-WebSocket proxy URL: no about link
  await t.set("proxy-url", "http://proxy.example/");
  t.eq(
    await b.ev(
      `return document.getElementById("proxy-about-link").hasAttribute("href");`,
    ),
    false,
    "no about link for http",
  );
  // a URL the browser cannot open as WebSocket (form validation bypassed)
  await t.set("nameserver", env.nameserver);
  await t.set("zone", "full.example");
  await t.set("tsig", env.spec("kc"));
  await t.set("proxy-url", "ws://[");
  await b.ev(
    `document.getElementById("login-form").dispatchEvent(new Event("submit", { cancelable: true }));`,
  );
  await b.wait(
    `document.getElementById("login-status").textContent.includes("invalid WebSocket URL")`,
    "invalid WebSocket URL",
  );
  // without Web Crypto (insecure context), TSIG is impossible
  await t.set("proxy-url", env.proxyUrl);
  await b.ev(
    `Object.defineProperty(window.crypto, "subtle", { value: undefined });`,
  );
  await t.click("login-btn");
  await b.wait(
    `document.getElementById("login-status").textContent.includes("Web Crypto unavailable")`,
    "no Web Crypto",
  );

  // record editor: TTL and type checks behind the form validation
  await t.login("full.example");
  await t.click("add-btn");
  await t.set("edit-name", "x");
  await t.set("edit-ttl", "-5");
  await t.set("edit-data", "192.0.2.1");
  await b.ev(
    `document.getElementById("edit-form").dispatchEvent(new Event("submit", { cancelable: true }));`,
  );
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("invalid TTL")`,
    "invalid TTL",
  );
  await t.set("edit-ttl", "300");
  await b.ev(`document.getElementById("edit-type").value = "NOPE";`);
  await b.ev(
    `document.getElementById("edit-form").dispatchEvent(new Event("submit", { cancelable: true }));`,
  );
  await b.wait(
    `document.getElementById("edit-status").textContent.includes("unknown record type")`,
    "unknown type",
  );
  // navigating away closes dialogs
  await b.ev(`history.back();`);
  await b.wait(
    `!document.getElementById("edit-dialog").open && !document.getElementById("login-view").hidden`,
    "dialog closed by navigation",
  );
  // logging in again replaces the connection of the previous login
  await t.submitLogin({ zone: "xfr.example" });
  await b.wait(
    `${SHOWN} === "xfr.example."`,
    "second login",
  );
  await t.waitStatus("Zone loaded");
});

test("edge cases: concurrent actions", async (t) => {
  const { b, env } = t;
  await t.login("catalog.test");
  // double click on open: one session only
  await b.ev(`const row = [...document.querySelectorAll("#zone-list .vlist-row")]
    .find((r) => r.children[0].textContent === "full.example.");
    row.querySelector(".row-open").click();
    row.querySelector(".c-zone").click();`);
  await b.wait(
    `${SHOWN} === "full.example."`,
    "opened",
  );
  t.eq(await b.ev(`return history.state.depth;`), 1, "one history entry");
  await b.ev(`history.back();`);
  await b.wait(
    `${SHOWN} === "catalog.test."`,
    "catalog",
  );

  // a member opened while the catalog is not shown (a stale click):
  // the zone is loaded in the background, but not entered
  await b.ev(`history.back();`);
  await b.wait(`!document.getElementById("login-view").hidden`, "login");
  await b.ev(`[...document.querySelectorAll("#zone-list .vlist-row")]
    .find((r) => r.children[0].textContent === "full.example.")
    .querySelector(".row-open").click();`);
  await sleep(1000);
  t.ok(await t.visible("login-view"), "not taken to the member zone");
  await b.ev(`history.forward();`);
  await b.wait(
    `${SHOWN} === "catalog.test."`,
    "catalog again",
  );

  // a second key prompt while one is open is refused
  await t.login("xfr.example");
  await t.addRecord({ name: "e2e-p1", type: "A", data: "192.0.2.80" }, null);
  await b.wait(`document.getElementById("key-dialog").open`, "first prompt");
  // (behind the modal dialog, triggered by script)
  await b.ev(`[...document.querySelectorAll("#record-list .vlist-row")]
    .find((r) => r.children[0].textContent === "www").querySelector(".row-del").click();`);
  await t.waitStatus("delete failed: update failed: NOTAUTH");
  await t.click("key-cancel");
  await t.click("edit-cancel");

  // two operations needing a new connection at once (the server closed
  // the previous one after refusing a transfer)
  await t.login("catalog.test");
  await t.rowAction("zone-list", ["own.example."], "row-open");
  await b.wait(`document.getElementById("key-dialog").open`, "own key prompt");
  await t.click("key-cancel");
  await sleep(300);
  await t.click("add-btn");
  await fillZoneRow(t, null, { "in-zone": "concurrent.example" }, false);
  await b.ev(`document.getElementById("refresh-btn").click();
    [...document.querySelectorAll("#zone-list .vlist-row.editing")]
      .find((r) => !r.querySelector(".in-zone").hidden).querySelector(".row-check").click();`);
  await b.wait(
    `[...document.querySelectorAll("#zone-list .vlist-row")].some((r) =>
      r.children[0].textContent === "concurrent.example."
      && r.querySelector(".c-soa").textContent.startsWith("ns1.concurrent.example."))`,
    "zone created",
  );
  await t.rowAction("zone-list", ["concurrent.example."], "row-del");
  await t.waitStatus("Removed concurrent.example.");
});

test("refresh: errors, SOA-only changes, mismatching differences", async (t) => {
  const { b, env } = t;
  // a member zone removed from the catalog while it is shown
  fs.writeFileSync(
    env.dir + "/zones/temp.example.zone",
    "@ 3600 SOA ns. h. 1 3600 600 86400 300\n@ 3600 NS ns.\n",
  );
  await env.knsupdate("catalog.test", [
    "update add temp.zones.catalog.test. 0 PTR temp.example.",
  ]);
  for (let i = 0; i < 100; i++) {
    if ((await env.serial("temp.example").catch(() => 0)) === 1) break;
    await sleep(100);
  }
  await t.login("temp.example");
  // only the SOA changes
  await env.knsupdate("temp.example", [
    "update add temp.example. 3600 SOA ns. h. 5 3600 600 86400 300",
  ]);
  t.ok(
    (await t.refresh()).endsWith("only the SOA changed."),
    "SOA-only change",
  );
  await env.knsupdate("catalog.test", [
    "update delete temp.zones.catalog.test.",
  ]);
  for (let i = 0; i < 100; i++) {
    if (!(await env.serial("temp.example").catch(() => 0))) break;
    await sleep(100);
  }
  t.ok(
    (await t.refresh()).startsWith("✗ reload failed: IXFR refused: NOTAUTH"),
    "refresh error",
  );

  // differences that do not fit what we have: the zone was reset, and the
  // server's journal holds a different history for our serial
  await t.login("open.example", null);
  await env.knsupdate(
    "open.example",
    ["update add m1.open.example. 300 A 192.0.2.44"],
    null,
  );
  await env.knsupdate(
    "open.example",
    ["update add m2.open.example. 300 A 192.0.2.45"],
    null,
  );
  t.ok((await t.refresh()).startsWith("Updated via IXFR"), "caught up");
  const ours = await env.serial("open.example", null);
  await env.knotc("zone-purge", "-f", "open.example", "+journal");
  await env.knotc("zone-reload", "-f", "open.example");
  for (let i = 0; i < 50 && (await env.serial("open.example", null)) !== 1; i++)
    await sleep(100);
  await env.knsupdate(
    "open.example",
    ["update add other.open.example. 300 A 192.0.2.46"],
    null,
  );
  for (let s = await env.serial("open.example", null); s < ours; s++) {
    await env.knsupdate(
      "open.example",
      [`update add f${s}.open.example. 300 A 192.0.2.47`],
      null,
    );
  }
  t.eq(
    await env.serial("open.example", null),
    ours,
    "same serial, different history",
  );
  await env.knsupdate(
    "open.example",
    ["update delete other.open.example."],
    null,
  );
  const msg = await t.refresh();
  t.ok(
    msg.startsWith(
      "Zone reloaded via AXFR, the IXFR did not match the last transfer",
    ),
    msg,
  );
  await t.expectInSync("open.example", null, { withSoa: true });
});

test("connection lost: interrupted transfer, reconnect", async (t) => {
  const { b, env } = t;
  // through the slow relay, so that the connection can be cut in the
  // middle of the transfer; a slow page lets messages queue up meanwhile
  await t.open();
  await b.throttle(30);
  try {
    await t.submitLogin({ zone: "big.example", ns: env.slowNameserver });
    await t.waitStatus("Transferring zone… [1-9]", "transfer under way");
    env.relay.cut();
    await t.waitStatus("✗ zone transfer failed", "transfer failed");
  } finally {
    await b.throttle(1);
  }
  // the half-loaded zone: no serial yet
  await b.ev(`history.back();`);
  await b.wait(`!document.getElementById("login-view").hidden`, "login");
  await b.ev(`history.forward();`);
  await b.wait(
    `document.getElementById("zone-meta").textContent.startsWith("serial ?")`,
    "unknown serial",
  );
  // without a complete transfer, a refresh transfers the whole zone
  const reload = await t.refresh();
  t.ok(
    reload.startsWith("Zone reloaded via AXFR (30003 records"),
    "full reload: " + reload,
  );

  // two operations needing the new connection at once
  await env.restartDows();
  await sleep(300);
  await t.click("add-btn");
  await t.set("edit-name", "reconnect");
  await t.set("edit-data", "192.0.2.88");
  await b.ev(
    `document.getElementById("refresh-btn").click(); document.getElementById("edit-save").click();`,
  );
  await b.wait(`!document.getElementById("edit-dialog").open`, "record added");
  await t.set("filter", "reconnect");
  await b.wait(
    `document.querySelector("#record-list .vlist-row:not([style*='display: none'])")?.children[0].textContent === "reconnect"`,
    "filtered",
  );
  await t.deleteRecord(["reconnect", null, "A"]);
});

// ---- setting up new zones ----

// Add a member zone without records to the catalog; resolves once Knot
// has configured it (a SOA query then fails with SERVFAIL).
async function newMember(env, zone, group) {
  const id = zone.split(".")[0];
  await env.knsupdate("catalog.test", [
    `update add ${id}.zones.catalog.test. 0 PTR ${zone}.`,
    `update add group.${id}.zones.catalog.test. 0 TXT "${group}"`,
  ]);
  for (let i = 0; i < 100; i++) {
    if ((await env.kdig(["SOA", zone], null)).includes("status: SERVFAIL"))
      return;
    await sleep(100);
  }
  throw new Error(zone + " not configured");
}

// The zone view of a zone without records: its single row with inputs.
const setupShown = (b, zone) =>
  b.wait(
    `document.getElementById("zone-view").classList.contains("catalog-mode")
    && [...document.querySelectorAll("#zone-list .vlist-row")]
      .filter((r) => r.style.display !== "none")
      .map((r) => r.classList.contains("editing")
        && r.querySelector(".c-zone-cell .c-text").textContent).join() === ${JSON.stringify(zone)}`,
    "row of the zone without records",
  );

test("setup: zones without records in the catalog view", async (t) => {
  const { b, env } = t;
  await newMember(env, "fresh1.example", "full");
  await t.login("catalog.test");
  await b.wait(
    `[...document.querySelectorAll("#zone-list .vlist-row.editing")]
      .some((r) => r.querySelector(".c-zone-cell .c-text").textContent === "fresh1.example.")`,
    "inputs for the zone without records",
  );
  t.ok(
    !(await b.ev(`return document.getElementById("key-dialog").open;`)),
    "no key prompt",
  );
  const row = `[...document.querySelectorAll("#zone-list .vlist-row.editing")]
    .find((r) => r.querySelector(".c-zone-cell .c-text").textContent === "fresh1.example.")`;
  t.eq(
    await b.ev(`const r = ${row}; return [r.querySelector(".c-group").textContent,
      r.querySelector(".in-soa").value, r.querySelector(".row-open").hidden,
      r.querySelector(".row-check").hidden, r.querySelector(".in-zone").hidden];`),
    ["full", "ns1 hostmaster 1 3600 600 86400 300", true, false, true],
    "row of a zone without records",
  );
  // input is kept across a refresh
  await fillZoneRow(
    t,
    "fresh1.example.",
    { "in-soa": "ns1 admin 1 3600 600 86400 300", "in-ns": "ns2.example.net." },
    false,
  );
  await t.refresh();
  await b.wait(
    `${row}?.querySelector(".in-soa").value === "ns1 admin 1 3600 600 86400 300"`,
    "input kept",
  );

  await t.clearStatus();
  await fillZoneRow(t, "fresh1.example.", {});
  await t.waitStatus("^Created fresh1\\.example\\.");
  await soaShown(b);
  t.eq(
    (await t.rows("zone-list")).find((r) => r[0] === "fresh1.example."),
    [
      "fresh1.example.",
      "full",
      "ns1.fresh1.example. admin.fresh1.example. 1 3600 600 86400 300",
    ],
    "created",
  );
  await t.rowAction("zone-list", ["fresh1.example."], "c-zone");
  await b.wait(
    `${SHOWN} === "fresh1.example."`,
    "opened",
  );
  await t.waitStatus("Zone loaded");
  await t.expectInSync("fresh1.example", "kc", { withSoa: true });
  t.eq(
    (await t.rows())
      .filter((r) => r[2] === "NS")
      .map((r) => r[3])
      .sort(),
    ["ns1.fresh1.example.", "ns2.example.net."],
    "NS records",
  );
});

test("setup: direct login, input errors, concurrent setup", async (t) => {
  const { b, env } = t;
  await newMember(env, "fresh2.example", "full");
  await t.open();
  await t.submitLogin({ zone: "fresh2.example" });
  await setupShown(b, "fresh2.example.");
  const row = `[...document.querySelectorAll("#zone-list .vlist-row")]
    .find((r) => r.style.display !== "none")`;
  t.eq(
    await b.ev(`const r = ${row}; return [r.querySelector(".in-soa").value,
      r.querySelector(".in-ns").value, r.querySelector(".c-group").textContent,
      r.querySelector(".c-zone-cell .c-text").title,
      r.querySelector(".row-check").hidden, r.querySelector(".row-del").hidden,
      r.querySelector(".in-zone").hidden];`),
    ["ns1 hostmaster 1 7200 3600 1209600 300", "", "", "fresh2.example.",
      false, true, true],
    "defaults, no removal",
  );
  t.ok(
    await b.ev(`return ["filter", "add-btn", "refresh-btn", "raw-btn"]
      .every((id) => getComputedStyle(document.getElementById(id)).display === "none");`),
    "no list tools",
  );
  const bad = async (soa, ns, pattern) => {
    await t.clearStatus();
    await fillZoneRow(t, "fresh2.example.", { "in-soa": soa, "in-ns": ns });
    await t.waitStatus(pattern);
  };
  await bad("ns1 hostmaster 1 3600 -1 86400 300", "", "✗ creating fresh2\\.example\\. failed");
  await bad("ns1 hostmaster", "", "✗ creating fresh2\\.example\\. failed");
  await bad("a..b hostmaster 1 3600 600 86400 300", "", "empty label");
  await bad("ns1 hostmaster 1 3600 600 86400 300", "x..y", "empty label");
  await fillZoneRow(
    t,
    "fresh2.example.",
    { "in-soa": "ns1 admin 1 3600 600 86400 300", "in-ns": "" },
    false,
  );
  // the input is kept across navigation
  await b.ev(`history.back();`);
  await b.wait(`!document.getElementById("login-view").hidden`, "login");
  await b.ev(`history.forward();`);
  await setupShown(b, "fresh2.example.");
  t.eq(
    await b.ev(`return ${row}.querySelector(".in-soa").value;`),
    "ns1 admin 1 3600 600 86400 300",
    "input kept",
  );

  // someone else sets it up first: the prerequisite fails, the zone loads
  await env.knsupdate("fresh2.example", [
    "update add fresh2.example. 3600 SOA ns.other. h.other. 7 3600 600 86400 300",
    "update add fresh2.example. 3600 NS ns.other.",
  ]);
  await fillZoneRow(t, "fresh2.example.", {});
  await t.waitStatus("Zone created \\(serial 7\\)");
  t.eq(
    (await t.rows()).find((r) => r[2] === "NS")[3],
    "ns.other.",
    "the other setup",
  );
});

test("setup: a signed zone shows its DS records", async (t) => {
  const { b, env } = t;
  await t.login("catalog.test");
  await t.click("add-btn");
  await fillZoneRow(t, null, {
    "in-zone": "fresh3.example",
    "in-group": "signed",
  });
  await b.wait(
    `document.getElementById("dnssec-dialog").open`,
    "DNSSEC records",
  );
  t.eq(await t.text("dnssec-zone"), "fresh3.example.", "zone");
  const ds = (await t.value("dnssec-ds")).split("\n");
  const dnskey = (await t.value("dnssec-dnskey")).split("\n");
  t.ok(
    dnskey.length >= 1 && dnskey.every((l) => / IN DNSKEY /.test(l)),
    "DNSKEY: " + dnskey,
  );
  // the same DS (SHA-256) as Knot computes
  const { stdout } = await env.keymgr("fresh3.example", "ds");
  const expected = stdout
    .trim()
    .split("\n")
    .map((l) => l.trim().split(/\s+/))
    .filter((f) => f[f.length - 2] === "2")
    .map((f) => f.slice(-4).join(" ").toLowerCase());
  t.eq(
    ds.map((l) => l.split(" IN DS ")[1].toLowerCase()),
    expected,
    "DS records",
  );
  await t.click("dnssec-close");
  await soaShown(b);
  t.ok(
    (await t.rows("zone-list"))
      .find((r) => r[0] === "fresh3.example.")[2]
      .startsWith("ns1.fresh3.example."),
    "created",
  );

  // the row of a directly logged in zone shows them as well
  await newMember(env, "fresh4.example", "signed");
  await t.open();
  await t.submitLogin({ zone: "fresh4.example" });
  await setupShown(b, "fresh4.example.");
  await fillZoneRow(t, "fresh4.example.", {});
  await b.wait(
    `document.getElementById("dnssec-dialog").open`,
    "DNSSEC records after setup",
  );
  await t.click("dnssec-close");
  await t.waitStatus("Zone created \\(serial");
  t.ok(
    (await t.rows()).some((r) => r[2] === "DNSKEY"),
    "zone with its keys",
  );
});

test("setup: the zone goes away before it is created", async (t) => {
  const { b, env } = t;
  await newMember(env, "fresh5.example", "full");
  await t.login("catalog.test");
  await b.wait(
    `[...document.querySelectorAll("#zone-list .vlist-row.editing")]
      .some((r) => r.querySelector(".c-zone-cell .c-text").textContent === "fresh5.example.")`,
    "inputs",
  );
  await env.knsupdate("catalog.test", [
    "update delete fresh5.zones.catalog.test.",
  ]);
  for (let i = 0; i < 100; i++) {
    if (
      (await env.kdig(["SOA", "fresh5.example"], null)).includes(
        "status: REFUSED",
      )
    )
      break;
    await sleep(100);
  }
  await fillZoneRow(t, "fresh5.example.", {});
  // the server is no longer authoritative: the key may be wrong as well
  await b.wait(
    `document.getElementById("key-dialog").open`,
    "key prompt for NOTAUTH",
  );
  await t.click("key-cancel");
  await t.waitStatus(
    "✗ creating fresh5.example. failed: update failed: NOTAUTH",
  );
});

test("catalog: SOA and NS records are only queried for rows on screen", async (t) => {
  const { b, env } = t;
  const lines = [];
  for (let i = 0; i < 300; i++) {
    lines.push(
      `update add many${i}.zones.catalog.test. 0 PTR many${i}.example.`,
    );
  }
  await env.knsupdate("catalog.test", lines);
  try {
    await t.open();
    // count the DNS messages the page sends
    await b.ev(`window.sentMessages = 0;
      const send = WebSocket.prototype.send;
      WebSocket.prototype.send = function (data) {
        window.sentMessages++;
        return send.call(this, data);
      };`);
    await t.submitLogin({ zone: "catalog.test" });
    await t.waitStatus("Zone loaded");
    const rendered = () =>
      b.ev(`return [...document.querySelectorAll("#zone-list .vlist-row")]
        .filter((r) => r.style.display !== "none").length;`);
    const settled = async () => {
      await sleep(300);
      await soaShown(b);
    };
    await settled();
    const n = await rendered();
    const first = await b.ev(`return window.sentMessages;`);
    // the AXFR, plus SOA and NS for each rendered row
    t.ok(
      n < 60 && first <= 1 + 2 * n,
      `${first} messages for ${n} of 305 rows`,
    );

    // jumping past the middle to the end: only the rows that stay on
    // screen are queried
    await b.ev(`const l = document.getElementById("zone-list");
      l.scrollTop = l.scrollHeight / 2;
      l.dispatchEvent(new Event("scroll"));
      l.scrollTop = l.scrollHeight;`);
    await settled();
    const second = await b.ev(`return window.sentMessages;`);
    t.ok(
      second > first && second - first <= 2 * n,
      `${second - first} more messages`,
    );
    const last = (await t.rows("zone-list")).at(-1);
    t.eq(last[0], "xfr.example.", "scrolled to the end");
  } finally {
    await env.knsupdate(
      "catalog.test",
      lines.map((l) =>
        l.replace("update add", "update delete").replace(/ 0 PTR .*/, ""),
      ),
    );
  }
});
