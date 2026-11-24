// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Catalog zones (RFC 9432): detection, member listing and the RFC 2136
// updates that add or remove member zones.
//
// Layout of a catalog zone, relative to the catalog's apex:
//
//   version              TXT "2"
//   <id>.zones           PTR <member zone>
//   group.<id>.zones     TXT "<group>"         (optional property)
//   ....<id>.zones       ...                   (other member properties)
//   ....ext              ...                   (custom properties)

import {
  nameToWire,
  readName,
  TYPES,
  CLASS_IN,
  CLASS_NONE,
} from "./dnswire.js";

const td = new TextDecoder();
const te = new TextEncoder();

const MEMBER_RE = /^(?:(.+)\.)?([^.]+)\.zones$/;

// Concatenated <character-string>s of TXT rdata.
function txtValue(rdata) {
  const parts = [];
  for (let o = 0; o < rdata.length; o += 1 + rdata[o]) {
    parts.push(td.decode(rdata.subarray(o + 1, o + 1 + rdata[o])));
  }
  return parts.join("");
}

// Inspect a ZoneStore. Returns null when it does not hold a catalog zone,
// otherwise { version, members } where every member is
//   { id, zone, group, recs }
// with `zone` the absolute member zone name, `group` the value of the
// group property (or null) and `recs` the store indices of all records
// belonging to the member (its PTR and all properties).
//
// A zone is treated as a catalog if it has a "version" TXT record with a
// known schema version and either lists member zones or contains nothing
// but catalog records (an empty catalog).
export function parseCatalog(store) {
  let version = null;
  for (const i of store.findName("version")) {
    const r = store.get(i);
    if (r.type === TYPES.TXT) version = txtValue(r.rdata);
  }
  if (version !== "1" && version !== "2") return null;

  const byId = new Map();
  let foreign = false;
  for (let i = 0; i < store.count; i++) {
    const r = store.get(i);
    const name = r.name.toLowerCase();
    if (name === "" || name === "version") continue;
    if (name === "ext" || name.endsWith(".ext")) continue;
    const m = MEMBER_RE.exec(name);
    if (!m) {
      foreign = true;
      continue;
    }
    let member = byId.get(m[2]);
    if (!member) {
      // The ID label as stored (original case): the one before "zones".
      const labels = r.name.split(".");
      const id = labels[labels.length - 2];
      member = { id, zone: null, group: null, recs: [] };
      byId.set(m[2], member);
    }
    member.recs.push(i);
    if (!m[1] && r.type === TYPES.PTR && member.zone === null) {
      try {
        member.zone = readName(r.rdata, 0)[0];
      } catch (e) {
        // malformed PTR; the member is skipped below
      }
    } else if (m[1] === "group" && r.type === TYPES.TXT) {
      member.group = txtValue(r.rdata);
    }
  }

  // IDs without a PTR record are not valid members.
  const members = [...byId.values()].filter((m) => m.zone !== null);
  if (members.length === 0 && foreign) return null;
  members.sort((a, b) => compareZones(a.zone, b.zone));
  return { version, members };
}

function compareZones(a, b) {
  const ka = a.toLowerCase().split(".").reverse().join(".");
  const kb = b.toLowerCase().split(".").reverse().join(".");
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

// A fresh random member ID (a single hex label) not yet used in `catalog`.
export function newMemberId(catalog) {
  for (;;) {
    const b = crypto.getRandomValues(new Uint8Array(8));
    const id = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
    if (!catalog.members.some((m) => m.id.toLowerCase() === id)) return id;
  }
}

// Records (relative to the catalog) that add `zone` with the given ID and
// optional group. Returned as { name, type, ttl, rdata } entries.
export function memberRecords(zone, id, group) {
  const fqdn = zone.endsWith(".") ? zone : zone + ".";
  const recs = [
    { name: id + ".zones", type: TYPES.PTR, ttl: 0, rdata: nameToWire(fqdn) },
  ];
  if (group) {
    const b = te.encode(group);
    if (b.length > 255) throw new Error("group name exceeds 255 bytes");
    const rdata = new Uint8Array(1 + b.length);
    rdata[0] = b.length;
    rdata.set(b, 1);
    recs.push({
      name: "group." + id + ".zones",
      type: TYPES.TXT,
      ttl: 0,
      rdata,
    });
  }
  return recs;
}

// RFC 2136 update entries adding the given relative records.
export function addUpdates(store, recs) {
  return recs.map((r) => ({
    name: store.absolutize(r.name),
    type: r.type,
    cls: CLASS_IN,
    ttl: r.ttl,
    rdata: r.rdata,
  }));
}

// RFC 2136 update entries deleting all records of `member`.
export function deleteMemberUpdates(store, member) {
  return member.recs.map((i) => {
    const r = store.get(i);
    return {
      name: store.absolutize(r.name),
      type: r.type,
      cls: CLASS_NONE,
      ttl: 0,
      rdata: r.rdata,
    };
  });
}
