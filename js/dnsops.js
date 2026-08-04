// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// High-level DNS operations over a DoWS connection: AXFR and RFC 2136 UPDATE.
//
// TODO(IXFR): for incremental reloads, send an IXFR query (type 251) with the
// current SOA in the authority section and apply the delta envelopes to the
// ZoneStore instead of rebuilding it. The transport and TSIG layers already
// support this; only the envelope interpretation is missing.

import {
  Writer,
  buildQuery,
  parseMessage,
  TYPE_SOA,
  TYPE_RRSIG,
  TYPE_NSEC,
  TYPE_NSEC3,
  TYPE_AXFR,
  TYPE_TSIG,
  CLASS_IN,
  OPCODE_UPDATE,
} from "./dnswire.js";
import { TsigSession, tsigErrorName } from "./tsig.js";

const RCODES = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  6: "YXDOMAIN",
  7: "YXRRSET",
  8: "NXRRSET",
  9: "NOTAUTH",
  10: "NOTZONE",
};

export function rcodeName(rc) {
  return RCODES[rc] || "RCODE" + rc;
}

// RRtypes that are dropped when received: they are never stored in the
// client state nor shown in the UI.
export const IGNORED_RRTYPES = new Set([TYPE_RRSIG, TYPE_NSEC, TYPE_NSEC3]);

function randId() {
  return crypto.getRandomValues(new Uint16Array(1))[0];
}

function errorDetail(resp) {
  const tsig = resp.additional.find((rr) => rr.type === TYPE_TSIG);
  if (!tsig) return "";
  const name = tsigErrorName(tsig.rdata);
  return name ? " (" + name + ")" : "";
}

// Stream a full zone transfer; `onRecord` is called for every record of the
// zone exactly once (the trailing terminator SOA is suppressed).
// Returns the number of records seen.
export async function axfr(conn, zone, tsigKey, onRecord) {
  const id = randId();
  const tsig = tsigKey ? new TsigSession(tsigKey) : null;
  let msg = buildQuery(id, zone, TYPE_AXFR);
  if (tsig) msg = await tsig.sign(msg);
  conn.send(msg);

  console.log(
    "[axfr] query sent: id=" +
      id +
      " zone=" +
      zone +
      (tsigKey ? " (TSIG-signed)" : " (unsigned)"),
  );

  let soaSeen = 0;
  let count = 0;
  let frameNo = 0;
  let lastSigned = true;
  while (soaSeen < 2) {
    const raw = await conn.recv(120000);
    frameNo++;
    const resp = parseMessage(raw);
    console.log(
      "[axfr] reply #" +
        frameNo +
        ": " +
        raw.length +
        " bytes," +
        " id=" +
        resp.id +
        " (expected " +
        id +
        ")," +
        " rcode=" +
        rcodeName(resp.rcode) +
        "," +
        " qd=" +
        resp.questions.length +
        " an=" +
        resp.answers.length +
        " ns=" +
        resp.authority.length +
        " ar=" +
        resp.additional.length,
    );
    if (resp.id !== id) {
      // stray message; not ours -- keep waiting
      console.warn(
        "[axfr] reply #" +
          frameNo +
          " ignored due to ID mismatch; still waiting for id=" +
          id,
      );
      continue;
    }
    if (resp.rcode !== 0) {
      throw new Error(
        "AXFR refused: " + rcodeName(resp.rcode) + errorDetail(resp),
      );
    }
    if (tsig) {
      lastSigned = (await tsig.verify(raw)).signed;
      if (!lastSigned) {
        console.log("[axfr] reply #" + frameNo + " carries no TSIG (deferred)");
      }
    }
    let progressed = false;
    let ignored = 0;
    for (const rr of resp.answers) {
      if (rr.type === TYPE_TSIG) continue;
      if (IGNORED_RRTYPES.has(rr.type)) {
        ignored++;
        progressed = true; // consumed from the stream, just not stored
        continue;
      }
      if (rr.type === TYPE_SOA) {
        soaSeen++;
        console.log(
          "[axfr] reply #" +
            frameNo +
            ": SOA record (soaSeen=" +
            soaSeen +
            ")" +
            (soaSeen === 2 ? " -> transfer complete" : ""),
        );
        if (soaSeen === 2) break; // terminator SOA, do not report again
      } else if (soaSeen === 0) {
        throw new Error("AXFR stream did not start with SOA");
      }
      onRecord(rr);
      count++;
      progressed = true;
    }
    console.log(
      "[axfr] reply #" +
        frameNo +
        " processed: " +
        count +
        " records total, " +
        ignored +
        " ignored, soaSeen=" +
        soaSeen,
    );
    if (!progressed && soaSeen < 2) {
      throw new Error("AXFR stream stalled (empty response message)");
    }
  }
  // RFC 8945 5.3.1: the last message of the transfer must carry a TSIG.
  if (tsig && !lastSigned) {
    throw new Error("AXFR ended with an unsigned message (missing TSIG)");
  }
  console.log("[axfr] done: " + count + " records");
  return count;
}

// Build an RFC 2136 UPDATE message. `updates` entries:
//   { name (absolute), type, cls, ttl, rdata (Uint8Array) }
export function buildUpdateMessage(id, zone, updates) {
  const w = new Writer(128);
  w.u16(id).u16(OPCODE_UPDATE << 11);
  w.u16(1).u16(0).u16(updates.length).u16(0);
  w.name(zone).u16(TYPE_SOA).u16(CLASS_IN); // zone section
  for (const u of updates) {
    w.name(u.name).u16(u.type).u16(u.cls).u32(u.ttl);
    w.u16(u.rdata.length).bytes(u.rdata);
  }
  return w.done();
}

export async function sendUpdate(conn, zone, tsigKey, updates) {
  const id = randId();
  const tsig = tsigKey ? new TsigSession(tsigKey) : null;
  let msg = buildUpdateMessage(id, zone, updates);
  if (tsig) msg = await tsig.sign(msg);
  conn.send(msg);
  for (;;) {
    const raw = await conn.recv();
    const resp = parseMessage(raw);
    if (resp.id !== id) continue;
    if (resp.rcode !== 0) {
      throw new Error(
        "update failed: " + rcodeName(resp.rcode) + errorDetail(resp),
      );
    }
    if (tsig) await tsig.verify(raw);
    return;
  }
}
