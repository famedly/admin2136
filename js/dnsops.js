// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// High-level DNS operations over a DoWS connection: AXFR, IXFR (RFC 1995)
// and RFC 2136 UPDATE.

import {
  Writer,
  buildQuery,
  parseMessage,
  TYPES,
  CLASS_IN,
  OPCODE_UPDATE,
} from "./dnswire.js";
import { TsigSession, tsigErrorName } from "./tsig.js";
import { soaSerial } from "./rdata.js";

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

export const RCODE_FORMERR = 1;
export const RCODE_SERVFAIL = 2;
export const RCODE_NOTIMP = 4;
export const RCODE_REFUSED = 5;
export const RCODE_YXRRSET = 7;
export const RCODE_NXRRSET = 8;
const RCODE_NOTAUTH = 9;

const EDNS_EDE = 15; // Extended DNS Error option (RFC 8914)
const EDE_INVALID_DATA = 24;

export function rcodeName(rc) {
  return RCODES[rc] || "RCODE" + rc;
}

// RRtypes that are dropped when received: they are never stored in the
// client state nor shown in the UI.
export const IGNORED_RRTYPES = new Set([TYPES.RRSIG, TYPES.NSEC, TYPES.NSEC3]);

function randId() {
  return crypto.getRandomValues(new Uint16Array(1))[0];
}

// A DNS error response. `rcode` is the response code, `tsigError` the
// TSIG error name (e.g. "BADKEY") or null, `response` the parsed message.
export class DnsError extends Error {
  constructor(what, resp) {
    const tsig = resp.additional.find((rr) => rr.type === TYPES.TSIG);
    const tsigError = tsig ? tsigErrorName(tsig.rdata) : null;
    super(
      what +
        ": " +
        rcodeName(resp.rcode) +
        (tsigError ? " (" + tsigError + ")" : ""),
    );
    this.rcode = resp.rcode;
    this.tsigError = tsigError;
    this.response = resp;
  }
}

// Whether `err` is a refusal by the server that a different TSIG key might
// overcome (as opposed to e.g. a failed update prerequisite). SERVFAIL is
// a server-side failure (e.g. a zone without contents) whatever else the
// response says, so never a rejection.
export function isRejection(err) {
  return (
    err instanceof DnsError &&
    err.rcode !== RCODE_SERVFAIL &&
    (err.rcode === RCODE_REFUSED ||
      err.rcode === RCODE_NOTAUTH ||
      err.tsigError !== null)
  );
}

// Send the (unsigned) query `msg` and read the transfer response stream
// it triggers. `onRecord(rr)` is called for every answer record except
// TSIG and IGNORED_RRTYPES, in order, and returns true once the record
// ended the transfer. The whole stream is authenticated with `tsigKey`,
// if given (RFC 8945 Section 5.3.1). `what` names the transfer in errors.
async function streamTransfer(conn, msg, tsigKey, what, onRecord) {
  const id = (msg[0] << 8) | msg[1];
  const tsig = tsigKey ? new TsigSession(tsigKey) : null;
  if (tsig) msg = await tsig.sign(msg);
  conn.send(msg);
  const tag = "[" + what.toLowerCase() + "]";
  console.log(
    tag +
      " query sent: id=" +
      id +
      (tsigKey ? " (TSIG-signed)" : " (unsigned)"),
  );

  let done = false;
  let frameNo = 0;
  let lastSigned = true;
  while (!done) {
    const raw = await conn.recv(120000);
    frameNo++;
    const resp = parseMessage(raw);
    console.log(
      tag +
        " reply #" +
        frameNo +
        ": " +
        raw.length +
        " bytes, id=" +
        resp.id +
        " (expected " +
        id +
        "), rcode=" +
        rcodeName(resp.rcode) +
        ", an=" +
        resp.answers.length,
    );
    if (resp.id !== id) {
      // stray message; not ours -- keep waiting
      console.warn(tag + " reply #" + frameNo + " ignored due to ID mismatch");
      continue;
    }
    if (resp.rcode !== 0) {
      throw new DnsError(what + " refused", resp);
    }
    if (tsig) {
      lastSigned = (await tsig.verify(raw)).signed;
      if (!lastSigned) {
        console.log(tag + " reply #" + frameNo + " carries no TSIG (deferred)");
      }
    }
    // (A TSIG RR is always in the additional section.)
    const progressed = resp.answers.length > 0;
    for (const rr of resp.answers) {
      if (IGNORED_RRTYPES.has(rr.type)) continue; // consumed, not reported
      if (onRecord(rr)) {
        done = true;
        break;
      }
    }
    if (!progressed && !done) {
      throw new Error(what + " stream stalled (empty response message)");
    }
  }
  // RFC 8945 5.3.1: the last message of the transfer must carry a TSIG.
  if (tsig && !lastSigned) {
    throw new Error(what + " ended with an unsigned message (missing TSIG)");
  }
  console.log(tag + " done after " + frameNo + " messages");
}

// Stream a full zone transfer; `onRecord` is called for every record of the
// zone exactly once (the trailing terminator SOA is suppressed).
// Returns the number of records seen.
export async function axfr(conn, zone, tsigKey, onRecord) {
  let count = 0;
  const msg = buildQuery(randId(), zone, TYPES.AXFR);
  await streamTransfer(conn, msg, tsigKey, "AXFR", (rr) => {
    if (rr.type === TYPES.SOA && count > 0) return true; // terminator SOA
    if (count === 0 && rr.type !== TYPES.SOA) {
      throw new Error("AXFR stream did not start with SOA");
    }
    onRecord(rr);
    count++;
    return false;
  });
  return count;
}

// RFC 1982 serial number arithmetic: whether serial `a` is newer than `b`.
export function serialGt(a, b) {
  const d = (a - b) >>> 0;
  return d !== 0 && d < 0x80000000;
}

// IXFR query (RFC 1995 Section 3): the client's current SOA goes into the
// authority section.
export function buildIxfrQuery(id, zone, soa) {
  const w = new Writer(128);
  w.u16(id).u16(0).u16(1).u16(0).u16(1).u16(0);
  w.name(zone).u16(TYPES.IXFR).u16(CLASS_IN);
  w.name(zone).u16(TYPES.SOA).u16(CLASS_IN).u32(soa.ttl);
  w.u16(soa.rdata.length).bytes(soa.rdata);
  return w.done();
}

// Request an incremental zone transfer (RFC 1995) relative to `soa`, the
// { ttl, rdata } of the SOA the client holds. Resolves to one of
//   { kind: "uptodate", soa }  the client's version is current
//   { kind: "incremental", soa, changes }
//       `changes` lists { op: "del" | "add", rr } in order, without the
//       SOA records that delimit the difference sequences
//   { kind: "full", soa }  the server sent the whole zone instead (as an
//       AXFR would); its records were passed to `onFullRecord` exactly
//       like axfr() passes them to `onRecord`
// where `soa` is the server's current SOA record. `onProgress(n)` is
// called with the number of records received so far, every 1024 records.
export async function ixfr(conn, zone, tsigKey, soa, onFullRecord, onProgress) {
  const clientSerial = soaSerial(soa.rdata);
  const result = { kind: null, soa: null, changes: [] };
  let serverSerial = null;
  let op = null; // "del" / "add" within an incremental response
  let n = 0;
  const msg = buildIxfrQuery(randId(), zone, soa);
  await streamTransfer(conn, msg, tsigKey, "IXFR", (rr) => {
    if (++n % 1024 === 0 && onProgress) onProgress(n);
    const isSoa = rr.type === TYPES.SOA;
    if (n === 1) {
      if (!isSoa) throw new Error("IXFR stream did not start with SOA");
      result.soa = rr;
      serverSerial = soaSerial(rr.rdata);
      if (!serialGt(serverSerial, clientSerial)) {
        result.kind = "uptodate";
        return true;
      }
      return false;
    }
    if (n === 2) {
      // An incremental response continues with the SOA of the client's
      // version, starting the first deletion sequence. Anything else is
      // a full transfer -- except a second SOA of the current version,
      // which ends the full transfer of a zone consisting of its SOA only.
      if (isSoa && soaSerial(rr.rdata) !== serverSerial) {
        result.kind = "incremental";
        op = "del";
        return false;
      }
      result.kind = "full";
      onFullRecord(result.soa);
      if (isSoa) return true;
    }
    if (result.kind === "full") {
      if (isSoa) return true; // terminator SOA
      onFullRecord(rr);
      return false;
    }
    if (isSoa) {
      // Every difference sequence is "SOA(old) deletions SOA(new)
      // additions"; the current version's SOA after additions ends it all.
      if (op === "add" && soaSerial(rr.rdata) === serverSerial) return true;
      op = op === "del" ? "add" : "del";
      return false;
    }
    result.changes.push({ op, rr });
    return false;
  });
  return result;
}

// Build an RFC 2136 UPDATE message. `updates` and `prereqs` entries:
//   { name (absolute), type, cls, ttl, rdata (Uint8Array) }
export function buildUpdateMessage(id, zone, updates, prereqs = []) {
  const w = new Writer(128);
  w.u16(id).u16(OPCODE_UPDATE << 11);
  w.u16(1).u16(prereqs.length).u16(updates.length).u16(0);
  w.name(zone).u16(TYPES.SOA).u16(CLASS_IN); // zone section
  for (const u of [...prereqs, ...updates]) {
    w.name(u.name).u16(u.type).u16(u.cls).u32(u.ttl);
    w.u16(u.rdata.length).bytes(u.rdata);
  }
  return w.done();
}

// Send an update and wait for the response. Throws DnsError if the server
// refuses it or a prerequisite is not met (e.g. RCODE_NXRRSET).
export async function sendUpdate(conn, zone, tsigKey, updates, prereqs = []) {
  const id = randId();
  const tsig = tsigKey ? new TsigSession(tsigKey) : null;
  let msg = buildUpdateMessage(id, zone, updates, prereqs);
  if (tsig) msg = await tsig.sign(msg);
  conn.send(msg);
  for (;;) {
    const raw = await conn.recv();
    const resp = parseMessage(raw);
    if (resp.id !== id) continue;
    if (resp.rcode !== 0) {
      throw new DnsError("update failed", resp);
    }
    if (tsig) await tsig.verify(raw);
    return;
  }
}

// Query `qname`/`qtype` and return the answer records of the response.
// With `edns`, the query carries an OPT record (RFC 6891), so that the
// server can add Extended DNS Errors to its response.
export async function query(
  conn,
  qname,
  qtype,
  tsigKey,
  { edns = false } = {},
) {
  const id = randId();
  const tsig = tsigKey ? new TsigSession(tsigKey) : null;
  let msg = buildQuery(id, qname, qtype);
  if (edns) msg = withOpt(msg);
  if (tsig) msg = await tsig.sign(msg);
  conn.send(msg);
  for (;;) {
    const raw = await conn.recv();
    const resp = parseMessage(raw);
    if (resp.id !== id) continue;
    if (resp.rcode !== 0) throw new DnsError("query failed", resp);
    if (tsig) await tsig.verify(raw);
    return resp.answers;
  }
}

// Append an empty OPT record (UDP payload size 1232) to message `msg`.
function withOpt(msg) {
  const w = new Writer(msg.length + 11);
  w.bytes(msg).u8(0).u16(TYPES.OPT).u16(1232).u32(0).u16(0);
  const out = w.done();
  out[11] += 1; // ARCOUNT (queries have no other additional records)
  return out;
}

// The Extended DNS Error codes (RFC 8914) of a parsed response.
export function ednsErrors(resp) {
  const codes = [];
  for (const rr of resp.additional) {
    if (rr.type !== TYPES.OPT) continue;
    const d = rr.rdata;
    for (let o = 0; o + 4 <= d.length; ) {
      const code = (d[o] << 8) | d[o + 1];
      const len = (d[o + 2] << 8) | d[o + 3];
      if (code === EDNS_EDE && len >= 2) codes.push((d[o + 4] << 8) | d[o + 5]);
      o += 4 + len;
    }
  }
  return codes;
}

// Whether the response to a SOA query (with EDNS) says that the zone is
// configured on the server but has no contents yet: Knot DNS answers
// SERVFAIL without any records, with the Extended DNS Error "Invalid
// Data" (an unknown zone gets REFUSED instead).
export function isUnsetZoneResponse(resp) {
  const ede = ednsErrors(resp);
  return (
    resp.rcode === RCODE_SERVFAIL &&
    resp.answers.length === 0 &&
    resp.authority.length === 0 &&
    ede.every((code) => code === EDE_INVALID_DATA)
  );
}

// Send many (unsigned) queries at once, at most `window` of them in flight,
// and match the responses by ID. `questions` are { name, type }; resolves
// to one result per question: the parsed response (any rcode).
export async function queryAll(conn, questions, window = 32) {
  const results = new Array(questions.length);
  const inFlight = new Map(); // id -> question index
  let next = 0;
  let done = 0;
  const fill = () => {
    while (inFlight.size < window && next < questions.length) {
      let id;
      do id = randId();
      while (inFlight.has(id));
      inFlight.set(id, next);
      const q = questions[next++];
      conn.send(buildQuery(id, q.name, q.type));
    }
  };
  fill();
  while (done < questions.length) {
    const resp = parseMessage(await conn.recv());
    const i = inFlight.get(resp.id);
    if (i === undefined) continue; // stray message
    inFlight.delete(resp.id);
    results[i] = resp;
    done++;
    fill();
  }
  return results;
}
