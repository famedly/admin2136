// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Conversion between rdata wire format and presentation text.
//
// Fully supported (editable): A, AAAA, CNAME, TXT.
// Displayed nicely (read-only): SOA, NS, PTR, MX.
// Everything else is shown as RFC 3597 generic data: \# <len> <hex>.

import {
  nameToWire,
  readName,
  typeToName,
  TYPE_A,
  TYPE_NS,
  TYPE_CNAME,
  TYPE_SOA,
  TYPE_PTR,
  TYPE_MX,
  TYPE_TXT,
  TYPE_AAAA,
  TYPE_SSHFP,
} from "./dnswire.js";

const te = new TextEncoder();

export function rdataToText(type, rdata) {
  try {
    switch (type) {
      case TYPE_A:
        if (rdata.length === 4) return rdata.join(".");
        break;
      case TYPE_AAAA:
        if (rdata.length === 16) return formatIpv6(rdata);
        break;
      case TYPE_CNAME:
      case TYPE_NS:
      case TYPE_PTR:
        return readName(rdata, 0)[0];
      case TYPE_MX: {
        const pref = (rdata[0] << 8) | rdata[1];
        return pref + " " + readName(rdata, 2)[0];
      }
      case TYPE_SOA:
        return formatSoa(rdata);
      case TYPE_TXT:
        return formatTxt(rdata);
      case TYPE_SSHFP:
        return formatSshfp(rdata);
    }
  } catch (e) {
    // fall through to generic representation
  }
  return genericToText(rdata);
}

export function textToRdata(type, text, absolutize) {
  const t = text.trim();
  if (t.startsWith("\\#")) return parseGeneric(t); // RFC 3597 escape hatch
  switch (type) {
    case TYPE_A:
      return parseIpv4(t);
    case TYPE_AAAA:
      return parseIpv6(t);
    case TYPE_CNAME: {
      if (t === "") throw new Error("CNAME target must not be empty");
      return nameToWire(absolutize(t));
    }
    case TYPE_TXT:
      return parseTxt(text);
    case TYPE_SSHFP:
      return parseSshfp(t);
  }
  throw new Error(
    "editing " +
      typeToName(type) +
      ' records is not supported (use "\\# <len> <hex>" for raw rdata)',
  );
}

export function soaSerial(rdata) {
  const [, o1] = readName(rdata, 0);
  const [, o2] = readName(rdata, o1);
  if (o2 + 20 > rdata.length) return null;
  return (
    ((rdata[o2] << 24) |
      (rdata[o2 + 1] << 16) |
      (rdata[o2 + 2] << 8) |
      rdata[o2 + 3]) >>>
    0
  );
}

function formatSoa(rdata) {
  const [mname, o1] = readName(rdata, 0);
  const [rname, o2] = readName(rdata, o1);
  if (o2 + 20 > rdata.length) throw new Error("short SOA");
  const u32 = (o) =>
    ((rdata[o] << 24) |
      (rdata[o + 1] << 16) |
      (rdata[o + 2] << 8) |
      rdata[o + 3]) >>>
    0;
  return (
    mname +
    " " +
    rname +
    " " +
    u32(o2) +
    " " +
    u32(o2 + 4) +
    " " +
    u32(o2 + 8) +
    " " +
    u32(o2 + 12) +
    " " +
    u32(o2 + 16)
  );
}

// --- IPv4 ---

export function parseIpv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) throw new Error('invalid IPv4 address "' + s + '"');
  const b = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const v = Number(m[i + 1]);
    if (v > 255) throw new Error('invalid IPv4 address "' + s + '"');
    b[i] = v;
  }
  return b;
}

// --- IPv6 ---

export function formatIpv6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push((b[i] << 8) | b[i + 1]);
  // Find the longest run of zero groups (length >= 2) for "::".
  let best = -1,
    bestLen = 0,
    cur = -1;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (cur < 0) cur = i;
      if (i - cur + 1 > bestLen) {
        best = cur;
        bestLen = i - cur + 1;
      }
    } else {
      cur = -1;
    }
  }
  const hex = (x) => x.toString(16);
  if (bestLen < 2) return g.map(hex).join(":");
  return (
    g.slice(0, best).map(hex).join(":") +
    "::" +
    g
      .slice(best + bestLen)
      .map(hex)
      .join(":")
  );
}

export function parseIpv6(s) {
  s = s.trim().toLowerCase();
  if (s === "") throw new Error("empty IPv6 address");
  let head = s,
    tail = null;
  const dc = s.indexOf("::");
  if (dc >= 0) {
    head = s.slice(0, dc);
    tail = s.slice(dc + 2);
    if (tail.includes("::"))
      throw new Error('invalid IPv6 address "' + s + '"');
  }
  const parseGroups = (part) => {
    if (part === "") return [];
    const out = [];
    for (const grp of part.split(":")) {
      if (grp.includes(".")) {
        const v4 = parseIpv4(grp); // embedded IPv4, e.g. ::ffff:1.2.3.4
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(grp))
          throw new Error('invalid IPv6 address "' + s + '"');
        out.push(parseInt(grp, 16));
      }
    }
    return out;
  };
  const h = parseGroups(head);
  const t = tail === null ? [] : parseGroups(tail);
  let groups;
  if (tail !== null) {
    if (h.length + t.length > 7)
      throw new Error('invalid IPv6 address "' + s + '"');
    groups = h.concat(new Array(8 - h.length - t.length).fill(0), t);
  } else {
    if (h.length !== 8) throw new Error('invalid IPv6 address "' + s + '"');
    groups = h;
  }
  const b = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    b[2 * i] = groups[i] >>> 8;
    b[2 * i + 1] = groups[i] & 0xff;
  }
  return b;
}

// --- TXT ---

function formatTxt(rdata) {
  const parts = [];
  let o = 0;
  while (o < rdata.length) {
    const len = rdata[o++];
    if (o + len > rdata.length) throw new Error("malformed TXT rdata");
    parts.push(quoteString(rdata.subarray(o, o + len)));
    o += len;
  }
  return parts.length ? parts.join(" ") : '""';
}

function quoteString(b) {
  let s = '"';
  for (const c of b) {
    if (c === 0x22 || c === 0x5c)
      s += "\\" + String.fromCharCode(c); // " and \
    else if (c < 0x20 || c > 0x7e) s += "\\" + String(c).padStart(3, "0");
    else s += String.fromCharCode(c);
  }
  return s + '"';
}

// Accepts either master-file style quoted strings ("foo" "bar", with \" \\
// and \DDD escapes) or, when the input does not start with a quote, raw text
// that is split into 255-byte chunks automatically.
export function parseTxt(text) {
  const strings = [];
  const t = text.trim();
  if (t.startsWith('"')) {
    let i = 0;
    while (i < t.length) {
      while (i < t.length && (t[i] === " " || t[i] === "\t")) i++;
      if (i >= t.length) break;
      if (t[i] !== '"') throw new Error("expected opening quote in TXT data");
      i++;
      const bytes = [];
      while (i < t.length && t[i] !== '"') {
        if (t[i] === "\\") {
          i++;
          if (i >= t.length) throw new Error("dangling backslash in TXT data");
          if (/[0-9]/.test(t[i])) {
            const dec = t.slice(i, i + 3);
            if (!/^[0-9]{3}$/.test(dec))
              throw new Error("invalid \\DDD escape in TXT data");
            const v = parseInt(dec, 10);
            if (v > 255) throw new Error("invalid \\DDD escape in TXT data");
            bytes.push(v);
            i += 3;
          } else {
            bytes.push(...te.encode(t[i]));
            i++;
          }
        } else {
          bytes.push(...te.encode(t[i]));
          i++;
        }
      }
      if (t[i] !== '"') throw new Error("unterminated string in TXT data");
      i++;
      if (bytes.length > 255) throw new Error("TXT string exceeds 255 bytes");
      strings.push(Uint8Array.from(bytes));
    }
  } else {
    const b = te.encode(t);
    for (let i = 0; i < b.length; i += 255)
      strings.push(b.subarray(i, i + 255));
  }
  if (strings.length === 0) strings.push(new Uint8Array(0));

  let total = 0;
  for (const s of strings) total += 1 + s.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const s of strings) {
    out[o++] = s.length;
    out.set(s, o);
    o += s.length;
  }
  return out;
}

// --- SSHFP (RFC 4255) ---

// Presentation format: <algorithm> <fptype> <fingerprint-hex>
function formatSshfp(rdata) {
  if (rdata.length < 3) throw new Error("malformed SSHFP rdata");
  let hex = "";
  for (let i = 2; i < rdata.length; i++)
    hex += rdata[i].toString(16).padStart(2, "0");
  return rdata[0] + " " + rdata[1] + " " + hex;
}

export function parseSshfp(text) {
  const m = /^(\d+)\s+(\d+)\s+([0-9a-fA-F\s]+)$/.exec(text.trim());
  if (!m) {
    throw new Error(
      'invalid SSHFP data (expected "<algorithm> <fptype> <fingerprint-hex>")',
    );
  }
  const algo = Number(m[1]);
  const fptype = Number(m[2]);
  if (algo > 255) throw new Error("SSHFP algorithm must be 0-255");
  if (fptype > 255) throw new Error("SSHFP fingerprint type must be 0-255");
  const hex = m[3].replace(/\s+/g, "").toLowerCase();
  if (hex.length === 0 || hex.length % 2 !== 0) {
    throw new Error("SSHFP fingerprint must be an even number of hex digits");
  }
  const b = new Uint8Array(2 + hex.length / 2);
  b[0] = algo;
  b[1] = fptype;
  for (let i = 0; i < hex.length / 2; i++) {
    b[2 + i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return b;
}

// --- RFC 3597 generic rdata ---

export function genericToText(rdata) {
  let hex = "";
  for (const b of rdata) hex += b.toString(16).padStart(2, "0");
  return "\\# " + rdata.length + (rdata.length ? " " + hex : "");
}

export function parseGeneric(text) {
  const m = /^\\#\s+(\d+)\s*([0-9a-fA-F\s]*)$/.exec(text.trim());
  if (!m) throw new Error('invalid generic rdata (expected "\\# <len> <hex>")');
  const len = Number(m[1]);
  const hex = m[2].replace(/\s+/g, "");
  if (hex.length !== len * 2) throw new Error("generic rdata length mismatch");
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++)
    b[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return b;
}
