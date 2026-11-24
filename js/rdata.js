// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Conversion between rdata wire format and presentation text.
//
// Every type listed in SCHEMAS below is displayed in its presentation
// format and can be edited (the SOA serial is managed by the app).
// Everything else is shown as RFC 3597 generic data: \# <len> <hex>; that
// notation is also accepted as input for any type.

import { Writer, readName, typeToName, TYPES } from "./dnswire.js";

const te = new TextEncoder();

// ---- schemas ----

// Each schema lists the rdata fields in order, plus a hint describing the
// presentation format. Field kinds are defined in FIELDS below; kinds
// marked `rest` consume the remainder of the rdata (and of the text).
const DS_LIKE = {
  fields: ["u16", "u8", "u8", "hex"],
  hint: "<key tag> <algorithm> <digest type> <digest hex>",
};
const DNSKEY_LIKE = {
  fields: ["u16", "u8", "u8", "b64"],
  hint: "<flags> <protocol> <algorithm> <public key base64>",
};
const TLSA_LIKE = {
  fields: ["u8", "u8", "u8", "hex"],
  hint: "<usage> <selector> <matching type> <data hex>",
};
const SVCB_LIKE = {
  fields: ["u16", "name", "svc"],
  hint: '<priority> <target> [key=value…], e.g. 1 . alpn="h2,h3"',
};
const TXT_LIKE = {
  format: formatTxt,
  parse: (text) => parseTxt(text),
  hint: '"text" ["more text"…] (or unquoted text)',
};

const SCHEMAS = {
  [TYPES.A]: { fields: ["ipv4"], hint: "<IPv4 address>" },
  [TYPES.NS]: { fields: ["name"], hint: "<nameserver>" },
  [TYPES.CNAME]: { fields: ["name"], hint: "<target>" },
  [TYPES.SOA]: {
    fields: ["name", "name", "u32", "u32", "u32", "u32", "u32"],
    hint: "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>",
  },
  [TYPES.PTR]: { fields: ["name"], hint: "<target>" },
  [TYPES.HINFO]: { fields: ["str", "str"], hint: '"<cpu>" "<os>"' },
  [TYPES.MX]: { fields: ["u16", "name"], hint: "<preference> <exchange>" },
  [TYPES.TXT]: TXT_LIKE,
  [TYPES.RP]: { fields: ["name", "name"], hint: "<mailbox> <txt name>" },
  [TYPES.AFSDB]: { fields: ["u16", "name"], hint: "<subtype> <hostname>" },
  [TYPES.RT]: { fields: ["u16", "name"], hint: "<preference> <host>" },
  [TYPES.AAAA]: { fields: ["ipv6"], hint: "<IPv6 address>" },
  [TYPES.SRV]: {
    fields: ["u16", "u16", "u16", "name"],
    hint: "<priority> <weight> <port> <target>",
  },
  [TYPES.NAPTR]: {
    fields: ["u16", "u16", "str", "str", "str", "name"],
    hint: '<order> <preference> "<flags>" "<services>" "<regexp>" <replacement>',
  },
  [TYPES.KX]: { fields: ["u16", "name"], hint: "<preference> <exchanger>" },
  [TYPES.CERT]: {
    fields: ["u16", "u16", "u8", "b64"],
    hint: "<type> <key tag> <algorithm> <certificate base64>",
  },
  [TYPES.DNAME]: { fields: ["name"], hint: "<target>" },
  [TYPES.DS]: DS_LIKE,
  [TYPES.SSHFP]: {
    fields: ["u8", "u8", "hex"],
    hint: "<algorithm> <fptype> <fingerprint hex>",
  },
  [TYPES.DNSKEY]: DNSKEY_LIKE,
  [TYPES.DHCID]: { fields: ["b64"], hint: "<data base64>" },
  [TYPES.NSEC3PARAM]: {
    fields: ["u8", "u8", "u16", "salt"],
    hint: "<algorithm> <flags> <iterations> <salt hex or ->",
  },
  [TYPES.TLSA]: TLSA_LIKE,
  [TYPES.SMIMEA]: TLSA_LIKE,
  [TYPES.CDS]: DS_LIKE,
  [TYPES.CDNSKEY]: DNSKEY_LIKE,
  [TYPES.OPENPGPKEY]: { fields: ["b64"], hint: "<public key base64>" },
  [TYPES.ZONEMD]: {
    fields: ["u32", "u8", "u8", "hex"],
    hint: "<serial> <scheme> <hash algorithm> <digest hex>",
  },
  [TYPES.SVCB]: SVCB_LIKE,
  [TYPES.HTTPS]: SVCB_LIKE,
  [TYPES.SPF]: TXT_LIKE,
  [TYPES.URI]: {
    fields: ["u16", "u16", "rest"],
    hint: '<priority> <weight> "<target URI>"',
  },
  [TYPES.CAA]: {
    fields: ["u8", "tag", "rest"],
    hint: '<flags> <tag> "<value>", e.g. 0 issue "ca.example.net"',
  },
};

// Types that can be added, sorted by mnemonic. The SOA record exists
// exactly once per zone: it can be edited, but not added.
export const ADDABLE_TYPES = Object.keys(SCHEMAS)
  .map(Number)
  .filter((t) => t !== TYPES.SOA)
  .sort((a, b) => (typeToName(a) < typeToName(b) ? -1 : 1));

export function isEditableType(type) {
  return type in SCHEMAS;
}

// Short description of the presentation format of `type`, for input hints.
export function typeHint(type) {
  return SCHEMAS[type]?.hint ?? "\\# <length> <hex>";
}

export function rdataToText(type, rdata) {
  const schema = SCHEMAS[type];
  if (schema) {
    try {
      if (schema.format) return schema.format(rdata);
      const r = new Reader(rdata);
      const out = [];
      for (const f of schema.fields) out.push(FIELDS[f].read(r));
      if (r.o !== rdata.length) throw new Error("trailing rdata");
      return out.filter((s) => s !== "").join(" ");
    } catch (e) {
      // fall through to generic representation
    }
  }
  return genericToText(rdata);
}

// Parse the presentation text of `type` into wire-format rdata. Relative
// names are made absolute with `absolutize` (default: append the root).
export function textToRdata(type, text, absolutize = (n) => absName(n)) {
  const t = text.trim();
  if (t.startsWith("\\#")) return parseGeneric(t); // RFC 3597 escape hatch
  const schema = SCHEMAS[type];
  if (!schema) {
    throw new Error(
      "editing " +
        typeToName(type) +
        ' records is not supported (use "\\# <len> <hex>" for raw rdata)',
    );
  }
  if (schema.parse) return schema.parse(text);
  const what = "invalid " + typeToName(type) + " data";
  const toks = tokenize(t);
  const w = new Writer(64);
  let i = 0;
  for (const f of schema.fields) {
    const field = FIELDS[f];
    try {
      if (field.rest) {
        field.write(w, toks.slice(i), absolutize);
        i = toks.length;
      } else {
        if (i >= toks.length) throw new Error("too few fields");
        field.write(w, toks[i++], absolutize);
      }
    } catch (e) {
      throw new Error(
        what + ": " + e.message + ' (expected "' + schema.hint + '")',
      );
    }
  }
  if (i < toks.length) {
    throw new Error(
      what + ": too many fields" + ' (expected "' + schema.hint + '")',
    );
  }
  return w.done();
}

function absName(n) {
  return n.endsWith(".") ? n : n + ".";
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

const SOA_FIELDS = [
  "mname",
  "rname",
  "serial",
  "refresh",
  "retry",
  "expire",
  "minimum",
];

// Split SOA rdata into { mname, rname, serial, refresh, ... }.
export function soaFields(rdata) {
  const r = new Reader(rdata);
  const out = {};
  for (const f of SOA_FIELDS) {
    out[f] = f.endsWith("name") ? FIELDS.name.read(r) : r.u32();
  }
  if (r.o !== rdata.length) throw new Error("malformed SOA rdata");
  return out;
}

export function soaRdata(f) {
  const w = new Writer(64);
  w.name(f.mname).name(f.rname);
  for (const k of SOA_FIELDS.slice(2)) w.u32(f[k]);
  return w.done();
}

// Three-way merge of an SOA edit: apply the fields that changed from
// `base` (the SOA the edit started from) to `edited` onto `current` (the
// SOA now in the zone, which a concurrent update may have changed), and
// increment the serial of `current` (RFC 1982 arithmetic). Servers ignore
// SOA updates that do not increase the serial (RFC 2136 Section 3.4.2.2).
export function mergeSoa(base, edited, current) {
  const same = (k) =>
    k.endsWith("name")
      ? base[k].toLowerCase() === edited[k].toLowerCase()
      : base[k] === edited[k];
  const out = {};
  for (const k of SOA_FIELDS) out[k] = same(k) ? current[k] : edited[k];
  out.serial = (current.serial + 1) >>> 0;
  return out;
}

// ---- field codecs ----

class Reader {
  constructor(b) {
    this.b = b;
    this.o = 0;
  }

  bytes(n) {
    if (this.o + n > this.b.length) throw new Error("short rdata");
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }

  u8() {
    return this.bytes(1)[0];
  }

  u16() {
    const b = this.bytes(2);
    return (b[0] << 8) | b[1];
  }

  u32() {
    const b = this.bytes(4);
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  }

  rest() {
    return this.bytes(this.b.length - this.o);
  }
}

function parseNum(tok, max) {
  if (!/^\d+$/.test(tok) || Number(tok) > max) {
    throw new Error(
      "expected a number from 0 to " + max + ', got "' + tok + '"',
    );
  }
  return Number(tok);
}

const FIELDS = {
  u8: {
    read: (r) => String(r.u8()),
    write: (w, t) => w.u8(parseNum(t, 0xff)),
  },
  u16: {
    read: (r) => String(r.u16()),
    write: (w, t) => w.u16(parseNum(t, 0xffff)),
  },
  u32: {
    read: (r) => String(r.u32()),
    write: (w, t) => w.u32(parseNum(t, 0xffffffff)),
  },
  name: {
    read: (r) => {
      const [n, e] = readName(r.b, r.o);
      r.o = e;
      return n;
    },
    write: (w, t, absolutize) => w.name(absolutize(t)),
  },
  ipv4: {
    read: (r) => r.bytes(4).join("."),
    write: (w, t) => w.bytes(parseIpv4(t)),
  },
  ipv6: {
    read: (r) => formatIpv6(r.bytes(16)),
    write: (w, t) => w.bytes(parseIpv6(t)),
  },
  // A single <character-string>.
  str: {
    read: (r) => quoteString(r.bytes(r.u8())),
    write: (w, t) => {
      const b = decodeString(t);
      if (b.length > 255) throw new Error("string exceeds 255 bytes");
      w.u8(b.length).bytes(b);
    },
  },
  // Hex data up to the end; may be split by whitespace.
  hex: {
    rest: true,
    read: (r) => toHex(nonEmpty(r.rest())),
    write: (w, toks) => w.bytes(nonEmpty(parseHex(toks.join("")))),
  },
  // Base64 data up to the end; may be split by whitespace.
  b64: {
    rest: true,
    read: (r) => nonEmpty(r.rest()).toBase64(),
    write: (w, toks) => w.bytes(nonEmpty(parseBase64(toks.join("")))),
  },
  // Length-prefixed hex, "-" when empty (NSEC3PARAM salt).
  salt: {
    read: (r) => {
      const b = r.bytes(r.u8());
      return b.length ? toHex(b) : "-";
    },
    write: (w, t) => {
      const b = t === "-" ? new Uint8Array(0) : parseHex(t);
      if (b.length > 255) throw new Error("salt exceeds 255 bytes");
      w.u8(b.length).bytes(b);
    },
  },
  // Length-prefixed alphanumeric token (CAA tag).
  tag: {
    read: (r) => {
      const s = String.fromCharCode(...r.bytes(r.u8()));
      if (!/^[A-Za-z0-9]+$/.test(s)) throw new Error("invalid tag");
      return s;
    },
    write: (w, t) => {
      if (!/^[A-Za-z0-9]{1,255}$/.test(t)) {
        throw new Error('invalid tag "' + t + '" (letters and digits only)');
      }
      w.u8(t.length).bytes(te.encode(t));
    },
  },
  // Unprefixed string up to the end, shown quoted (CAA value, URI target).
  rest: {
    rest: true,
    read: (r) => quoteString(r.rest()),
    write: (w, toks) => {
      toks.forEach((t, i) => {
        if (i > 0) w.u8(0x20);
        w.bytes(decodeString(t));
      });
    },
  },
  // SVCB/HTTPS SvcParams up to the end.
  svc: {
    rest: true,
    read: (r) => formatSvcParams(r.rest()),
    write: (w, toks) => writeSvcParams(w, toks),
  },
};

function nonEmpty(b) {
  if (b.length === 0) throw new Error("data must not be empty");
  return b;
}

// ---- presentation text tokens ----

// Split presentation text into whitespace-separated tokens. Quoted parts
// keep their quotes and backslash escapes are kept verbatim; they are
// resolved by decodeString(). Parentheses (multi-line master file
// syntax) are treated as whitespace.
export function tokenize(text) {
  const toks = [];
  let cur = null;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\\") {
      if (i + 1 >= text.length) throw new Error("dangling backslash");
      cur = (cur ?? "") + c + text[++i];
    } else if (quoted) {
      cur += c;
      if (c === '"') quoted = false;
    } else if (c === '"') {
      cur = (cur ?? "") + c;
      quoted = true;
    } else if (/[\s()]/.test(c)) {
      if (cur !== null) toks.push(cur);
      cur = null;
    } else {
      cur = (cur ?? "") + c;
    }
  }
  if (quoted) throw new Error("unterminated quoted string");
  if (cur !== null) toks.push(cur);
  return toks;
}

// Decode a token into bytes: quotes are dropped, \DDD and \X escapes are
// resolved, everything else is UTF-8 encoded.
export function decodeString(tok) {
  const out = [];
  for (let i = 0; i < tok.length; i++) {
    let c = tok[i];
    if (c === '"') continue;
    if (c === "\\") {
      c = tok[++i];
      if (c === undefined) throw new Error("dangling backslash");
      if (/[0-9]/.test(c)) {
        const dec = tok.slice(i, i + 3);
        if (!/^[0-9]{3}$/.test(dec) || Number(dec) > 255) {
          throw new Error("invalid \\DDD escape");
        }
        out.push(Number(dec));
        i += 2;
        continue;
      }
    }
    // Keep surrogate pairs together so they encode as one code point.
    const cp = tok.codePointAt(i);
    if (cp > 0xffff) i++;
    out.push(...te.encode(String.fromCodePoint(cp)));
  }
  return Uint8Array.from(out);
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

// ---- hex / base64 ----

function toHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function parseHex(s) {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) {
    throw new Error("expected an even number of hex digits");
  }
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++)
    b[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return b;
}

function parseBase64(s) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
    throw new Error("invalid base64 data");
  }
  return Uint8Array.fromBase64(s);
}

// ---- SVCB / HTTPS (RFC 9460) ----

const SVC_KEYS = [
  "mandatory",
  "alpn",
  "no-default-alpn",
  "port",
  "ipv4hint",
  "ech",
  "ipv6hint",
  "dohpath",
  "ohttp",
];
const SVC_MANDATORY = 0;
const SVC_ALPN = 1;
const SVC_NO_DEFAULT_ALPN = 2;
const SVC_PORT = 3;
const SVC_IPV4HINT = 4;
const SVC_ECH = 5;
const SVC_IPV6HINT = 6;
const SVC_DOHPATH = 7;
const SVC_OHTTP = 8;

function svcKeyName(k) {
  return SVC_KEYS[k] ?? "key" + k;
}

function svcKeyNumber(s) {
  const i = SVC_KEYS.indexOf(s.toLowerCase());
  if (i >= 0) return i;
  const m = /^key(\d{1,5})$/i.exec(s);
  if (m && Number(m[1]) < 65535) return Number(m[1]);
  throw new Error('unknown SvcParamKey "' + s + '"');
}

// Split a value-list (RFC 9460 Appendix A.1) at unescaped commas; "\," and
// "\\" stand for a literal comma and backslash within an item.
function splitValueList(b) {
  const items = [];
  let cur = [];
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0x5c && i + 1 < b.length) cur.push(b[++i]);
    else if (b[i] === 0x2c) {
      items.push(Uint8Array.from(cur));
      cur = [];
    } else cur.push(b[i]);
  }
  items.push(Uint8Array.from(cur));
  return items;
}

function joinValueList(items) {
  const out = [];
  items.forEach((item, i) => {
    if (i > 0) out.push(0x2c);
    for (const c of item) {
      if (c === 0x2c || c === 0x5c) out.push(0x5c);
      out.push(c);
    }
  });
  return Uint8Array.from(out);
}

function chunks(b, size) {
  if (b.length === 0 || b.length % size !== 0) {
    throw new Error("malformed SvcParam value");
  }
  const out = [];
  for (let i = 0; i < b.length; i += size) out.push(b.subarray(i, i + size));
  return out;
}

function formatSvcValue(key, v) {
  switch (key) {
    case SVC_MANDATORY:
      return chunks(v, 2)
        .map((k) => svcKeyName((k[0] << 8) | k[1]))
        .join(",");
    case SVC_ALPN: {
      const r = new Reader(v);
      const ids = [];
      while (r.o < v.length) ids.push(nonEmpty(r.bytes(r.u8())));
      return quoteString(joinValueList(nonEmpty(ids)));
    }
    case SVC_NO_DEFAULT_ALPN:
    case SVC_OHTTP:
      if (v.length) throw new Error("unexpected SvcParam value");
      return null;
    case SVC_PORT:
      if (v.length !== 2) throw new Error("malformed port");
      return String((v[0] << 8) | v[1]);
    case SVC_IPV4HINT:
      return chunks(v, 4)
        .map((a) => a.join("."))
        .join(",");
    case SVC_ECH:
      return nonEmpty(v).toBase64();
    case SVC_IPV6HINT:
      return chunks(v, 16).map(formatIpv6).join(",");
    default:
      return v.length ? quoteString(v) : null;
  }
}

function formatSvcParams(b) {
  const r = new Reader(b);
  const out = [];
  let last = -1;
  while (r.o < b.length) {
    const key = r.u16();
    if (key <= last) throw new Error("SvcParamKeys out of order");
    last = key;
    const val = formatSvcValue(key, r.bytes(r.u16()));
    out.push(svcKeyName(key) + (val === null ? "" : "=" + val));
  }
  return out.join(" ");
}

function parseSvcValue(key, hasValue, v) {
  const str = () => new TextDecoder().decode(v);
  if (key === SVC_NO_DEFAULT_ALPN || key === SVC_OHTTP) {
    if (hasValue) throw new Error(svcKeyName(key) + " takes no value");
    return new Uint8Array(0);
  }
  if (!hasValue && key < SVC_KEYS.length) {
    throw new Error(svcKeyName(key) + " requires a value");
  }
  const w = new Writer(v.length + 16);
  switch (key) {
    case SVC_MANDATORY: {
      const keys = str()
        .split(",")
        .map(svcKeyNumber)
        .sort((a, b) => a - b);
      for (const k of keys) w.u16(k);
      break;
    }
    case SVC_ALPN:
      for (const id of splitValueList(v)) {
        if (id.length === 0 || id.length > 255) {
          throw new Error("ALPN identifiers must have 1-255 bytes");
        }
        w.u8(id.length).bytes(id);
      }
      break;
    case SVC_PORT:
      w.u16(parseNum(str(), 0xffff));
      break;
    case SVC_IPV4HINT:
      for (const a of str().split(",")) w.bytes(parseIpv4(a));
      break;
    case SVC_ECH:
      w.bytes(nonEmpty(parseBase64(str())));
      break;
    case SVC_IPV6HINT:
      for (const a of str().split(",")) w.bytes(parseIpv6(a));
      break;
    default:
      w.bytes(v);
  }
  return w.done();
}

function writeSvcParams(w, toks) {
  const params = new Map();
  for (const tok of toks) {
    const eq = tok.indexOf("=");
    const key = svcKeyNumber(eq < 0 ? tok : tok.slice(0, eq));
    if (params.has(key)) {
      throw new Error("duplicate SvcParamKey " + svcKeyName(key));
    }
    const v = eq < 0 ? new Uint8Array(0) : decodeString(tok.slice(eq + 1));
    params.set(key, parseSvcValue(key, eq >= 0, v));
  }
  for (const key of [...params.keys()].sort((a, b) => a - b)) {
    const v = params.get(key);
    if (v.length > 0xffff) throw new Error("SvcParam value too long");
    w.u16(key).u16(v.length).bytes(v);
  }
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
