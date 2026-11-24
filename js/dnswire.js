// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// DNS wire format primitives: encoding, parsing, name (de)compression.

export const CLASS_IN = 1;
export const CLASS_NONE = 254;
export const CLASS_ANY = 255;

export const OPCODE_QUERY = 0;
export const OPCODE_UPDATE = 5;

export const TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  HINFO: 13,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  RT: 21,
  AAAA: 28,
  LOC: 29,
  SRV: 33,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  DNAME: 39,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  EUI48: 108,
  EUI64: 109,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  URI: 256,
  CAA: 257,
};

const TYPE_NAMES = Object.fromEntries(
  Object.entries(TYPES).map(([name, num]) => [num, name]),
);

export function typeToName(t) {
  return TYPE_NAMES[t] || "TYPE" + t;
}

export function nameToType(s) {
  s = s.trim().toUpperCase();
  if (Object.hasOwn(TYPES, s)) return TYPES[s];
  const m = /^TYPE(\d+)$/.exec(s);
  if (m) return Number(m[1]);
  return null;
}

const te = new TextEncoder();
const td = new TextDecoder();

// Growable big-endian byte writer.
export class Writer {
  constructor(cap = 512) {
    this.dv = new DataView(new ArrayBuffer(cap));
    this.n = 0;
  }

  _ensure(extra) {
    if (this.n + extra <= this.dv.byteLength) return;
    let cap = this.dv.byteLength * 2;
    while (cap < this.n + extra) cap *= 2;
    const buf = new ArrayBuffer(cap);
    new Uint8Array(buf).set(new Uint8Array(this.dv.buffer, 0, this.n));
    this.dv = new DataView(buf);
  }

  u8(v) {
    this._ensure(1);
    this.dv.setUint8(this.n, v);
    this.n += 1;
    return this;
  }

  u16(v) {
    this._ensure(2);
    this.dv.setUint16(this.n, v);
    this.n += 2;
    return this;
  }

  u32(v) {
    this._ensure(4);
    this.dv.setUint32(this.n, v);
    this.n += 4;
    return this;
  }

  u48(v) {
    this.u16(Math.floor(v / 0x100000000));
    this.u32(v % 0x100000000);
    return this;
  }

  bytes(b) {
    this._ensure(b.length);
    new Uint8Array(this.dv.buffer, this.n, b.length).set(b);
    this.n += b.length;
    return this;
  }

  name(s) {
    return this.bytes(nameToWire(s));
  }

  done() {
    return new Uint8Array(this.dv.buffer.slice(0, this.n));
  }
}

// Text name ("www.example.com." or "www.example.com") to uncompressed wire labels.
export function nameToWire(name) {
  if (name === "." || name === "") return Uint8Array.of(0);
  if (name.endsWith(".")) name = name.slice(0, -1);
  const w = new Writer(name.length + 2);
  for (const label of name.split(".")) {
    const b = te.encode(label);
    if (b.length === 0) throw new Error('empty label in name "' + name + '"');
    if (b.length > 63)
      throw new Error('label longer than 63 bytes: "' + label + '"');
    w.u8(b.length).bytes(b);
  }
  w.u8(0);
  const out = w.done();
  if (out.length > 255)
    throw new Error('name longer than 255 bytes: "' + name + '"');
  return out;
}

// Read a (possibly compressed) name at `off` in `msg`.
// Returns [nameText (absolute, with trailing dot), offset after the name].
export function readName(msg, off) {
  const labels = [];
  let end = -1;
  let jumps = 0;
  for (;;) {
    if (off >= msg.length) throw new Error("truncated name");
    const len = msg[off];
    if (len === 0) {
      if (end < 0) end = off + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= msg.length)
        throw new Error("truncated compression pointer");
      if (end < 0) end = off + 2;
      if (++jumps > 128) throw new Error("compression pointer loop");
      off = ((len & 0x3f) << 8) | msg[off + 1];
      continue;
    }
    if ((len & 0xc0) !== 0)
      throw new Error("unsupported label type 0x" + (len & 0xc0).toString(16));
    if (off + 1 + len > msg.length) throw new Error("truncated label");
    labels.push(td.decode(msg.subarray(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  return [labels.length ? labels.join(".") + "." : ".", end];
}

export function buildQuery(id, qname, qtype, qclass = CLASS_IN) {
  const w = new Writer(64);
  w.u16(id).u16(0).u16(1).u16(0).u16(0).u16(0);
  w.name(qname).u16(qtype).u16(qclass);
  return w.done();
}

// Layout of the rdata of types that may carry compressed names in received
// messages (RFC 3597 Section 4): "n" is a domain name, "s" a
// <character-string>, a number that many fixed-size bytes. Whatever follows
// the listed fields is copied verbatim.
const COMPRESSIBLE = {
  [TYPES.NS]: ["n"],
  [TYPES.CNAME]: ["n"],
  [TYPES.SOA]: ["n", "n"],
  [TYPES.PTR]: ["n"],
  [TYPES.MX]: [2, "n"],
  [TYPES.RP]: ["n", "n"],
  [TYPES.AFSDB]: [2, "n"],
  [TYPES.RT]: [2, "n"],
  [TYPES.SRV]: [6, "n"],
  [TYPES.NAPTR]: [4, "s", "s", "s", "n"],
};

// Decompress rdata into a self-contained buffer. Types whose rdata may
// legally contain compressed names get their names expanded so the copy
// stays valid outside of the original message.
function extractRdata(msg, type, off, rdlen) {
  const layout = COMPRESSIBLE[type];
  if (!layout) return msg.slice(off, off + rdlen);
  const end = off + rdlen;
  const w = new Writer(rdlen + 32);
  for (const f of layout) {
    if (f === "n") {
      const [n, e] = readName(msg, off);
      w.name(n);
      off = e;
    } else {
      if (off >= end) throw new Error("truncated rdata");
      const len = f === "s" ? 1 + msg[off] : f;
      if (off + len > end) throw new Error("truncated rdata");
      w.bytes(msg.subarray(off, off + len));
      off += len;
    }
    if (off > end) throw new Error("truncated rdata");
  }
  return w.bytes(msg.subarray(off, end)).done();
}

export function parseMessage(msg) {
  if (msg.length < 12) throw new Error("DNS message shorter than header");
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const id = dv.getUint16(0);
  const flags = dv.getUint16(2);
  const counts = [
    dv.getUint16(4),
    dv.getUint16(6),
    dv.getUint16(8),
    dv.getUint16(10),
  ];
  let off = 12;

  const questions = [];
  for (let i = 0; i < counts[0]; i++) {
    const [name, e] = readName(msg, off);
    off = e;
    if (off + 4 > msg.length) throw new Error("truncated question");
    questions.push({
      name,
      type: dv.getUint16(off),
      cls: dv.getUint16(off + 2),
    });
    off += 4;
  }

  const sections = [[], [], []];
  for (let s = 0; s < 3; s++) {
    for (let i = 0; i < counts[s + 1]; i++) {
      const [name, e] = readName(msg, off);
      off = e;
      if (off + 10 > msg.length) throw new Error("truncated resource record");
      const type = dv.getUint16(off);
      const cls = dv.getUint16(off + 2);
      const ttl = dv.getUint32(off + 4);
      const rdlen = dv.getUint16(off + 8);
      off += 10;
      if (off + rdlen > msg.length) throw new Error("truncated rdata");
      sections[s].push({
        name,
        type,
        cls,
        ttl,
        rdata: extractRdata(msg, type, off, rdlen),
      });
      off += rdlen;
    }
  }

  return {
    id,
    flags,
    opcode: (flags >>> 11) & 0xf,
    rcode: flags & 0xf,
    questions,
    answers: sections[0],
    authority: sections[1],
    additional: sections[2],
  };
}
