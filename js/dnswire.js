// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// DNS wire format primitives: encoding, parsing, name (de)compression.

export const TYPE_A = 1;
export const TYPE_NS = 2;
export const TYPE_CNAME = 5;
export const TYPE_SOA = 6;
export const TYPE_PTR = 12;
export const TYPE_MX = 15;
export const TYPE_TXT = 16;
export const TYPE_AAAA = 28;
export const TYPE_SSHFP = 44;
export const TYPE_RRSIG = 46;
export const TYPE_NSEC = 47;
export const TYPE_NSEC3 = 50;
export const TYPE_TSIG = 250;
export const TYPE_IXFR = 251;
export const TYPE_AXFR = 252;

export const CLASS_IN = 1;
export const CLASS_NONE = 254;
export const CLASS_ANY = 255;

export const OPCODE_QUERY = 0;
export const OPCODE_UPDATE = 5;

const TYPE_NAMES = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  35: "NAPTR",
  43: "DS",
  44: "SSHFP",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  50: "NSEC3",
  51: "NSEC3PARAM",
  52: "TLSA",
  59: "CDS",
  60: "CDNSKEY",
  64: "SVCB",
  65: "HTTPS",
  99: "SPF",
  250: "TSIG",
  257: "CAA",
};

export function typeToName(t) {
  return TYPE_NAMES[t] || "TYPE" + t;
}

export function nameToType(s) {
  s = s.trim().toUpperCase();
  for (const [num, name] of Object.entries(TYPE_NAMES)) {
    if (name === s) return Number(num);
  }
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

// Decompress rdata into a self-contained buffer. Types whose rdata may
// legally contain compressed names get their names expanded so the copy
// stays valid outside of the original message.
function extractRdata(msg, type, off, rdlen) {
  switch (type) {
    case TYPE_NS:
    case TYPE_CNAME:
    case TYPE_PTR: {
      const [n] = readName(msg, off);
      return nameToWire(n);
    }
    case TYPE_MX: {
      const w = new Writer(rdlen + 4);
      w.bytes(msg.subarray(off, off + 2));
      const [n] = readName(msg, off + 2);
      return w.name(n).done();
    }
    case TYPE_SOA: {
      const [mname, o1] = readName(msg, off);
      const [rname, o2] = readName(msg, o1);
      const w = new Writer(rdlen + 8);
      return w
        .name(mname)
        .name(rname)
        .bytes(msg.subarray(o2, off + rdlen))
        .done();
    }
    default:
      return msg.slice(off, off + rdlen);
  }
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
