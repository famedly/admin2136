// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// TSIG (RFC 8945) request signing and response verification using Web
// Crypto HMAC.
//
// A TsigSession covers one signed request and its response(s): it keeps
// the request MAC and, for multi-message answers such as AXFR, the running
// MAC so every received message is authenticated (RFC 8945 Section 5.3.1
// and 5.4).

import {
  Writer,
  nameToWire,
  readName,
  TYPE_TSIG,
  CLASS_ANY,
} from "./dnswire.js";

const ALGORITHMS = {
  "hmac-sha1": "SHA-1",
  "hmac-sha256": "SHA-256",
  "hmac-sha384": "SHA-384",
  "hmac-sha512": "SHA-512",
};

const HASH_BYTES = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
};

export const TSIG_ERRORS = {
  16: "BADSIG",
  17: "BADKEY",
  18: "BADTIME",
  22: "BADTRUNC",
};

// Parse "hmac-sha256:keyname:base64secret" (same order as `nsupdate -y`).
export function parseTsigSpec(spec) {
  const parts = spec.split(":");
  if (parts.length < 3) {
    throw new Error(
      'TSIG secret must be given as "hmac-sha256:keyname:base64secret"',
    );
  }
  const algo = parts[0].trim().toLowerCase();
  const name = parts[1].trim().toLowerCase().replace(/\.$/, "");
  const secretB64 = parts.slice(2).join(":").trim();
  if (!name) throw new Error("TSIG key name is empty");
  if (!(algo in ALGORITHMS)) {
    throw new Error(
      'unsupported TSIG algorithm "' +
        algo +
        '" (supported: ' +
        Object.keys(ALGORITHMS).join(", ") +
        ")",
    );
  }
  let secret;
  try {
    secret = b64decode(secretB64);
  } catch (e) {
    throw new Error("TSIG secret is not valid base64");
  }
  if (secret.length === 0) throw new Error("TSIG secret is empty");
  return { name, algo, hash: ALGORITHMS[algo], secret, cryptoKey: null };
}

function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmac(key, data) {
  if (!key.cryptoKey) {
    key.cryptoKey = await crypto.subtle.importKey(
      "raw",
      key.secret,
      { name: "HMAC", hash: key.hash },
      false,
      ["sign"],
    );
  }
  return new Uint8Array(await crypto.subtle.sign("HMAC", key.cryptoKey, data));
}

// Sign a complete DNS message: returns the new message with the TSIG RR
// appended to the additional section, plus the request MAC needed to
// verify the response.
async function signWithMac(msg, key) {
  const now = Math.floor(Date.now() / 1000);
  const fudge = 300;
  const keyWire = nameToWire(key.name);
  const algWire = nameToWire(key.algo);

  // Digest input: full message followed by the TSIG variables.
  const v = new Writer(msg.length + keyWire.length + algWire.length + 20);
  v.bytes(msg);
  v.bytes(keyWire).u16(CLASS_ANY).u32(0);
  v.bytes(algWire).u48(now).u16(fudge);
  v.u16(0).u16(0); // error, other-len
  const mac = await hmac(key, v.done());

  const rd = new Writer(algWire.length + mac.length + 16);
  rd.bytes(algWire).u48(now).u16(fudge);
  rd.u16(mac.length).bytes(mac);
  rd.u16((msg[0] << 8) | msg[1]); // original ID
  rd.u16(0).u16(0); // error, other-len
  const rdata = rd.done();

  const out = new Writer(msg.length + keyWire.length + rdata.length + 10);
  out.bytes(msg);
  out.bytes(keyWire).u16(TYPE_TSIG).u16(CLASS_ANY).u32(0);
  out.u16(rdata.length).bytes(rdata);
  const signed = out.done();

  // Bump ARCOUNT.
  const arcount = ((signed[10] << 8) | signed[11]) + 1;
  signed[10] = (arcount >>> 8) & 0xff;
  signed[11] = arcount & 0xff;
  return { signed, mac };
}

// Sign a complete DNS message: returns a new message with the TSIG RR
// appended to the additional section. Prefer TsigSession when the response
// should be verified as well.
export async function signMessage(msg, key) {
  return (await signWithMac(msg, key)).signed;
}

// Locate and parse the TSIG RR in a wire-format message. Returns null when
// the message carries no TSIG; throws when a TSIG RR is misplaced or
// malformed. `rrStart` is the byte offset of the TSIG RR: everything
// before it is the part of the message covered by the MAC.
function locateTsig(msg) {
  if (msg.length < 12) throw new Error("DNS message shorter than header");
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const counts = [
    dv.getUint16(4),
    dv.getUint16(6),
    dv.getUint16(8),
    dv.getUint16(10),
  ];
  let off = 12;
  for (let i = 0; i < counts[0]; i++) {
    off = readName(msg, off)[1] + 4;
  }
  const nrrs = counts[1] + counts[2] + counts[3];
  let tsig = null;
  for (let i = 0; i < nrrs; i++) {
    const rrStart = off;
    const [owner, e] = readName(msg, off);
    off = e;
    if (off + 10 > msg.length) throw new Error("truncated resource record");
    const type = dv.getUint16(off);
    const cls = dv.getUint16(off + 2);
    const ttl = dv.getUint32(off + 4);
    const rdlen = dv.getUint16(off + 8);
    const rd = off + 10;
    off = rd + rdlen;
    if (off > msg.length) throw new Error("truncated rdata");
    if (type !== TYPE_TSIG) continue;
    if (tsig) throw new Error("multiple TSIG records in message");
    if (i !== nrrs - 1 || counts[3] === 0) {
      throw new Error("TSIG RR is not the last record of the message");
    }
    const [algName, ao] = readName(msg, rd);
    if (ao + 10 > off) throw new Error("truncated TSIG rdata");
    const time = dv.getUint16(ao) * 0x100000000 + dv.getUint32(ao + 2);
    const fudge = dv.getUint16(ao + 6);
    const macSize = dv.getUint16(ao + 8);
    const p = ao + 10 + macSize;
    if (p + 6 > off) throw new Error("truncated TSIG rdata");
    const mac = msg.slice(ao + 10, p);
    const origId = dv.getUint16(p);
    const error = dv.getUint16(p + 2);
    const otherLen = dv.getUint16(p + 4);
    if (p + 6 + otherLen > off) throw new Error("truncated TSIG rdata");
    const other = msg.slice(p + 6, p + 6 + otherLen);
    tsig = {
      rrStart,
      keyName: owner,
      cls,
      ttl,
      algName,
      time,
      fudge,
      mac,
      origId,
      error,
      other,
    };
  }
  return tsig;
}

function macEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// One signed request/response exchange (RFC 8945). sign() the outgoing
// message once, then verify() every received message in order. For
// multi-message answers (AXFR) up to 99 unsigned messages between signed
// ones are tolerated; they are folded into the running digest and are
// authenticated by the next signed message.
export class TsigSession {
  constructor(key) {
    this.key = key;
    this.requestMac = null; // MAC of the signed request
    this.priorMac = null; // running MAC: last TSIG MAC seen
    this.pending = []; // unsigned messages since the last TSIG
    this.unsigned = 0; // count of `pending`
    this.signedSeen = 0; // verified TSIG records so far
  }

  async sign(msg) {
    const { signed, mac } = await signWithMac(msg, this.key);
    this.requestMac = mac;
    this.priorMac = mac;
    return signed;
  }

  // Verify one response message. Returns { signed }: false means the
  // message carried no TSIG and its authentication is deferred to the next
  // signed message in the stream. Throws on any verification failure.
  async verify(raw) {
    if (!this.requestMac) {
      throw new Error("TsigSession.verify() called before sign()");
    }
    const t = locateTsig(raw);
    if (!t) {
      if (this.signedSeen === 0) {
        throw new Error("response is not TSIG-signed");
      }
      if (++this.unsigned > 99) {
        throw new Error("more than 99 unsigned messages in TSIG-signed stream");
      }
      this.pending.push(raw);
      return { signed: false };
    }

    const keyName = t.keyName.toLowerCase().replace(/\.$/, "");
    if (keyName !== this.key.name) {
      throw new Error('response TSIG uses unexpected key "' + keyName + '"');
    }
    const algName = t.algName.toLowerCase().replace(/\.$/, "");
    if (algName !== this.key.algo) {
      throw new Error(
        'response TSIG uses unexpected algorithm "' + algName + '"',
      );
    }
    if (t.cls !== CLASS_ANY || t.ttl !== 0) {
      throw new Error("malformed TSIG RR (class/TTL)");
    }

    const errName =
      t.error === 0 ? null : TSIG_ERRORS[t.error] || "TSIG error " + t.error;
    if (t.mac.length === 0) {
      // Unsigned error response (RFC 8945 Section 5.3.2): it cannot be
      // authenticated, but surface the server's reason.
      throw new Error(
        "server rejected TSIG: " + (errName || "unsigned TSIG in response"),
      );
    }
    const hashLen = HASH_BYTES[this.key.hash];
    if (t.mac.length > hashLen) {
      throw new Error("TSIG MAC longer than " + this.key.algo + " output");
    }
    if (t.mac.length < Math.max(10, hashLen / 2)) {
      throw new Error("TSIG MAC shorter than allowed truncation");
    }

    // The digested form of the message: TSIG RR removed, ARCOUNT
    // decremented, original ID restored (RFC 8945 Section 4.3.2).
    const dm = raw.slice(0, t.rrStart);
    dm[0] = (t.origId >>> 8) & 0xff;
    dm[1] = t.origId & 0xff;
    const arcount = ((dm[10] << 8) | dm[11]) - 1;
    if (arcount < 0) throw new Error("TSIG RR not counted in ARCOUNT");
    dm[10] = (arcount >>> 8) & 0xff;
    dm[11] = arcount & 0xff;

    const w = new Writer(raw.length + 64);
    w.u16(this.priorMac.length).bytes(this.priorMac);
    for (const m of this.pending) w.bytes(m);
    w.bytes(dm);
    if (this.signedSeen === 0) {
      // First signed response digests the full TSIG variables...
      w.bytes(nameToWire(keyName)).u16(CLASS_ANY).u32(0);
      w.bytes(nameToWire(algName)).u48(t.time).u16(t.fudge);
      w.u16(t.error).u16(t.other.length).bytes(t.other);
    } else {
      // ...subsequent ones only the timers (RFC 8945 Section 5.3.1).
      w.u48(t.time).u16(t.fudge);
    }
    const full = await hmac(this.key, w.done());
    if (!macEqual(full.subarray(0, t.mac.length), t.mac)) {
      throw new Error(
        "response TSIG MAC verification failed" +
          (errName ? " (server reported " + errName + ")" : ""),
      );
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - t.time) > t.fudge) {
      throw new Error(
        "response TSIG time out of range (server " +
          t.time +
          ", client " +
          now +
          ", fudge " +
          t.fudge +
          "); check clock synchronization",
      );
    }
    if (errName) {
      throw new Error("server reported TSIG error: " + errName);
    }

    this.priorMac = t.mac;
    this.pending = [];
    this.unsigned = 0;
    this.signedSeen++;
    return { signed: true };
  }
}

// Extract the TSIG error code from a TSIG RR's rdata; returns a text like
// "BADKEY" or null if the record carries no error.
export function tsigErrorName(rdata) {
  try {
    const [, o] = readName(rdata, 0); // algorithm name
    // time(6) fudge(2) macsize(2) mac(n) origid(2) error(2)
    const macSize = (rdata[o + 8] << 8) | rdata[o + 9];
    const errOff = o + 10 + macSize + 2;
    const err = (rdata[errOff] << 8) | rdata[errOff + 1];
    if (!err) return null;
    return TSIG_ERRORS[err] || "TSIG error " + err;
  } catch (e) {
    return null;
  }
}
