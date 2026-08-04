// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Compact in-memory zone representation.
//
// All records live in a single growable Uint8Array arena; a Uint32Array holds
// one offset per record. Owner names are stored with the zone suffix stripped
// ('' = zone apex, trailing dot = out-of-zone absolute name) and rdata is kept
// in raw (uncompressed) wire format. Per-record layout in the arena:
//
//   u8  name length
//   ..  name (UTF-8, relative to zone)
//   u16 rrtype
//   u32 ttl
//   u16 rdata length
//   ..  rdata (wire format)
//
// The class is not stored: zones transferred via AXFR are single-class (IN).
// Replacing or removing records leaves garbage in the arena; it is reclaimed
// on the next zone reload, which is fine for an editing session.

const te = new TextEncoder();
const td = new TextDecoder();

const DOT = 0x2e; // '.'

function lowerByte(b) {
  return b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
}

// Compare two relative DNS names label-wise from the rightmost label
// ("reversed name"), case-insensitively. '' (the apex) sorts first. Reads
// directly from arena bytes at [oa, oa+na) / [ob, ob+nb) -- no decoding or
// splitting -- to keep the display-order sort allocation-free.
function compareRevNameBytes(arena, oa, na, ob, nb) {
  if (na === 0 && nb === 0) return 0;
  if (na === 0) return -1;
  if (nb === 0) return 1;
  // Absolute (out-of-zone) names carry a trailing dot; ignore it so it does
  // not sort before real labels (equivalent to dropping the trailing empty
  // element that String.split('.') would produce).
  const ea = oa + na - (arena[oa + na - 1] === DOT ? 1 : 0);
  const eb = ob + nb - (arena[ob + nb - 1] === DOT ? 1 : 0);
  let ia = ea - 1;
  let ib = eb - 1;
  for (;;) {
    let sa = ia;
    while (sa >= oa && arena[sa] !== DOT) sa--;
    let sb = ib;
    while (sb >= ob && arena[sb] !== DOT) sb--;
    let pa = sa + 1;
    let pb = sb + 1;
    while (pa <= ia && pb <= ib) {
      const ca = lowerByte(arena[pa]);
      const cb = lowerByte(arena[pb]);
      if (ca !== cb) return ca - cb;
      pa++;
      pb++;
    }
    if (pa <= ia) return 1; // b's label is a proper prefix of a's -> a > b
    if (pb <= ib) return -1; // a's label is a proper prefix of b's -> a < b
    ia = sa - 1;
    ib = sb - 1;
    const aDone = ia < oa;
    const bDone = ib < ob;
    if (aDone && bDone) return 0;
    if (aDone) return -1; // shared suffix: fewer labels first
    if (bDone) return 1;
  }
}

export class ZoneStore {
  constructor(zone) {
    this.zone = zone.toLowerCase().replace(/\.+$/, "");
    this.zoneFqdn = this.zone === "" ? "." : this.zone + ".";
    this.arena = new Uint8Array(1 << 16);
    this.arenaLen = 0;
    this.offsets = new Uint32Array(1024);
    this.count = 0;
    this.serial = null; // SOA serial, tracked by the app
  }

  clear() {
    this.arenaLen = 0;
    this.count = 0;
    this.serial = null;
  }

  // 'www.example.com.' -> 'www'; apex -> ''; out-of-zone names are kept
  // absolute (trailing dot).
  relativize(fqdn) {
    const lower = fqdn.toLowerCase();
    if (lower === this.zoneFqdn) return "";
    const suffix = "." + this.zoneFqdn;
    if (lower.endsWith(suffix))
      return fqdn.slice(0, fqdn.length - suffix.length);
    return fqdn;
  }

  absolutize(rel) {
    if (rel === "" || rel === "@") return this.zoneFqdn;
    if (rel.endsWith(".")) return rel;
    return rel + "." + this.zoneFqdn;
  }

  _growArena(need) {
    if (this.arenaLen + need <= this.arena.length) return;
    let cap = this.arena.length * 2;
    while (cap < this.arenaLen + need) cap *= 2;
    const b = new Uint8Array(cap);
    b.set(this.arena.subarray(0, this.arenaLen));
    this.arena = b;
  }

  _encode(nameRel, type, ttl, rdata) {
    const nb = te.encode(nameRel);
    if (nb.length > 255) throw new Error("name too long");
    if (rdata.length > 0xffff) throw new Error("rdata too long");
    this._growArena(1 + nb.length + 8 + rdata.length);
    const a = this.arena;
    let o = this.arenaLen;
    a[o++] = nb.length;
    a.set(nb, o);
    o += nb.length;
    a[o++] = (type >>> 8) & 0xff;
    a[o++] = type & 0xff;
    a[o++] = (ttl >>> 24) & 0xff;
    a[o++] = (ttl >>> 16) & 0xff;
    a[o++] = (ttl >>> 8) & 0xff;
    a[o++] = ttl & 0xff;
    a[o++] = (rdata.length >>> 8) & 0xff;
    a[o++] = rdata.length & 0xff;
    a.set(rdata, o);
    o += rdata.length;
    const off = this.arenaLen;
    this.arenaLen = o;
    return off;
  }

  add(nameRel, type, ttl, rdata) {
    if (this.count === this.offsets.length) {
      const b = new Uint32Array(this.offsets.length * 2);
      b.set(this.offsets);
      this.offsets = b;
    }
    this.offsets[this.count] = this._encode(nameRel, type, ttl, rdata);
    return this.count++;
  }

  replace(i, nameRel, type, ttl, rdata) {
    if (i < 0 || i >= this.count) throw new Error("record index out of range");
    this.offsets[i] = this._encode(nameRel, type, ttl, rdata);
  }

  remove(i) {
    if (i < 0 || i >= this.count) throw new Error("record index out of range");
    this.offsets.copyWithin(i, i + 1, this.count);
    this.count--;
  }

  // Display-order comparator for two record indices, reading straight from
  // the arena: sorts by (revname, type, ttl). revname is the DNS name
  // compared alphabetically with its labels reversed, so names group by
  // subtree; the apex ('', shown as '@') sorts before all other names.
  //
  // Reads bytes directly out of the arena (no this.get(), no string
  // decoding/splitting) since this runs O(n log n) times per rebuildOrder()
  // and allocation was the dominant cost for large zones.
  compareRecords(ia, ib) {
    const a = this.arena;
    const oa = this.offsets[ia];
    const ob = this.offsets[ib];
    const nlenA = a[oa];
    const nlenB = a[ob];
    const c = compareRevNameBytes(a, oa + 1, nlenA, ob + 1, nlenB);
    if (c !== 0) return c;
    let pa = oa + 1 + nlenA;
    let pb = ob + 1 + nlenB;
    const typeA = (a[pa] << 8) | a[pa + 1];
    const typeB = (a[pb] << 8) | a[pb + 1];
    if (typeA !== typeB) return typeA - typeB;
    pa += 2;
    pb += 2;
    const ttlA =
      ((a[pa] << 24) | (a[pa + 1] << 16) | (a[pa + 2] << 8) | a[pa + 3]) >>> 0;
    const ttlB =
      ((a[pb] << 24) | (a[pb + 1] << 16) | (a[pb + 2] << 8) | a[pb + 3]) >>> 0;
    return ttlA - ttlB;
  }

  // Decode record i. `rdata` is a view into the arena: valid until the store
  // is cleared, but stays intact across add/replace/remove.
  get(i) {
    if (i < 0 || i >= this.count) throw new Error("record index out of range");
    const a = this.arena;
    let o = this.offsets[i];
    const nlen = a[o++];
    const name = td.decode(a.subarray(o, o + nlen));
    o += nlen;
    const type = (a[o] << 8) | a[o + 1];
    const ttl =
      ((a[o + 2] << 24) | (a[o + 3] << 16) | (a[o + 4] << 8) | a[o + 5]) >>> 0;
    const rdlen = (a[o + 6] << 8) | a[o + 7];
    o += 8;
    return { name, type, ttl, rdata: a.subarray(o, o + rdlen) };
  }
}
