// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// DNSSEC helpers: DS records for DNSKEY records, to be entered at the
// parent zone.

import { nameToWire } from "./dnswire.js";

const DIGEST_SHA256 = 2;

// Key tag of DNSKEY rdata (RFC 4034 Appendix B).
export function keyTag(rdata) {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    ac += i & 1 ? rdata[i] : rdata[i] << 8;
  }
  ac += (ac >>> 16) & 0xffff;
  return ac & 0xffff;
}

// Whether DNSKEY rdata has the Secure Entry Point flag (a key signing key).
export function isSep(rdata) {
  return (rdata[1] & 1) === 1;
}

// DS rdata with a SHA-256 digest (RFC 4509) for DNSKEY rdata of `owner`.
export async function dsRdata(owner, dnskey) {
  const name = nameToWire(owner.toLowerCase());
  const data = new Uint8Array(name.length + dnskey.length);
  data.set(name);
  data.set(dnskey, name.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  const tag = keyTag(dnskey);
  return Uint8Array.of(
    tag >> 8,
    tag & 0xff,
    dnskey[3],
    DIGEST_SHA256,
    ...digest,
  );
}

// The DNSKEY rdata to publish DS records for: the key signing keys, or
// all keys if none has the SEP flag (e.g. a single combined key).
export function dsKeys(dnskeys) {
  const sep = dnskeys.filter(isSep);
  return sep.length ? sep : dnskeys;
}
