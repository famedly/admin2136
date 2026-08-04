// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Smoke tests for the DOM-independent modules.
// Run with:  deno run test/smoke.mjs   (or: node test/smoke.mjs)

import {
  Writer,
  nameToWire,
  readName,
  buildQuery,
  parseMessage,
  typeToName,
  nameToType,
  TYPE_A,
  TYPE_CNAME,
  TYPE_SOA,
  TYPE_TXT,
  TYPE_AAAA,
  TYPE_SSHFP,
  TYPE_TSIG,
  CLASS_IN,
  CLASS_ANY,
  CLASS_NONE,
} from "../js/dnswire.js";
import { parseTsigSpec, signMessage, TsigSession } from "../js/tsig.js";
import { buildUpdateMessage, IGNORED_RRTYPES } from "../js/dnsops.js";
import { ZoneStore } from "../js/zonestore.js";
import {
  rdataToText,
  textToRdata,
  parseIpv4,
  parseIpv6,
  formatIpv6,
  parseTxt,
  genericToText,
  parseGeneric,
  soaSerial,
} from "../js/rdata.js";

let failures = 0;
function check(what, cond) {
  if (!cond) {
    failures++;
    console.error("FAIL:", what);
  } else {
    console.log("ok:", what);
  }
}
function eq(what, a, b) {
  check(
    what + " (" + JSON.stringify(a) + " == " + JSON.stringify(b) + ")",
    JSON.stringify(a) === JSON.stringify(b),
  );
}
const hex = (u8) =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

// --- names ---
eq("nameToWire root", hex(nameToWire(".")), "00");
eq(
  "nameToWire www.example.com.",
  hex(nameToWire("www.example.com.")),
  "03777777076578616d706c6503636f6d00",
);
eq(
  "readName roundtrip",
  readName(nameToWire("a.b.example.org."), 0)[0],
  "a.b.example.org.",
);

// compression pointer: name at offset 2 pointing back to offset 12
{
  const msg = new Uint8Array(32);
  msg.set(nameToWire("example.com."), 12);
  msg[2] = 0x03;
  msg[3] = 0x77;
  msg[4] = 0x77;
  msg[5] = 0x77; // "www"
  msg[6] = 0xc0;
  msg[7] = 12; // pointer to offset 12
  const [n, end] = readName(msg, 2);
  eq("compressed name", n, "www.example.com.");
  eq("compressed name end offset", end, 8);
}

// --- query build/parse ---
{
  const q = buildQuery(0x1234, "example.com.", TYPE_A);
  const p = parseMessage(q);
  eq("query id", p.id, 0x1234);
  eq("query qname", p.questions[0].name, "example.com.");
  eq("query qtype", p.questions[0].type, TYPE_A);
}

// --- full message with answer parse, incl. compressed CNAME rdata ---
{
  const w = new Writer();
  w.u16(1).u16(0x8400).u16(1).u16(1).u16(0).u16(0);
  w.name("example.com.").u16(TYPE_CNAME).u16(CLASS_IN); // question at offset 12
  w.name("alias.example.com.").u16(TYPE_CNAME).u16(CLASS_IN).u32(300);
  w.u16(2).u8(0xc0).u8(12); // rdata: pointer to "example.com." in question
  const p = parseMessage(w.done());
  eq("answer name", p.answers[0].name, "alias.example.com.");
  eq(
    "answer rdata decompressed",
    readName(p.answers[0].rdata, 0)[0],
    "example.com.",
  );
}

// --- rdata text conversions ---
eq("A text", rdataToText(TYPE_A, Uint8Array.of(192, 0, 2, 1)), "192.0.2.1");
eq("A parse", hex(textToRdata(TYPE_A, "192.0.2.1")), "c0000201");
eq("AAAA roundtrip", formatIpv6(parseIpv6("2001:db8::1")), "2001:db8::1");
eq(
  "AAAA full form",
  formatIpv6(parseIpv6("2001:0db8:0000:0000:0000:0000:0000:0001")),
  "2001:db8::1",
);
eq("AAAA all zero", formatIpv6(parseIpv6("::")), "::");
eq(
  "AAAA embedded v4",
  hex(parseIpv6("::ffff:192.0.2.1")),
  "00000000000000000000ffffc0000201",
);
eq(
  "TXT quoted parse",
  hex(parseTxt('"hi" "yo"')),
  "0268690279 6f".replace(/\s/g, ""),
);
eq("TXT display", rdataToText(TYPE_TXT, parseTxt('"a\\"b"')), '"a\\"b"');
eq("TXT raw split", parseTxt("x".repeat(300)).length, 2 + 300);
eq(
  "generic roundtrip",
  hex(parseGeneric(genericToText(Uint8Array.of(1, 2, 0xff)))),
  "0102ff",
);
eq(
  "unknown type display",
  rdataToText(999, Uint8Array.of(0xde, 0xad)),
  "\\# 2 dead",
);
eq("unknown type name", typeToName(999), "TYPE999");
eq("nameToType TYPE999", nameToType("TYPE999"), 999);
check("RRSIG is ignored", IGNORED_RRTYPES.has(nameToType("RRSIG")));
check("NSEC is ignored", IGNORED_RRTYPES.has(nameToType("NSEC")));
check("NSEC3 is ignored", IGNORED_RRTYPES.has(nameToType("NSEC3")));

// SSHFP
eq("SSHFP type number", TYPE_SSHFP, 44);
eq("SSHFP parse", hex(textToRdata(TYPE_SSHFP, "4 2 aabbCCdd")), "0402aabbccdd");
eq(
  "SSHFP display",
  rdataToText(TYPE_SSHFP, Uint8Array.of(4, 2, 0xaa, 0xbb, 0xcc, 0xdd)),
  "4 2 aabbccdd",
);
eq(
  "SSHFP roundtrip",
  rdataToText(TYPE_SSHFP, textToRdata(TYPE_SSHFP, "1 1 0123456789abcdef")),
  "1 1 0123456789abcdef",
);
check(
  "SSHFP rejects odd hex",
  (() => {
    try {
      textToRdata(TYPE_SSHFP, "4 2 abc");
      return false;
    } catch (e) {
      return true;
    }
  })(),
);

// CNAME parse with relative name
{
  const abs = (n) => (n.endsWith(".") ? n : n + ".example.com.");
  eq(
    "CNAME relative",
    readName(textToRdata(TYPE_CNAME, "www", abs), 0)[0],
    "www.example.com.",
  );
  eq(
    "CNAME absolute",
    readName(textToRdata(TYPE_CNAME, "other.net.", abs), 0)[0],
    "other.net.",
  );
}

// --- SOA ---
{
  const w = new Writer();
  w.name("ns1.example.com.").name("hostmaster.example.com.");
  w.u32(2024011501).u32(7200).u32(3600).u32(1209600).u32(300);
  const soa = w.done();
  eq("soa serial", soaSerial(soa), 2024011501);
  check(
    "soa text contains serial",
    rdataToText(TYPE_SOA, soa).includes("2024011501"),
  );
}

// --- zone store ---
{
  const st = new ZoneStore("example.com");
  eq("relativize apex", st.relativize("EXAMPLE.com."), "");
  eq("relativize sub", st.relativize("www.example.com."), "www");
  eq("relativize foreign", st.relativize("other.net."), "other.net.");
  eq("absolutize @", st.absolutize("@"), "example.com.");
  eq("absolutize rel", st.absolutize("www"), "www.example.com.");
  eq("absolutize abs", st.absolutize("other.net."), "other.net.");

  const i0 = st.add("www", TYPE_A, 300, Uint8Array.of(192, 0, 2, 1));
  const i1 = st.add("", TYPE_TXT, 60, parseTxt('"hello"'));
  eq("store count", st.count, 2);
  const r0 = st.get(i0);
  eq("store get name", r0.name, "www");
  eq("store get type", r0.type, TYPE_A);
  eq("store get ttl", r0.ttl, 300);
  eq("store get rdata", hex(r0.rdata), "c0000201");
  st.replace(i0, "www", TYPE_A, 600, Uint8Array.of(192, 0, 2, 2));
  eq("store replace", st.get(i0).ttl, 600);
  st.remove(i0);
  eq("store remove count", st.count, 1);
  eq("store remove shifts", st.get(0).type, TYPE_TXT);

  // stress: many records, arena growth
  for (let i = 0; i < 50000; i++) {
    st.add(
      "host-" + i,
      TYPE_A,
      300,
      Uint8Array.of(10, i >> 16, (i >> 8) & 0xff, i & 0xff),
    );
  }
  eq("store stress count", st.count, 50001);
  eq("store stress spot check", st.get(25000).name, "host-" + 24999);
}

// --- update message ---
{
  const upd = buildUpdateMessage(7, "example.com.", [
    {
      name: "www.example.com.",
      type: TYPE_A,
      cls: CLASS_NONE,
      ttl: 0,
      rdata: Uint8Array.of(192, 0, 2, 1),
    },
    {
      name: "www.example.com.",
      type: TYPE_A,
      cls: CLASS_IN,
      ttl: 300,
      rdata: Uint8Array.of(192, 0, 2, 2),
    },
  ]);
  const p = parseMessage(upd);
  eq("update opcode", p.opcode, 5);
  eq("update zone", p.questions[0].name, "example.com.");
  eq("update zone type", p.questions[0].type, TYPE_SOA);
  // prcount=0, upcount=2: update RRs occupy the "authority" section slot
  eq("update count", p.authority.length, 2);
  eq("update delete class", p.authority[0].cls, CLASS_NONE);
  eq("update add class", p.authority[1].cls, CLASS_IN);
}

// --- TSIG signing ---
{
  const key = parseTsigSpec("hmac-sha256:KeyName:" + btoa("secret-bytes"));
  eq("tsig key name", key.name, "keyname");
  const q = buildQuery(42, "example.com.", TYPE_SOA);
  const signed = await signMessage(q, key);
  const p = parseMessage(signed);
  eq("tsig arcount", p.additional.length, 1);
  const tsig = p.additional[0];
  eq("tsig rr type", tsig.type, TYPE_TSIG);
  eq("tsig rr class", tsig.cls, CLASS_ANY);
  eq("tsig rr name", tsig.name, "keyname.");
  const [alg, o] = readName(tsig.rdata, 0);
  eq("tsig algorithm", alg, "hmac-sha256.");
  const macSize = (tsig.rdata[o + 8] << 8) | tsig.rdata[o + 9];
  eq("tsig mac size", macSize, 32);
  const origId =
    (tsig.rdata[o + 10 + macSize] << 8) | tsig.rdata[o + 10 + macSize + 1];
  eq("tsig original id", origId, 42);

  // independently recompute the MAC over message + variables
  const v = new Writer();
  v.bytes(q);
  v.bytes(nameToWire("keyname")).u16(CLASS_ANY).u32(0);
  v.bytes(nameToWire("hmac-sha256"));
  const timeHi = (tsig.rdata[o] << 8) | tsig.rdata[o + 1];
  const timeLo =
    ((tsig.rdata[o + 2] << 24) |
      (tsig.rdata[o + 3] << 16) |
      (tsig.rdata[o + 4] << 8) |
      tsig.rdata[o + 5]) >>>
    0;
  v.u16(timeHi).u32(timeLo);
  v.u16((tsig.rdata[o + 6] << 8) | tsig.rdata[o + 7]); // fudge
  v.u16(0).u16(0);
  const ck = await crypto.subtle.importKey(
    "raw",
    key.secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", ck, v.done()),
  );
  eq(
    "tsig mac matches",
    hex(tsig.rdata.subarray(o + 10, o + 10 + macSize)),
    hex(expected),
  );
}

// --- TSIG response verification ---
{
  const key = parseTsigSpec("hmac-sha256:keyname:" + btoa("secret-bytes"));

  // Server-side signing of a response, per RFC 8945 4.3 / 5.3.1.
  const hmacRaw = async (data) => {
    const ck = await crypto.subtle.importKey(
      "raw",
      key.secret,
      { name: "HMAC", hash: key.hash },
      false,
      ["sign"],
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", ck, data));
  };
  const serverSign = async (msg, priorMac, opts = {}) => {
    const {
      first = true,
      unsigned = [], // unsigned messages since the last TSIG
      time = Math.floor(Date.now() / 1000),
      fudge = 300,
      error = 0,
      keyName = key.name,
    } = opts;
    const keyWire = nameToWire(keyName);
    const algWire = nameToWire(key.algo);
    const v = new Writer();
    v.u16(priorMac.length).bytes(priorMac);
    for (const u of unsigned) v.bytes(u);
    v.bytes(msg);
    if (first) {
      v.bytes(keyWire).u16(CLASS_ANY).u32(0);
      v.bytes(algWire).u48(time).u16(fudge);
      v.u16(error).u16(0);
    } else {
      v.u48(time).u16(fudge);
    }
    const mac = await hmacRaw(v.done());
    const rd = new Writer();
    rd.bytes(algWire).u48(time).u16(fudge);
    rd.u16(mac.length).bytes(mac);
    rd.u16((msg[0] << 8) | msg[1])
      .u16(error)
      .u16(0);
    const rdata = rd.done();
    const out = new Writer();
    out.bytes(msg);
    out.bytes(keyWire).u16(TYPE_TSIG).u16(CLASS_ANY).u32(0);
    out.u16(rdata.length).bytes(rdata);
    const signed = out.done();
    signed[11] += 1; // bump ARCOUNT (test messages have ARCOUNT < 255)
    return signed;
  };
  const throws = async (what, fn, substr) => {
    try {
      await fn();
      check(what + " (throws)", false);
    } catch (e) {
      check(
        what + ' ("' + e.message + '" contains "' + substr + '")',
        e.message.includes(substr),
      );
    }
  };
  const mkResp = () => {
    const r = buildQuery(7, "example.com.", TYPE_SOA);
    r[2] |= 0x80; // QR
    return r;
  };

  const session = new TsigSession(key);
  await session.sign(buildQuery(7, "example.com.", TYPE_SOA));

  // Missing TSIG on the first response is fatal.
  await throws(
    "tsig verify rejects unsigned response",
    () => session.verify(mkResp()),
    "not TSIG-signed",
  );

  // Valid first response verifies; a tampered copy does not.
  const resp1 = await serverSign(mkResp(), session.requestMac);
  const tampered = resp1.slice();
  tampered[13] ^= 0x01; // flip a bit in the qname
  await throws(
    "tsig verify detects tampering",
    () => session.verify(tampered),
    "MAC verification failed",
  );
  eq("tsig verify first response", (await session.verify(resp1)).signed, true);

  // Signed continuation (running MAC, timers-only variables).
  const resp2 = await serverSign(mkResp(), session.priorMac, { first: false });
  eq("tsig verify continuation", (await session.verify(resp2)).signed, true);

  // Unsigned intermediate messages are covered by the next signed one.
  const gap1 = mkResp();
  const gap2 = mkResp();
  eq(
    "tsig unsigned intermediate 1",
    (await session.verify(gap1)).signed,
    false,
  );
  eq(
    "tsig unsigned intermediate 2",
    (await session.verify(gap2)).signed,
    false,
  );
  const resp3 = await serverSign(mkResp(), session.priorMac, {
    first: false,
    unsigned: [gap1, gap2],
  });
  eq("tsig verify after gap", (await session.verify(resp3)).signed, true);

  // A continuation that omits the pending unsigned messages must fail.
  eq("tsig unsigned gap", (await session.verify(mkResp())).signed, false);
  const bad = await serverSign(mkResp(), session.priorMac, { first: false });
  await throws(
    "tsig verify detects dropped messages",
    () => session.verify(bad),
    "MAC verification failed",
  );

  // Unsigned TSIG error response (MAC size 0) surfaces the error code.
  {
    const s = new TsigSession(key);
    await s.sign(buildQuery(7, "example.com.", TYPE_SOA));
    const msg = mkResp();
    const rd = new Writer();
    rd.bytes(nameToWire(key.algo)).u48(0).u16(0);
    rd.u16(0); // mac size 0
    rd.u16(7).u16(17).u16(0); // orig id, error BADKEY, other-len
    const rdata = rd.done();
    const out = new Writer();
    out.bytes(msg);
    out.bytes(nameToWire(key.name)).u16(TYPE_TSIG).u16(CLASS_ANY).u32(0);
    out.u16(rdata.length).bytes(rdata);
    const err = out.done();
    err[11] += 1;
    await throws("tsig unsigned error response", () => s.verify(err), "BADKEY");
  }

  // Wrong key name and stale timestamps are rejected.
  {
    const s = new TsigSession(key);
    await s.sign(buildQuery(7, "example.com.", TYPE_SOA));
    const wrongKey = await serverSign(mkResp(), s.requestMac, {
      keyName: "otherkey",
    });
    await throws(
      "tsig verify rejects wrong key",
      () => s.verify(wrongKey),
      "unexpected key",
    );
    const stale = await serverSign(mkResp(), s.requestMac, {
      time: Math.floor(Date.now() / 1000) - 4000,
    });
    await throws(
      "tsig verify rejects stale time",
      () => s.verify(stale),
      "time out of range",
    );
  }
}

// --- display order (indirection array sorted by revname, type, ttl) ---
{
  const st = new ZoneStore("example.com");
  const soa = (() => {
    const w = new Writer();
    w.name("ns1.example.com.").name("host.example.com.");
    w.u32(1).u32(2).u32(3).u32(4).u32(5);
    return w.done();
  })();
  const ip = Uint8Array.of(192, 0, 2, 1);
  // insertion order deliberately scrambled
  const recs = [
    st.add("b.www", TYPE_A, 300, ip), //     rev: www.b
    st.add("mail", TYPE_A, 300, ip), //      rev: mail
    st.add("", TYPE_SOA, 300, soa), //       apex, first
    st.add("www", TYPE_TXT, 60, parseTxt('"x"')), // rev: www, TXT(16) > A(1)
    st.add("www", TYPE_A, 100, ip), //       rev: www, ttl 100 < 300
    st.add("a.www", TYPE_A, 300, ip), //     rev: www.a
    st.add("www", TYPE_A, 300, ip), //       rev: www, ttl 300
    st.add("", TYPE_TXT, 60, parseTxt('"apex"')), // apex, TXT after SOA(6)
  ];
  const order = new Uint32Array(st.count);
  for (let i = 0; i < st.count; i++) order[i] = i;
  order.sort((a, b) => st.compareRecords(a, b));
  const got = Array.from(order, (i) => {
    const r = st.get(i);
    return (
      (r.name === "" ? "@" : r.name) + "/" + typeToName(r.type) + "/" + r.ttl
    );
  });
  eq("display order", got, [
    "@/SOA/300",
    "@/TXT/60",
    "mail/A/300",
    "www/A/100",
    "www/A/300",
    "www/TXT/60",
    "a.www/A/300",
    "b.www/A/300",
  ]);
}

if (failures) {
  console.error("\n" + failures + " failure(s)");
  throw new Error(failures + " test failure(s)");
}
console.log("\nall tests passed");
