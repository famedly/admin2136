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
import {
  buildUpdateMessage,
  IGNORED_RRTYPES,
  DnsError,
  isRejection,
  ixfr,
  axfr,
  serialGt,
  buildIxfrQuery,
} from "../js/dnsops.js";
import { ZoneStore } from "../js/zonestore.js";
import {
  parseCatalog,
  newMemberId,
  memberRecords,
  addUpdates,
  deleteMemberUpdates,
} from "../js/catalog.js";
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
  isEditableType,
  typeHint,
  ADDABLE_TYPES,
  soaFields,
  soaRdata,
  mergeSoa,
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

// Presentation format round trips for all supported types: parsing the
// text and formatting the result again must reproduce the input.
{
  const abs = (n) => (n.endsWith(".") ? n : n + ".example.com.");
  const cases = [
    ["NS", "ns1.example.com."],
    ["PTR", "host.example.com."],
    ["DNAME", "example.net."],
    ["MX", "10 mail.example.com."],
    ["AFSDB", "1 afs.example.com."],
    ["RT", "10 relay.example.com."],
    ["KX", "10 kx.example.com."],
    ["RP", "admin.example.com. info.example.com."],
    ["HINFO", '"PC" "Linux"'],
    ["SPF", '"v=spf1 -all"'],
    ["SRV", "0 5 5060 sip.example.com."],
    ["NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.'],
    ["DS", "60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118"],
    ["CDS", "0 0 0 00"],
    ["DNSKEY", "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+E="],
    ["CDNSKEY", "0 3 0 AA=="],
    ["CERT", "1 0 0 MIIB"],
    ["DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="],
    ["NSEC3PARAM", "1 0 0 -"],
    ["NSEC3PARAM", "1 0 10 aabbccdd"],
    [
      "TLSA",
      "3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6",
    ],
    ["SMIMEA", "3 0 0 308201"],
    ["OPENPGPKEY", "mQINBFit2jsBEADrbl5vjVxYeAE0g0IDYCBpHirv1Sjlqxx5gjtPhb2Y"],
    ["ZONEMD", "2021071219 1 1 aabbcc"],
    ["URI", '10 1 "ftp://ftp1.example.com/public"'],
    ["CAA", '0 issue "letsencrypt.org"'],
    ["CAA", '128 iodef "mailto:security@example.com"'],
    ["CAA", '0 issue ""'],
    ["HTTPS", "1 ."],
    ["HTTPS", "0 svc.example.net."],
    [
      "HTTPS",
      '1 . alpn="h3,h2" ipv4hint=192.0.2.1,192.0.2.2 ech=AEX+DQBB ipv6hint=2001:db8::1',
    ],
    [
      "SVCB",
      '16 foo.example.org. mandatory=alpn,ipv4hint alpn="h2" ipv4hint=192.0.2.1',
    ],
    ["SVCB", '1 foo.example.com. port=53 dohpath="/dns-query{?dns}"'],
    ["SVCB", "1 . no-default-alpn ohttp"],
    ["SVCB", '1 . key667="hello"'],
    ["SVCB", '1 . alpn="f\\\\\\\\oo\\\\,bar,h2"'],
  ];
  for (const [t, text] of cases) {
    const type = nameToType(t);
    check(t + " can be added", ADDABLE_TYPES.includes(type));
    let got;
    try {
      got = rdataToText(type, textToRdata(type, text, abs));
    } catch (e) {
      got = "error: " + e.message;
    }
    eq(t + " roundtrip", got, text);
  }

  const wire = (t, text) => hex(textToRdata(nameToType(t), text, abs));
  eq(
    "MX relative name",
    wire("MX", "10 mail"),
    wire("MX", "10 mail.example.com."),
  );
  eq("CAA wire", wire("CAA", '0 issue "ca.net"'), "0005697373756563612e6e6574");
  eq(
    "CAA unquoted value",
    wire("CAA", "0 issue ca.net; account=1"),
    wire("CAA", '0 issue "ca.net; account=1"'),
  );
  eq(
    "HTTPS wire (RFC 9460 D.2)",
    wire(
      "HTTPS",
      "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
    ),
    "0010" +
      "03666f6f076578616d706c65036f726700" +
      "00000004" +
      "00010004" +
      "000100090268320568332d3139" +
      "00040004c0000201",
  );
  eq(
    "SVCB escaped alpn (RFC 9460 D.2)",
    wire("SVCB", '16 foo.example.org. alpn="f\\\\\\\\oo\\\\,bar,h2"'),
    wire("SVCB", "16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2"),
  );
  eq(
    "DNSKEY multi-line key",
    wire("DNSKEY", "256 3 8 ( AwEAAa\n bc )"),
    wire("DNSKEY", "256 3 8 AwEAAabc"),
  );
  eq(
    "TLSA uppercase hex",
    rdataToText(
      nameToType("TLSA"),
      textToRdata(nameToType("TLSA"), "3 1 1 AB CD"),
    ),
    "3 1 1 abcd",
  );
  eq("SOA is editable", isEditableType(TYPE_SOA), true);
  check("SOA cannot be added", !ADDABLE_TYPES.includes(TYPE_SOA));
  check("unknown type is read-only", !isEditableType(999));
  check("CAA hint", typeHint(nameToType("CAA")).includes("issue"));

  const throws = (what, fn, substr) => {
    try {
      fn();
      check(what + " (throws)", false);
    } catch (e) {
      check(
        what + ' ("' + e.message + '" contains "' + substr + '")',
        e.message.includes(substr),
      );
    }
  };
  throws("MX missing exchange", () => wire("MX", "10"), "too few fields");
  throws("MX extra field", () => wire("MX", "10 a b"), "too many fields");
  throws("MX preference range", () => wire("MX", "70000 a"), "0 to 65535");
  throws("CAA bad tag", () => wire("CAA", '0 is-sue "x"'), "invalid tag");
  throws("DS odd hex", () => wire("DS", "1 2 3 abc"), "hex digits");
  throws("DNSKEY bad base64", () => wire("DNSKEY", "256 3 8 a?b"), "base64");
  throws("HTTPS unknown key", () => wire("HTTPS", "1 . foo=1"), "SvcParamKey");
  throws(
    "HTTPS duplicate key",
    () => wire("HTTPS", "1 . port=1 port=2"),
    "duplicate",
  );
  throws(
    "HTTPS flag with value",
    () => wire("HTTPS", "1 . ohttp=1"),
    "no value",
  );
  throws("unterminated quote", () => wire("CAA", '0 issue "x'), "unterminated");

  // Malformed wire data falls back to the generic representation.
  eq(
    "malformed MX shown generic",
    rdataToText(nameToType("MX"), Uint8Array.of(0, 10)),
    "\\# 2 000a",
  );
  eq(
    "HTTPS unordered keys shown generic",
    rdataToText(
      nameToType("HTTPS"),
      Uint8Array.of(0, 1, 0, 0, 3, 0, 2, 0, 1, 0, 1, 0, 0),
    ).startsWith("\\#"),
    true,
  );
}

// Compressed names in SRV and NAPTR rdata are expanded on receipt.
{
  const w = new Writer();
  w.u16(1).u16(0x8400).u16(1).u16(2).u16(0).u16(0);
  w.name("example.com.").u16(TYPE_A).u16(CLASS_IN); // question at offset 12
  w.u8(0xc0).u8(12).u16(nameToType("SRV")).u16(CLASS_IN).u32(300);
  w.u16(10).u16(1).u16(2).u16(3).bytes([1, 0x78]).u8(0xc0).u8(12);
  w.u8(0xc0).u8(12).u16(nameToType("NAPTR")).u16(CLASS_IN).u32(300);
  w.u16(10).u16(1).u16(2).bytes([1, 0x53, 0, 0]).u8(0xc0).u8(12);
  const p = parseMessage(w.done());
  eq(
    "SRV decompressed",
    rdataToText(p.answers[0].type, p.answers[0].rdata),
    "1 2 3 x.example.com.",
  );
  eq(
    "NAPTR decompressed",
    rdataToText(p.answers[1].type, p.answers[1].rdata),
    '1 2 "S" "" "" example.com.',
  );
}

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
  eq("soa fields roundtrip", hex(soaRdata(soaFields(soa))), hex(soa));

  // Three-way merge: the user changed rname and minimum starting from
  // `base`; meanwhile another update raised the serial and changed retry.
  const f = (text) => soaFields(textToRdata(TYPE_SOA, text));
  const base = f(
    "ns1.example.com. hostmaster.example.com. 5 7200 3600 1209600 300",
  );
  const edited = f(
    "ns1.example.com. admin.example.com. 5 7200 3600 1209600 60",
  );
  const current = f(
    "ns1.example.com. hostmaster.example.com. 9 7200 900 1209600 300",
  );
  eq(
    "soa merge",
    rdataToText(TYPE_SOA, soaRdata(mergeSoa(base, edited, current))),
    "ns1.example.com. admin.example.com. 10 7200 900 1209600 60",
  );
  eq(
    "soa merge ignores name case",
    mergeSoa(
      base,
      f("NS1.example.com. hostmaster.example.com. 5 7200 3600 1209600 300"),
      current,
    ).mname,
    "ns1.example.com.",
  );
  eq(
    "soa serial wraps (RFC 1982)",
    mergeSoa(base, edited, { ...current, serial: 0xffffffff }).serial,
    0,
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

  // prerequisites go into the answer section slot, before the updates
  const rr = (cls, ttl) => ({
    name: "example.com.",
    type: TYPE_SOA,
    cls,
    ttl,
    rdata: Uint8Array.of(0, 0, ...new Array(20).fill(0)),
  });
  const q = parseMessage(
    buildUpdateMessage(
      8,
      "example.com.",
      [rr(CLASS_IN, 300)],
      [rr(CLASS_IN, 0)],
    ),
  );
  eq("update prereq count", q.answers.length, 1);
  eq("update prereq ttl", q.answers[0].ttl, 0);
  eq("update count with prereq", q.authority.length, 1);
  eq("update ttl with prereq", q.authority[0].ttl, 300);
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

// --- DNS error responses ---
{
  const resp = (rcode, tsigError = 0) => {
    const w = new Writer();
    w.bytes(buildQuery(9, "example.com.", TYPE_SOA));
    if (tsigError) {
      const rd = new Writer();
      rd.name("hmac-sha256.").u48(0).u16(300).u16(0); // no MAC
      rd.u16(9).u16(tsigError).u16(0);
      const rdata = rd.done();
      w.name("key.").u16(TYPE_TSIG).u16(CLASS_ANY).u32(0);
      w.u16(rdata.length).bytes(rdata);
    }
    const m = w.done();
    m[3] = rcode;
    if (tsigError) m[11] = 1; // ARCOUNT
    return parseMessage(m);
  };
  const refused = new DnsError("update failed", resp(5));
  eq("DnsError message", refused.message, "update failed: REFUSED");
  check("REFUSED is a rejection", isRejection(refused));
  const badkey = new DnsError("AXFR refused", resp(9, 17));
  eq("DnsError TSIG message", badkey.message, "AXFR refused: NOTAUTH (BADKEY)");
  eq("DnsError TSIG error", badkey.tsigError, "BADKEY");
  check("NOTAUTH is a rejection", isRejection(badkey));
  check(
    "YXRRSET is no rejection",
    !isRejection(new DnsError("update failed", resp(7))),
  );
  check("plain error is no rejection", !isRejection(new Error("timeout")));
  check(
    "SERVFAIL is no rejection, even with a TSIG error",
    !isRejection(new DnsError("AXFR refused", resp(2, 16))),
  );
}

// --- catalog zones (RFC 9432) ---
{
  const ptr = (n) => nameToWire(n);
  const mkCatalog = () => {
    const st = new ZoneStore("catalog.invalid");
    st.add("", TYPE_SOA, 0, Uint8Array.of(0, 0, ...new Array(20).fill(0)));
    st.add("", nameToType("NS"), 0, nameToWire("invalid."));
    st.add("version", TYPE_TXT, 0, parseTxt('"2"'));
    st.add("b1.zones", nameToType("PTR"), 0, ptr("b.example."));
    st.add("group.b1.zones", TYPE_TXT, 0, parseTxt('"web"'));
    st.add("A2.zones", nameToType("PTR"), 0, ptr("a.example."));
    st.add("ext", TYPE_TXT, 0, parseTxt('"custom"'));
    st.add("nozone.zones", TYPE_TXT, 0, parseTxt('"orphan property"'));
    return st;
  };

  const st = mkCatalog();
  eq("findName", st.findName("VERSION"), [2]);
  {
    const t = mkCatalog();
    const v2 = parseTxt('"2"');
    eq("indexOf", t.indexOf("VERSION", TYPE_TXT, v2), 2);
    eq(
      "indexOf other rdata",
      t.indexOf("version", TYPE_TXT, parseTxt('"3"')),
      -1,
    );
    eq("indexOf other type", t.indexOf("version", TYPE_SOA, v2), -1);
    t.remove(0);
    eq("indexOf after shift", t.indexOf("version", TYPE_TXT, v2), 1);
  }
  const cat = parseCatalog(st);
  check("catalog detected", cat !== null);
  eq("catalog version", cat.version, "2");
  eq(
    "catalog members",
    cat.members.map((m) => [m.zone, m.id, m.group, m.recs]),
    [
      ["a.example.", "A2", null, [5]],
      ["b.example.", "b1", "web", [3, 4]],
    ],
  );

  const plain = new ZoneStore("example.com");
  plain.add("www", TYPE_A, 300, Uint8Array.of(192, 0, 2, 1));
  eq("plain zone is no catalog", parseCatalog(plain), null);
  plain.add("version", TYPE_TXT, 0, parseTxt('"2"'));
  eq(
    "version alone with other records is no catalog",
    parseCatalog(plain),
    null,
  );
  plain.add("x.zones", nameToType("PTR"), 0, ptr("member.example."));
  eq(
    "mixed zone with members is a catalog",
    parseCatalog(plain)?.members.length,
    1,
  );

  const empty = new ZoneStore("catalog.invalid");
  empty.add("version", TYPE_TXT, 0, parseTxt('"2"'));
  eq("empty catalog", parseCatalog(empty)?.members, []);
  empty.replace(0, "version", TYPE_TXT, 0, parseTxt('"3"'));
  eq("unknown catalog version", parseCatalog(empty), null);

  const id = newMemberId(cat);
  check("member id is a hex label", /^[0-9a-f]{16}$/.test(id));
  const recs = memberRecords("c.example", id, "mail");
  eq(
    "member records",
    recs.map((r) => [r.name, typeToName(r.type), rdataToText(r.type, r.rdata)]),
    [
      [id + ".zones", "PTR", "c.example."],
      ["group." + id + ".zones", "TXT", '"mail"'],
    ],
  );
  const add = addUpdates(st, recs);
  eq("add update name", add[0].name, id + ".zones.catalog.invalid.");
  eq("add update class", add[0].cls, CLASS_IN);
  const del = deleteMemberUpdates(st, cat.members[1]);
  eq(
    "delete member updates",
    del.map((u) => [u.name, typeToName(u.type), u.cls]),
    [
      ["b1.zones.catalog.invalid.", "PTR", CLASS_NONE],
      ["group.b1.zones.catalog.invalid.", "TXT", CLASS_NONE],
    ],
  );
}

// --- IXFR (RFC 1995) ---
{
  const Z = "example.com.";
  const soaRdata = (serial) => {
    const w = new Writer();
    w.name("ns1.example.com.").name("host.example.com.");
    w.u32(serial).u32(3600).u32(600).u32(86400).u32(300);
    return w.done();
  };
  const SOA = (serial) => ({
    name: Z,
    type: TYPE_SOA,
    ttl: 300,
    rdata: soaRdata(serial),
  });
  const A = (name, ip, ttl = 300) => ({
    name: name + "." + Z,
    type: TYPE_A,
    ttl,
    rdata: parseIpv4(ip),
  });
  const TXT = (name, text) => ({
    name: name + "." + Z,
    type: TYPE_TXT,
    ttl: 300,
    rdata: parseTxt(text),
  });
  const RRSIG = {
    name: Z,
    type: nameToType("RRSIG"),
    ttl: 300,
    rdata: Uint8Array.of(1, 2),
  };

  // A fake connection answering the query with the given messages, each a
  // list of answer records.
  const fakeConn = (messages, rcode = 0) => {
    const conn = { sent: null, queue: [] };
    conn.send = (msg) => {
      conn.sent = msg;
      for (const rrs of messages) {
        const w = new Writer();
        w.bytes(msg.subarray(0, 2))
          .u16(0x8400 | rcode)
          .u16(1)
          .u16(rrs.length);
        w.u16(0).u16(0);
        w.name(Z).u16(251).u16(CLASS_IN);
        for (const rr of rrs) {
          w.name(rr.name).u16(rr.type).u16(CLASS_IN).u32(rr.ttl);
          w.u16(rr.rdata.length).bytes(rr.rdata);
        }
        conn.queue.push(w.done());
      }
    };
    conn.recv = async () => conn.queue.shift();
    return conn;
  };
  const run = async (messages, clientSerial = 5) => {
    const full = [];
    const conn = fakeConn(messages);
    const res = await ixfr(
      conn,
      Z,
      null,
      { ttl: 300, rdata: soaRdata(clientSerial) },
      (rr) => full.push(rr),
    );
    return {
      conn,
      kind: res.kind,
      serial: soaSerial(res.soa.rdata),
      changes: res.changes.map(
        (c) =>
          c.op + " " + c.rr.name + " " + rdataToText(c.rr.type, c.rr.rdata),
      ),
      full: full.map((rr) => rr.name + " " + typeToName(rr.type)),
    };
  };

  check("serialGt", serialGt(6, 5) && !serialGt(5, 5) && !serialGt(4, 5));
  check("serialGt wraps", serialGt(1, 0xffffffff) && !serialGt(0xffffffff, 1));

  const q = parseMessage(
    buildIxfrQuery(3, Z, { ttl: 300, rdata: soaRdata(5) }),
  );
  eq("ixfr query type", q.questions[0].type, 251);
  eq("ixfr query authority SOA", soaSerial(q.authority[0].rdata), 5);

  let r = await run([[SOA(5)]]);
  eq("ixfr up to date", [r.kind, r.serial], ["uptodate", 5]);
  r = await run([[SOA(4)]]);
  eq("ixfr older server", [r.kind, r.serial], ["uptodate", 4]);

  // two difference sequences 5 -> 6 -> 7, split over messages
  r = await run([
    [SOA(7), SOA(5), A("x", "192.0.2.1"), SOA(6)],
    [A("x", "192.0.2.2"), RRSIG, SOA(6), TXT("t", '"old"')],
    [SOA(7), TXT("t", '"new"'), A("y", "192.0.2.3"), SOA(7)],
  ]);
  eq("ixfr incremental kind", [r.kind, r.serial], ["incremental", 7]);
  eq("ixfr incremental changes", r.changes, [
    "del x.example.com. 192.0.2.1",
    "add x.example.com. 192.0.2.2",
    'del t.example.com. "old"',
    'add t.example.com. "new"',
    "add y.example.com. 192.0.2.3",
  ]);
  eq("ixfr query sent", parseMessage(r.conn.sent).questions[0].type, 251);

  // a difference sequence that only deletes
  r = await run([[SOA(6), SOA(5), A("x", "192.0.2.1"), SOA(6), SOA(6)]]);
  eq("ixfr deletion only", r.changes, ["del x.example.com. 192.0.2.1"]);

  // full zone instead of differences
  r = await run([
    [SOA(7), A("x", "192.0.2.1")],
    [TXT("t", '"x"'), SOA(7)],
  ]);
  eq("ixfr full kind", r.kind, "full");
  eq("ixfr full records", r.full, [
    "example.com. SOA",
    "x.example.com. A",
    "t.example.com. TXT",
  ]);
  r = await run([[SOA(7), SOA(7)]]);
  eq(
    "ixfr full SOA-only zone",
    [r.kind, r.full],
    ["full", ["example.com. SOA"]],
  );

  // errors
  try {
    await ixfr(
      fakeConn([[]], 4),
      Z,
      null,
      { ttl: 0, rdata: soaRdata(5) },
      () => {},
    );
    check("ixfr NOTIMP throws", false);
  } catch (e) {
    check("ixfr NOTIMP is a DnsError", e instanceof DnsError && e.rcode === 4);
  }

  // AXFR on top of the shared stream code
  const seen = [];
  const n = await axfr(
    fakeConn([[SOA(7), A("x", "192.0.2.1"), RRSIG], [SOA(7)]]),
    Z,
    null,
    (rr) => seen.push(typeToName(rr.type)),
  );
  eq("axfr records", [n, seen], [2, ["SOA", "A"]]);

  // applying the changes to a store: relative to the last transfer
  const mkStore = () => {
    const st = new ZoneStore("example.com");
    st.add("", TYPE_SOA, 300, soaRdata(5));
    st.add("www", TYPE_A, 300, parseIpv4("192.0.2.1"));
    st.add("mail", TYPE_A, 300, parseIpv4("192.0.2.9"));
    st.add("t", TYPE_TXT, 300, parseTxt('"keep"'));
    st.add("t", TYPE_TXT, 300, parseTxt('"old"'));
    st.serial = 5;
    st.syncSoa = { ttl: 300, rdata: soaRdata(5) };
    st.markSynced();
    return st;
  };
  const dump = (st) => {
    const out = [];
    for (let i = 0; i < st.count; i++) {
      const x = st.get(i);
      out.push(
        (x.name || "@") +
          " " +
          x.ttl +
          " " +
          typeToName(x.type) +
          " " +
          rdataToText(x.type, x.rdata),
      );
    }
    return out.sort();
  };
  const ch = (op, rr) => ({ op, rr });
  const base = dump(mkStore());

  // Local edits acknowledged by the server: one it applied (mine), and
  // ones it silently ignored (phantom add, phantom delete, duplicate add,
  // phantom TTL change via replace, SOA edit).
  const st = mkStore();
  st.add("mine", TYPE_A, 300, parseIpv4("192.0.2.50"));
  st.add("phantom", TYPE_A, 300, parseIpv4("192.0.2.66"));
  st.remove(2); // mail
  st.add("www", TYPE_A, 300, parseIpv4("192.0.2.1")); // duplicate
  st.replace(3, "t", TYPE_TXT, 999, parseTxt('"keep"'));
  st.replace(0, "", TYPE_SOA, 300, soaRdata(6));
  st.serial = 6;

  // revertToSynced() restores exactly the transferred contents
  const reverted = mkStore();
  reverted.add("x", TYPE_A, 1, parseIpv4("192.0.2.99"));
  reverted.remove(1);
  reverted.replace(0, "", TYPE_SOA, 300, soaRdata(9));
  reverted.serial = 9;
  eq("revert reports changes", reverted.revertToSynced(), true);
  eq("revert restores contents", dump(reverted), base);
  eq("revert restores serial", reverted.serial, 5);
  eq("revert without changes", reverted.revertToSynced(), false);

  const ok = st.applyChanges(
    [
      // 5 -> 6: www changes address, t "old" goes, mine was applied
      ch("del", A("www", "192.0.2.1")),
      ch("del", TXT("t", '"old"')),
      ch("add", A("www", "192.0.2.2")),
      ch("add", A("mine", "192.0.2.50")),
      // 6 -> 7: TTL change of www, a record added and removed again
      ch("del", A("www", "192.0.2.2")),
      ch("add", A("new", "192.0.2.7")),
      ch("add", A("WWW", "192.0.2.2", 600)),
      ch("del", A("new", "192.0.2.7")),
    ],
    SOA(7),
  );
  eq("applyChanges succeeds", ok, true);
  eq("applyChanges yields the server state", dump(st), [
    "@ 300 SOA ns1.example.com. host.example.com. 7 3600 600 86400 300",
    "WWW 600 A 192.0.2.2",
    "mail 300 A 192.0.2.9",
    "mine 300 A 192.0.2.50",
    't 300 TXT "keep"',
  ]);
  eq("applyChanges serial", st.serial, 7);
  eq("applyChanges sync SOA", soaSerial(st.syncSoa.rdata), 7);
  eq("applyChanges new sync point", st.revertToSynced(), false);

  // differences that do not fit the last transfer are rejected untouched
  for (const [what, changes] of [
    ["deletion of a missing record", [ch("del", A("gone", "192.0.2.5"))]],
    ["addition of a present record", [ch("add", A("mail", "192.0.2.9"))]],
    [
      "double deletion",
      [ch("del", A("mail", "192.0.2.9")), ch("del", A("mail", "192.0.2.9"))],
    ],
  ]) {
    const bad = mkStore();
    bad.add("local", TYPE_A, 300, parseIpv4("192.0.2.70"));
    eq(
      "applyChanges rejects " + what,
      bad.applyChanges(changes, SOA(7)),
      false,
    );
    eq("rejected " + what + " leaves the last transfer", dump(bad), base);
    eq(
      "rejected " + what + " keeps the sync SOA",
      soaSerial(bad.syncSoa.rdata),
      5,
    );
  }

  // compaction keeps all records and drops the garbage
  const before = dump(st);
  for (let i = 0; i < 5000; i++)
    st.replace(
      1,
      st.get(1).name,
      st.get(1).type,
      st.get(1).ttl,
      st.get(1).rdata.slice(),
    );
  const bloated = st.arenaLen;
  st.compact();
  eq("compact keeps records", dump(st), before);
  check("compact shrinks arena", st.arenaLen < bloated / 10);
  st.add("after", TYPE_A, 1, parseIpv4("192.0.2.8"));
  eq("store usable after compact", st.get(st.count - 1).name, "after");
}

if (failures) {
  console.error("\n" + failures + " failure(s)");
  throw new Error(failures + " test failure(s)");
}
console.log("\nall tests passed");
