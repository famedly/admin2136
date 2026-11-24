// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test coverage of js/*.js: runs the smoke tests (Node) and the end-to-end
// tests (Chromium) with V8 coverage and reports the merged result.
//
//   nix develop .#e2e --command node test/coverage.mjs [--details]
//   node test/coverage.mjs --report DIR [--details]   (report only)
//
// Also writes the result as LCOV (paths relative to the repository) to
// coverage/lcov.info, or the file given with --lcov FILE, for editors and
// other tools.
//
// Coverage is computed from V8 block coverage, like c8 does: every block
// range V8 reports (if/else arms, ternary and logical operator sides,
// code after an early return, catch clauses, ...) counts as a branch. A
// function that never ran in any test only counts as an uncovered
// function: V8 reports no blocks inside it.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const details = args.includes("--details");
const reportIdx = args.indexOf("--report");
const lcovIdx = args.indexOf("--lcov");
const lcovFile = path.resolve(
  lcovIdx >= 0 ? args[lcovIdx + 1] : path.join(root, "coverage/lcov.info"),
);

let dir;
let failed = false;
if (reportIdx >= 0) {
  dir = path.resolve(args[reportIdx + 1]);
} else {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "admin2136-coverage-"));
  const run = (what, cmd, env = {}) => {
    console.log(`--- ${what}`);
    const r = spawnSync(process.execPath, cmd, {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "inherit"],
      encoding: "utf8",
    });
    // The smoke tests print a line per check; keep the summary only.
    const out = r.stdout.split("\n").filter((l) => !/^ok:|^\[/.test(l));
    console.log(out.join("\n").trim());
    if (r.status !== 0) failed = true;
  };
  run("smoke tests", ["test/smoke.mjs"], {
    NODE_V8_COVERAGE: path.join(dir, "node"),
  });
  run("end-to-end tests", [
    "test/e2e/run.mjs",
    "--coverage",
    path.join(dir, "browser"),
  ]);
}

// ---- merge ----

// All script coverage entries of the site's modules, by file.
const entries = new Map();
for (const sub of fs.readdirSync(dir, { recursive: true })) {
  if (!sub.endsWith(".json")) continue;
  const data = JSON.parse(fs.readFileSync(path.join(dir, sub), "utf8"));
  for (const script of data.result ?? []) {
    if (!script.url.startsWith("file://" + root + "/js/")) continue;
    const file = script.url.slice(("file://" + root + "/").length);
    if (!entries.has(file)) entries.set(file, []);
    entries.get(file).push(script);
  }
}

// Mark the characters that belong to comments (or whitespace), which do
// not make a line count as code. A rough lexer: strings, template
// literals and regular expression literals are skipped.
function codeMask(src) {
  const code = new Uint8Array(src.length);
  let i = 0;
  let prev = ""; // last significant character, to tell regex from division
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (c === "/" && next === "/") {
      while (i < src.length && src[i] !== "\n") i++;
    } else if (c === "/" && next === "*") {
      const end = src.indexOf("*/", i + 2);
      i = end < 0 ? src.length : end + 2;
    } else if (c === '"' || c === "'" || c === "`") {
      const start = i++;
      while (i < src.length && src[i] !== c) i += src[i] === "\\" ? 2 : 1;
      i++;
      code.fill(1, start, i);
      prev = c;
    } else if (
      c === "/" &&
      (prev === "" || "(,=:[!&|?{};+-*%<>~^".includes(prev))
    ) {
      const start = i++;
      let cls = false;
      while (i < src.length && (cls || src[i] !== "/") && src[i] !== "\n") {
        if (src[i] === "\\") i++;
        else if (src[i] === "[") cls = true;
        else if (src[i] === "]") cls = false;
        i++;
      }
      i++;
      code.fill(1, start, i);
      prev = "/";
    } else {
      if (!/\s/.test(c)) {
        code[i] = 1;
        prev = c;
      }
      i++;
    }
  }
  return code;
}

const report = [];
for (const file of [...fs.readdirSync(path.join(root, "js"))].sort()) {
  if (!file.endsWith(".js")) continue;
  const rel = "js/" + file;
  const src = fs.readFileSync(path.join(root, rel), "utf8");
  const code = codeMask(src);
  const covered = new Uint8Array(src.length);
  const blocks = new Map(); // "start:end" -> start offset
  const functions = new Map(); // "start:end" -> { name, start, hit }

  for (const script of entries.get(rel) ?? []) {
    // Innermost range wins: paint outer ranges first.
    const counts = new Int32Array(src.length).fill(-1);
    const ranges = [];
    for (const fn of script.functions) {
      fn.ranges.forEach((r, i) => {
        ranges.push(r);
        const key = r.startOffset + ":" + r.endOffset;
        if (i === 0 && fn.functionName !== "") {
          const f = functions.get(key) ?? {
            name: fn.functionName,
            start: r.startOffset,
            hit: false,
          };
          f.hit ||= r.count > 0;
          functions.set(key, f);
        } else if (i > 0) {
          blocks.set(key, r.startOffset);
        }
      });
    }
    ranges.sort(
      (a, b) => a.startOffset - b.startOffset || b.endOffset - a.endOffset,
    );
    for (const r of ranges)
      counts.fill(r.count, r.startOffset, Math.min(r.endOffset, src.length));
    for (let i = 0; i < src.length; i++) if (counts[i] > 0) covered[i] = 1;
  }
  const hasData = entries.has(rel);

  // A block is covered if its first code character ran.
  const firstCode = (start) => {
    let i = start;
    while (i < src.length && !code[i]) i++;
    return i;
  };
  const lineOf = (offset) => src.slice(0, offset).split("\n").length;
  const uncoveredBlocks = [...blocks.values()].filter(
    (s) => !covered[firstCode(s)],
  );

  // Lines: those with code, covered if their first code character ran.
  let lines = 0;
  let linesHit = 0;
  const uncoveredLines = [];
  const lineHits = []; // [line, 0 | 1] for LCOV
  let offset = 0;
  src.split("\n").forEach((line, n) => {
    let i = offset;
    while (i < offset + line.length && !code[i]) i++;
    if (i < offset + line.length) {
      lines++;
      if (covered[i]) linesHit++;
      else uncoveredLines.push(n + 1);
      lineHits.push([n + 1, covered[i]]);
    }
    offset += line.length + 1;
  });

  const fns = [...functions.values()];
  report.push({
    file: rel,
    hasData,
    lines: [linesHit, lines],
    branches: [blocks.size - uncoveredBlocks.length, blocks.size],
    functions: [fns.filter((f) => f.hit).length, fns.length],
    uncoveredBlocks: uncoveredBlocks
      .map((s) => firstCode(s))
      .sort((a, b) => a - b)
      .map((s) => [lineOf(s), src.slice(s, src.indexOf("\n", s)).trim()]),
    uncoveredFunctions: fns
      .filter((f) => !f.hit)
      .map((f) => [lineOf(f.start), f.name]),
    uncoveredLines,
    lineHits,
    blockHits: [...blocks.values()]
      .map((s) => firstCode(s))
      .sort((a, b) => a - b)
      .map((s) => [lineOf(s), covered[s]]),
    // LCOV needs unique function names: add the line to repeated ones
    // (e.g. the read() methods of the rdata field codecs).
    functionHits: fns.map((f) => {
      const line = lineOf(f.start);
      const repeated = fns.filter((g) => g.name === f.name).length > 1;
      return [line, repeated ? `${f.name}@${line}` : f.name, f.hit ? 1 : 0];
    }),
  });
}

// ---- report ----

const pct = ([hit, total]) =>
  total ? ((100 * hit) / total).toFixed(1) + "%" : "-";
const cell = (v) => `${pct(v).padStart(6)} (${v[0]}/${v[1]})`.padEnd(20);
const sum = (k) =>
  report.reduce((a, r) => [a[0] + r[k][0], a[1] + r[k][1]], [0, 0]);
console.log(
  "\n" +
    "File".padEnd(18) +
    "Lines".padEnd(20) +
    "Branches".padEnd(20) +
    "Functions",
);
for (const r of report) {
  console.log(
    r.file.padEnd(18) +
      cell(r.lines) +
      cell(r.branches) +
      cell(r.functions) +
      (r.hasData ? "" : "  (not loaded)"),
  );
}
console.log(
  "All files".padEnd(18) +
    cell(sum("lines")) +
    cell(sum("branches")) +
    cell(sum("functions")),
);

if (details) {
  for (const r of report) {
    if (!r.uncoveredBlocks.length && !r.uncoveredFunctions.length) continue;
    console.log(`\n${r.file}:`);
    for (const [line, name] of r.uncoveredFunctions)
      console.log(`  ${line}: function ${name} not called`);
    for (const [line, text] of r.uncoveredBlocks)
      console.log(`  ${line}: ${text.slice(0, 100)}`);
  }
}
// LCOV, with paths relative to the repository (e.g. for editors).
const lcov = [];
for (const r of report) {
  if (!r.hasData) continue;
  lcov.push("TN:", "SF:" + r.file);
  for (const [line, name] of r.functionHits) lcov.push(`FN:${line},${name}`);
  for (const [, name, hit] of r.functionHits) lcov.push(`FNDA:${hit},${name}`);
  lcov.push("FNF:" + r.functions[1], "FNH:" + r.functions[0]);
  r.blockHits.forEach(([line, hit], i) =>
    lcov.push(`BRDA:${line},${i},0,${hit}`),
  );
  lcov.push("BRF:" + r.branches[1], "BRH:" + r.branches[0]);
  for (const [line, hit] of r.lineHits) lcov.push(`DA:${line},${hit}`);
  lcov.push("LF:" + r.lines[1], "LH:" + r.lines[0], "end_of_record");
}
fs.mkdirSync(path.dirname(lcovFile), { recursive: true });
fs.writeFileSync(lcovFile, lcov.join("\n") + "\n");

console.log("\ncoverage data: " + dir);
console.log("LCOV: " + path.relative(process.cwd(), lcovFile));
if (failed) {
  console.error("tests failed");
  process.exitCode = 1;
}
