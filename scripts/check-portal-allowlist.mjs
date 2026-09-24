#!/usr/bin/env node
// Keeps docs/portal-allowlist.json in step with the tool roster and the
// tools' annotations.
//
// Source of truth: evals/src/contract/__toolsnaps__/ — `_roster.json` (the
// tool names a default install exposes) and one snapshot per tool carrying its
// annotations, both snapshotted by the evals contract test and gated in CI.
//
// What this guarantees is allowlist <-> annotation sync, not allowlist <->
// behaviour: `TOOL_ANNOTATIONS` is hand-maintained, and a tool that gains a
// write action only stops being read-only once someone flips its annotation.
// What it buys is that the flip cannot land without a decision here: the
// snapshot update CLAUDE.md requires on any annotation change fails this
// check until the portal entry agrees.
//
// The rule, per tool:
//   - a tool that is not read-only must be disabled. Hard fail, no override:
//     this is the direction that would expose a write tool on the portal.
//   - a read-only tool is enabled, unless its entry says
//     `"override": "sensitive-read"` with `enabled: false` — the file may be
//     more conservative than the annotation, never less.
// Every roster tool needs exactly one entry, and every entry a reason.
//
// Usage:  npm run check:portal-allowlist   # exit 1 on drift

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const OVERRIDES = new Set(['sensitive-read']);

/**
 * @param {unknown} allowlist the parsed docs/portal-allowlist.json
 * @param {string[]} roster tool names a default install exposes
 * @param {(name: string) => boolean | undefined} readOnlyOf a tool's
 *   readOnlyHint, or undefined when its snapshot is missing
 * @returns {string[]} one line per problem; empty when in step
 */
export function findProblems(allowlist, roster, readOnlyOf) {
  const problems = [];
  if (allowlist?.portal !== 'mcp')
    problems.push(`portal is ${JSON.stringify(allowlist?.portal)}, expected "mcp"`);
  if (allowlist?.server !== 'coolify')
    problems.push(`server is ${JSON.stringify(allowlist?.server)}, expected "coolify"`);
  if (allowlist?.default_disabled !== true) problems.push('default_disabled must be true');
  if (!Array.isArray(allowlist?.tools)) {
    problems.push('tools must be an array');
    return problems;
  }

  const seen = new Set();
  for (const tool of allowlist.tools) {
    if (typeof tool?.name !== 'string' || tool.name === '') {
      problems.push(`an entry has no name: ${JSON.stringify(tool)}`);
      continue;
    }
    if (seen.has(tool.name)) problems.push(`${tool.name}: listed twice`);
    seen.add(tool.name);
  }
  for (const name of roster)
    if (!seen.has(name)) problems.push(`${name}: in the roster but has no decision here`);
  for (const name of seen)
    if (!roster.includes(name)) problems.push(`${name}: listed here but not in the roster`);

  for (const tool of allowlist.tools) {
    if (typeof tool?.name !== 'string' || !roster.includes(tool.name)) continue;
    const { name, enabled, override, reason } = tool;
    if (typeof enabled !== 'boolean') {
      problems.push(`${name}: enabled must be a boolean`);
      continue;
    }
    if (typeof reason !== 'string' || reason.trim() === '') problems.push(`${name}: no reason`);
    if (override !== undefined && !OVERRIDES.has(override))
      problems.push(`${name}: unknown override ${JSON.stringify(override)}`);
    const readOnly = readOnlyOf(name);
    if (readOnly === undefined) {
      problems.push(`${name}: no tool snapshot to read its annotations from`);
      continue;
    }
    if (enabled && !readOnly) {
      problems.push(
        `${name}: enabled, but readOnlyHint is not true — a tool that writes is on the portal`,
      );
    } else if (!enabled && readOnly && override === undefined) {
      problems.push(
        `${name}: a read-only tool is disabled — enable it, or say "override": "sensitive-read" and why`,
      );
    } else if (override !== undefined && (enabled || !readOnly)) {
      problems.push(`${name}: an override only applies to a disabled read-only tool`);
    }
  }
  return problems;
}

function main() {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const snaps = join(root, 'evals/src/contract/__toolsnaps__');
  const roster = JSON.parse(readFileSync(join(snaps, '_roster.json'), 'utf8'));
  if (!Array.isArray(roster) || roster.length < 20) {
    const size = Array.isArray(roster) ? `${roster.length} entries` : 'not an array';
    console.error(`roster looks wrong (${size}) — refusing to check`);
    process.exit(2);
  }
  const allowlist = JSON.parse(readFileSync(join(root, 'docs/portal-allowlist.json'), 'utf8'));
  const readOnlyOf = (name) => {
    const path = join(snaps, `${name}.json`);
    if (!existsSync(path)) return undefined;
    return JSON.parse(readFileSync(path, 'utf8')).annotations?.readOnlyHint === true;
  };

  const problems = findProblems(allowlist, roster, readOnlyOf);
  if (problems.length) {
    for (const p of problems) console.error(`docs/portal-allowlist.json: ${p}`);
    process.exit(1);
  }
  const enabled = allowlist.tools.filter((t) => t.enabled).length;
  console.log(
    `docs/portal-allowlist.json: ${allowlist.tools.length} tools, ${enabled} enabled, in step with the roster`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
