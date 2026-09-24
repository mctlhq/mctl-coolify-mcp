#!/usr/bin/env node
// Keeps docs/portal-allowlist.json in step with the tool roster and the
// tools' annotations.
//
// Source of truth: evals/src/contract/__toolsnaps__/ — `_roster.json` (the
// tool names a default install exposes) and one snapshot per tool carrying its
// annotations, both snapshotted by the evals contract test and gated in CI.
//
// The rule the allowlist encodes is "enabled on the portal exactly when the
// tool is read-only". Two drift directions are fail-safe (a new tool is absent
// and so disabled; a renamed tool leaves a dead entry), but the third is not:
// a read-only tool that gains a write action flips its annotation while this
// file would still say `enabled: true`, and the next portal apply would expose
// a write tool. So the check is exact in both directions, and any annotation
// change forces a decision here in the same diff.
//
// Usage:  npm run check:portal-allowlist   # exit 1 on drift

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const snaps = join(root, 'evals/src/contract/__toolsnaps__');

const roster = JSON.parse(readFileSync(join(snaps, '_roster.json'), 'utf8'));
if (!Array.isArray(roster) || roster.length < 20) {
  console.error(`roster looks wrong (${roster.length} entries) — refusing to check`);
  process.exit(2);
}
const allowlist = JSON.parse(readFileSync(join(root, 'docs/portal-allowlist.json'), 'utf8'));

const problems = [];
if (allowlist.portal !== 'mcp')
  problems.push(`portal is ${JSON.stringify(allowlist.portal)}, expected "mcp"`);
if (allowlist.server !== 'coolify')
  problems.push(`server is ${JSON.stringify(allowlist.server)}, expected "coolify"`);
if (allowlist.default_disabled !== true) problems.push('default_disabled must be true');

const listed = allowlist.tools.map((t) => t.name);
const seen = new Set();
for (const name of listed) {
  if (seen.has(name)) problems.push(`${name}: listed twice`);
  seen.add(name);
}
for (const name of roster)
  if (!seen.has(name)) problems.push(`${name}: in the roster but has no decision here`);
for (const name of seen)
  if (!roster.includes(name)) problems.push(`${name}: listed here but not in the roster`);

for (const tool of allowlist.tools) {
  if (!roster.includes(tool.name)) continue;
  if (typeof tool.enabled !== 'boolean') {
    problems.push(`${tool.name}: enabled must be a boolean`);
    continue;
  }
  if (typeof tool.reason !== 'string' || tool.reason.trim() === '')
    problems.push(`${tool.name}: no reason`);
  const readOnly =
    JSON.parse(readFileSync(join(snaps, `${tool.name}.json`), 'utf8')).annotations?.readOnlyHint ===
    true;
  if (tool.enabled !== readOnly) {
    problems.push(
      `${tool.name}: enabled=${tool.enabled} but readOnlyHint=${readOnly} — ` +
        (readOnly ? 'a read-only tool is disabled' : 'a tool that writes is enabled on the portal'),
    );
  }
}

if (problems.length) {
  for (const p of problems) console.error(`docs/portal-allowlist.json: ${p}`);
  process.exit(1);
}
console.log(
  `docs/portal-allowlist.json: ${listed.length} tools, ${allowlist.tools.filter((t) => t.enabled).length} enabled, in step with the roster`,
);
