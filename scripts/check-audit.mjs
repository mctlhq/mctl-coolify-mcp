#!/usr/bin/env node
// The CI security gate: `npm audit` over the whole tree, dev tooling included,
// minus the advisories named in ALLOWED below.
//
// Plain `npm audit --audit-level=high` cannot be the gate while an advisory
// with no fixed release sits in the tree: it fails every pull request
// regardless of content, and a check that is always red gates nothing.
// `--omit=dev` would clear it, but would also stop gating everything the build
// and the publish job execute (shx, tsc, eslint, jest), which is where a
// compromised package does its damage. So the exemption is one advisory wide,
// not one dependency class wide.
//
// Usage:  npm run check:audit
//
// Exit 1: an advisory at or above the threshold that is not allowed.
// Exit 2: the audit could not be read. That is never a pass: a registry error
//         or a truncated report says nothing about what is in the tree.

import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// Each entry needs the reason it cannot be fixed and what removes it.
export const ALLOWED = {
  // braces: stack exhaustion on deeply nested patterns. Affects every release
  // (`*`), so no update clears it. Reached only through markdownlint-cli2 and
  // shx, which glob paths written in this repository, not untrusted input.
  // Remove when braces ships a fix or both tools are gone:
  // https://github.com/mctlhq/mctl-coolify-mcp/issues/14
  'GHSA-vfj7-8cjw-p6xm': 'braces: no fixed release exists',
};

const LEVELS = ['info', 'low', 'moderate', 'high', 'critical'];
export const THRESHOLD = 'high';

const ghsaOf = (url) => /GHSA(?:-[0-9a-z]{4}){3}/.exec(String(url ?? ''))?.[0] ?? null;

// Reads an `npm audit --json` report (auditReportVersion 2). Throws on
// anything it does not recognise instead of treating it as "no advisories".
export function evaluateAudit(report, { allowed = ALLOWED, threshold = THRESHOLD } = {}) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('audit report is not an object');
  }
  if (report.error) {
    throw new Error(`npm audit reported an error: ${report.error.summary ?? report.error.code}`);
  }
  if (report.auditReportVersion !== 2) {
    throw new Error(`unsupported auditReportVersion: ${report.auditReportVersion}`);
  }
  const { vulnerabilities } = report;
  if (vulnerabilities === null || typeof vulnerabilities !== 'object') {
    throw new Error('audit report has no vulnerabilities map');
  }
  const min = LEVELS.indexOf(threshold);
  if (min < 0) throw new Error(`unknown threshold: ${threshold}`);

  // A package is listed either for its own advisory (an object in `via`) or
  // because it depends on a listed package (a string). Every advisory appears
  // as an object exactly where it originates, so those are what gets judged.
  const blocking = new Map();
  const seen = new Set();
  for (const [name, entry] of Object.entries(vulnerabilities)) {
    if (!Array.isArray(entry?.via)) {
      throw new Error(`audit entry for ${name} has no via list`);
    }
    for (const via of entry.via) {
      if (typeof via === 'string') continue;
      const level = LEVELS.indexOf(via?.severity);
      if (level < 0) {
        throw new Error(`advisory on ${name} has an unknown severity: ${via?.severity}`);
      }
      const id = ghsaOf(via.url);
      if (id) seen.add(id);
      if (level < min) continue;
      // An advisory with no recognisable id cannot be on the allowlist.
      if (id && Object.hasOwn(allowed, id)) continue;
      const key = id ?? `${name}:${via.source ?? via.title}`;
      blocking.set(key, {
        id,
        package: name,
        severity: via.severity,
        title: via.title ?? '',
        url: via.url ?? '',
      });
    }
  }
  return {
    blocking: [...blocking.values()],
    unused: Object.keys(allowed).filter((id) => !seen.has(id)),
  };
}

// `npm audit` exits 1 when it finds anything, so the exit code alone says
// nothing; the report on stdout is what counts.
export function runNpmAudit(command = 'npm', args = ['audit', '--json']) {
  return new Promise((done, fail) => {
    execFile(
      command,
      args,
      { maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32' },
      (err, stdout) => {
        if (err && typeof err.code !== 'number') return fail(err);
        try {
          done(JSON.parse(stdout));
        } catch {
          fail(new Error(`npm audit did not print JSON (exit ${err?.code ?? 0})`));
        }
      },
    );
  });
}

export async function main({ audit = runNpmAudit, log = console } = {}) {
  let result;
  try {
    result = evaluateAudit(await audit());
  } catch (e) {
    log.error(`check-audit: could not read the audit: ${e.message}`);
    return 2;
  }
  for (const id of result.unused) {
    log.warn(
      `::warning title=check-audit::${id} is allowed but no longer reported. Remove it from ALLOWED in scripts/check-audit.mjs.`,
    );
  }
  if (result.blocking.length === 0) {
    log.log(
      `check-audit: no advisory at ${THRESHOLD} or above outside the allowlist (${Object.keys(ALLOWED).join(', ')})`,
    );
    return 0;
  }
  for (const a of result.blocking) {
    log.error(`${a.severity}  ${a.package}  ${a.id ?? '(no GHSA id)'}  ${a.title}  ${a.url}`);
  }
  log.error(
    `check-audit: ${result.blocking.length} advisory(ies) at ${THRESHOLD} or above. Run \`npm audit\` for the full report.`,
  );
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main());
}
