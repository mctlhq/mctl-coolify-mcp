import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from '@jest/globals';
import { findProblems } from '../check-portal-allowlist.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const READ_ONLY: Record<string, boolean> = { get_version: true, logs: true, deploy: false };
const ROSTER = Object.keys(READ_ONLY);
const readOnlyOf = (name: string): boolean | undefined => READ_ONLY[name];

type Tool = { name: string; enabled: boolean; reason: string; override?: string };
const base = (tools: Tool[]): Record<string, unknown> => ({
  portal: 'mcp',
  server: 'coolify',
  default_disabled: true,
  tools,
});
const good = (): Tool[] => [
  { name: 'get_version', enabled: true, reason: 'r' },
  { name: 'logs', enabled: true, reason: 'r' },
  { name: 'deploy', enabled: false, reason: 'r' },
];
const edit = (name: string, patch: Partial<Tool>): Tool[] =>
  good().map((t) => (t.name === name ? { ...t, ...patch } : t));

describe('check-portal-allowlist findProblems', () => {
  it('accepts an allowlist in step with the roster and annotations', () => {
    expect(findProblems(base(good()), ROSTER, readOnlyOf)).toEqual([]);
  });

  it('refuses a tool that writes being enabled, even with an override', () => {
    expect(findProblems(base(edit('deploy', { enabled: true })), ROSTER, readOnlyOf)).toEqual([
      expect.stringContaining('deploy: enabled, but readOnlyHint is not true'),
    ]);
    const withOverride = edit('deploy', { enabled: true, override: 'sensitive-read' });
    expect(findProblems(base(withOverride), ROSTER, readOnlyOf).join('\n')).toContain(
      'deploy: enabled, but readOnlyHint is not true',
    );
  });

  it('refuses a disabled read-only tool unless it carries the override', () => {
    expect(findProblems(base(edit('logs', { enabled: false })), ROSTER, readOnlyOf)).toEqual([
      expect.stringContaining('logs: a read-only tool is disabled'),
    ]);
    const overridden = edit('logs', { enabled: false, override: 'sensitive-read' });
    expect(findProblems(base(overridden), ROSTER, readOnlyOf)).toEqual([]);
  });

  it('refuses an override where it does not apply, and an unknown one', () => {
    expect(
      findProblems(base(edit('logs', { override: 'sensitive-read' })), ROSTER, readOnlyOf),
    ).toEqual([expect.stringContaining('logs: an override only applies')]);
    expect(
      findProblems(base(edit('logs', { enabled: false, override: 'nope' })), ROSTER, readOnlyOf),
    ).toEqual([expect.stringContaining('logs: unknown override "nope"')]);
  });

  it('refuses omissions, strays and duplicates', () => {
    const tools = good().filter((t) => t.name !== 'logs');
    tools.push({ name: 'get_version', enabled: true, reason: 'r' });
    tools.push({ name: 'ghost', enabled: false, reason: 'r' });
    const problems = findProblems(base(tools), ROSTER, readOnlyOf).join('\n');
    expect(problems).toContain('get_version: listed twice');
    expect(problems).toContain('logs: in the roster but has no decision here');
    expect(problems).toContain('ghost: listed here but not in the roster');
  });

  it('reports a missing snapshot and an empty reason instead of throwing', () => {
    const problems = findProblems(base(edit('logs', { reason: ' ' })), ROSTER, (n) =>
      n === 'deploy' ? undefined : readOnlyOf(n),
    ).join('\n');
    expect(problems).toContain('logs: no reason');
    expect(problems).toContain('deploy: no tool snapshot');
  });

  it('refuses the wrong portal, server or default, and a non-array tools', () => {
    const problems = findProblems(
      { portal: 'x', server: 'tg', default_disabled: false, tools: {} },
      ROSTER,
      readOnlyOf,
    );
    expect(problems).toEqual([
      'portal is "x", expected "mcp"',
      'server is "tg", expected "coolify"',
      'default_disabled must be true',
      'tools must be an array',
    ]);
  });

  it('holds for the committed file', () => {
    const snaps = path.join(ROOT, 'evals/src/contract/__toolsnaps__');
    const roster = JSON.parse(fs.readFileSync(path.join(snaps, '_roster.json'), 'utf8'));
    const allowlist = JSON.parse(
      fs.readFileSync(path.join(ROOT, 'docs/portal-allowlist.json'), 'utf8'),
    );
    const fromSnapshot = (name: string): boolean | undefined => {
      const file = path.join(snaps, `${name}.json`);
      if (!fs.existsSync(file)) return undefined;
      return JSON.parse(fs.readFileSync(file, 'utf8')).annotations?.readOnlyHint === true;
    };
    expect(findProblems(allowlist, roster, fromSnapshot)).toEqual([]);
  });
});
