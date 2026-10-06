import { describe, it, expect } from '@jest/globals';
import { ALLOWED, evaluateAudit, main } from '../check-audit.mjs';

const advisory = (ghsa: string, severity = 'high', title = 'something bad') => ({
  source: 1,
  title,
  url: `https://github.com/advisories/${ghsa}`,
  severity,
});

const report = (vulnerabilities: Record<string, unknown>) => ({
  auditReportVersion: 2,
  vulnerabilities,
  metadata: {},
});

const BRACES = 'GHSA-vfj7-8cjw-p6xm';
const OTHER = 'GHSA-6qxp-vccf-f47h';

// The shape `npm audit --json` prints for this repository: the braces advisory
// and the chain of dev tools that depend on it.
const bracesChain = {
  braces: { severity: 'high', via: [advisory(BRACES)] },
  micromatch: { severity: 'high', via: ['braces'] },
  'fast-glob': { severity: 'high', via: ['micromatch'] },
  shx: { severity: 'high', via: ['shelljs'] },
};

const silent = () => {
  const lines: string[] = [];
  const push = (m: string) => void lines.push(m);
  return { lines, log: { log: push, warn: push, error: push } };
};

describe('evaluateAudit', () => {
  it('passes a clean report', () => {
    expect(evaluateAudit(report({}), { allowed: {} })).toEqual({ blocking: [], unused: [] });
  });

  it('passes the allowed advisory and everything that only depends on it', () => {
    expect(evaluateAudit(report(bracesChain)).blocking).toEqual([]);
  });

  it('allows exactly the braces advisory by default', () => {
    expect(Object.keys(ALLOWED)).toEqual([BRACES]);
  });

  it('blocks a high advisory that is not allowed, dev dependency or not', () => {
    const { blocking } = evaluateAudit(
      report({ ...bracesChain, '@modelcontextprotocol/client': { via: [advisory(OTHER)] } }),
    );
    expect(blocking).toEqual([
      expect.objectContaining({ id: OTHER, package: '@modelcontextprotocol/client' }),
    ]);
  });

  it('blocks a second advisory on the allowed package', () => {
    const { blocking } = evaluateAudit(
      report({ braces: { via: [advisory(BRACES), advisory(OTHER, 'critical')] } }),
    );
    expect(blocking.map((b) => b.id)).toEqual([OTHER]);
  });

  it('does not block below the threshold', () => {
    const r = report({ katex: { via: [advisory(OTHER, 'moderate')] } });
    expect(evaluateAudit(r, { allowed: {} }).blocking).toEqual([]);
  });

  it('blocks an advisory with no GHSA id rather than matching it to the allowlist', () => {
    const r = report({ x: { via: [{ source: 7, title: 'malware', severity: 'critical' }] } });
    expect(evaluateAudit(r).blocking).toEqual([
      expect.objectContaining({ id: null, package: 'x' }),
    ]);
  });

  it('names an allowed advisory that is no longer reported', () => {
    expect(evaluateAudit(report({})).unused).toEqual([BRACES]);
    expect(evaluateAudit(report(bracesChain)).unused).toEqual([]);
  });

  it.each([
    ['null', null],
    ['an array', []],
    // Each of these two is otherwise a well-formed clean report, so only its
    // own guard can refuse it.
    [
      'an npm error',
      { ...report({}), error: { code: 'ENOTFOUND', summary: 'registry unreachable' } },
    ],
    ['another report version', { ...report({}), auditReportVersion: 3 }],
    ['no vulnerabilities map', { auditReportVersion: 2 }],
    ['an entry without via', report({ braces: { severity: 'high' } })],
    ['an unknown severity', report({ braces: { via: [advisory(OTHER, 'severe')] } })],
  ])('refuses %s instead of reading it as clean', (_name, input) => {
    expect(() => evaluateAudit(input)).toThrow();
  });
});

describe('main', () => {
  it('exits 0 when only the allowed advisory is present', async () => {
    const { log } = silent();
    expect(await main({ audit: async () => report(bracesChain), log })).toBe(0);
  });

  it('exits 1 and names the advisory when another one is present', async () => {
    const { log, lines } = silent();
    const audit = async () => report({ ...bracesChain, pkg: { via: [advisory(OTHER)] } });
    expect(await main({ audit, log })).toBe(1);
    expect(lines.join('\n')).toContain(OTHER);
  });

  it('exits 2 when the audit cannot be run', async () => {
    const { log } = silent();
    const audit = async () => {
      throw new Error('spawn npm ENOENT');
    };
    expect(await main({ audit, log })).toBe(2);
  });

  it('exits 2 when the report is unreadable', async () => {
    const { log } = silent();
    expect(await main({ audit: async () => ({ error: { code: 'E500' } }), log })).toBe(2);
  });

  it('warns, without failing, when an allowed advisory is gone', async () => {
    const { log, lines } = silent();
    expect(await main({ audit: async () => report({}), log })).toBe(0);
    expect(lines.join('\n')).toMatch(/::warning.*GHSA-vfj7-8cjw-p6xm is allowed but no longer/);
  });
});
