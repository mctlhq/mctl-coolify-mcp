import { describe, it, expect } from '@jest/globals';
import { ALLOWED, evaluateAudit, main, runNpmAudit } from '../check-audit.mjs';

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

// An allowlist with one entry, the shape ALLOWED had while the braces advisory
// (withdrawn by GitHub on 2026-10-23) was still reported.
const allowBraces = { [BRACES]: 'braces: no fixed release exists' };

// The shape `npm audit --json` printed for this repository while the braces
// advisory was live: that advisory and the chain of dev tools depending on it.
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
    expect(evaluateAudit(report(bracesChain), { allowed: allowBraces }).blocking).toEqual([]);
  });

  it('allows nothing by default', () => {
    expect(Object.keys(ALLOWED)).toEqual([]);
  });

  it('blocks the braces chain once nothing is allowed', () => {
    expect(evaluateAudit(report(bracesChain)).blocking).toEqual([
      expect.objectContaining({ id: BRACES, package: 'braces' }),
    ]);
  });

  it('blocks a high advisory that is not allowed, dev dependency or not', () => {
    const { blocking } = evaluateAudit(
      report({ ...bracesChain, '@modelcontextprotocol/client': { via: [advisory(OTHER)] } }),
      { allowed: allowBraces },
    );
    expect(blocking).toEqual([
      expect.objectContaining({ id: OTHER, package: '@modelcontextprotocol/client' }),
    ]);
  });

  it('blocks a second advisory on the allowed package', () => {
    const { blocking } = evaluateAudit(
      report({ braces: { via: [advisory(BRACES), advisory(OTHER, 'critical')] } }),
      { allowed: allowBraces },
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
    expect(evaluateAudit(report({}), { allowed: allowBraces }).unused).toEqual([BRACES]);
    expect(evaluateAudit(report(bracesChain), { allowed: allowBraces }).unused).toEqual([]);
  });

  it('names an allowed advisory that dropped below the threshold', () => {
    const r = report({ braces: { via: [advisory(BRACES, 'moderate')] } });
    expect(evaluateAudit(r, { allowed: allowBraces })).toEqual({ blocking: [], unused: [BRACES] });
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
    expect(await main({ audit: async () => report(bracesChain), log, allowed: allowBraces })).toBe(
      0,
    );
  });

  it('exits 1 and names the advisory when another one is present', async () => {
    const { log, lines } = silent();
    const audit = async () => report({ ...bracesChain, pkg: { via: [advisory(OTHER)] } });
    expect(await main({ audit, log, allowed: allowBraces })).toBe(1);
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

  it('describes an npm error that has neither summary nor code', async () => {
    const { log, lines } = silent();
    expect(await main({ audit: async () => ({ error: { detail: 'boom' } }), log })).toBe(2);
    expect(lines.join('\n')).toContain('"detail":"boom"');
  });

  it('warns, without failing, when an allowed advisory is gone', async () => {
    const { log, lines } = silent();
    expect(await main({ audit: async () => report({}), log, allowed: allowBraces })).toBe(0);
    expect(lines.join('\n')).toMatch(/::warning.*GHSA-vfj7-8cjw-p6xm is allowed but no longer/);
  });
});

// The real runner, pointed at `node` standing in for `npm`.
describe('runNpmAudit', () => {
  const node = (script: string) => runNpmAudit(process.execPath, ['-e', script]);

  it('reads the report even though a report with findings exits 1', async () => {
    const script = `console.log(JSON.stringify({ auditReportVersion: 2 })); process.exit(1)`;
    await expect(node(script)).resolves.toEqual({ auditReportVersion: 2 });
  });

  it.each([
    ['output that is not JSON', `console.log('npm error code ENOTFOUND'); process.exit(1)`],
    ['a truncated report', `console.log('{"auditReportVersion": 2, "vulnera')`],
    ['no output at all', `process.exit(0)`],
  ])('rejects %s', async (_name, script) => {
    await expect(node(script)).rejects.toThrow(/did not print JSON/);
  });

  it('rejects an audit that runs past the timeout', async () => {
    const hang = runNpmAudit(process.execPath, ['-e', 'setTimeout(() => {}, 60_000)'], 500);
    await expect(hang).rejects.toThrow();
  }, 10_000);

  it('rejects when the command cannot be started', async () => {
    await expect(runNpmAudit('/nonexistent/npm', [])).rejects.toThrow();
  });

  it('makes the gate exit 2 on unparseable output', async () => {
    const { log, lines } = silent();
    expect(await main({ audit: () => node(`console.log('<html>502</html>')`), log })).toBe(2);
    expect(lines.join('\n')).toContain('could not read the audit');
  });
});
