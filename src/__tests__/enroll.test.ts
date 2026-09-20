import { jest } from '@jest/globals';
import { isValidInstanceName, normalizeBaseUrl, probeCoolify } from '../lib/enroll.js';
import { UnsafeUrlError } from '../lib/ssrf.js';
import type { Resolver } from '../lib/ssrf.js';

describe('isValidInstanceName', () => {
  it('accepts lowercase letters, digits and hyphens, up to 31 characters', () => {
    expect(isValidInstanceName('default')).toBe(true);
    expect(isValidInstanceName('prod-eu-1')).toBe(true);
    expect(isValidInstanceName('a'.repeat(31))).toBe(true);
  });

  it('refuses anything that would be awkward as a path segment or tool argument', () => {
    expect(isValidInstanceName('')).toBe(false);
    expect(isValidInstanceName('Default')).toBe(false);
    expect(isValidInstanceName('has space')).toBe(false);
    expect(isValidInstanceName('has_underscore')).toBe(false);
    expect(isValidInstanceName('-leading-hyphen')).toBe(false);
    expect(isValidInstanceName('a'.repeat(32))).toBe(false);
  });
});

describe('normalizeBaseUrl', () => {
  it('drops a trailing slash, query and fragment, keeping the origin and path', () => {
    expect(normalizeBaseUrl(new URL('https://coolify.example.com/'))).toBe(
      'https://coolify.example.com',
    );
    expect(normalizeBaseUrl(new URL('https://coolify.example.com/app/'))).toBe(
      'https://coolify.example.com/app',
    );
    expect(normalizeBaseUrl(new URL('https://coolify.example.com/?x=1#y'))).toBe(
      'https://coolify.example.com',
    );
  });
});

describe('probeCoolify: SSRF refusals happen before any socket opens', () => {
  it('refuses a literal private or loopback address without a DNS lookup', async () => {
    const resolver = jest.fn<Resolver>();
    const result = await probeCoolify('http://10.240.26.111:8000', 'tok', { resolver });
    expect(result).toEqual({ ok: false, reason: expect.stringContaining('cannot be reached') });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('refuses plain http, since a tenant token must not cross the network in clear', async () => {
    const result = await probeCoolify('http://coolify.example.com', 'tok');
    expect(result).toEqual({ ok: false, reason: expect.stringContaining('cannot be reached') });
  });

  it('refuses an address that is not a URL at all, without throwing', async () => {
    const result = await probeCoolify('not a url', 'tok');
    expect(result.ok).toBe(false);
  });

  it('refuses a hostname that resolves to a private address — the rebinding-adjacent case', async () => {
    // This is the enrolment-time twin of the request-time check in
    // tenancy.test.ts: a domain that resolves privately must never reach the
    // probe request, exactly as a later rebind must never reach a tool call.
    const resolver: Resolver = async () => [{ address: '10.0.0.5', family: 4 }];
    const result = await probeCoolify('https://looks-public.example.com', 'tok', { resolver });
    expect(result).toEqual({ ok: false, reason: expect.stringContaining('cannot be reached') });
  });

  it('surfaces a resolution failure as a reason a tenant can act on', async () => {
    const resolver: Resolver = async () => {
      throw new UnsafeUrlError('nx.example did not resolve');
    };
    const result = await probeCoolify('https://nx.example', 'tok', { resolver });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('cannot be reached');
  });
});
