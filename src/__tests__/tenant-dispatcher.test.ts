import { jest } from '@jest/globals';
import { pinnedDispatcherFor, UnsafeUrlError } from '../lib/tenant-dispatcher.js';
import type { Resolver } from '../lib/ssrf.js';

describe('pinnedDispatcherFor', () => {
  it('produces a dispatcher for a URL that resolves publicly', async () => {
    const resolver: Resolver = async () => [{ address: '203.0.113.10', family: 4 }];
    const dispatcher = await pinnedDispatcherFor('https://coolify.example.com', { resolver });
    expect(dispatcher).toBeDefined();
    // Duck-typed: an undici Dispatcher is usable wherever fetch() wants one,
    // which is the only property this module's caller relies on.
    expect(typeof (dispatcher as { close?: unknown }).close).toBe('function');
  });

  it('refuses a private literal address before any DNS lookup', async () => {
    const resolver = jest.fn<Resolver>();
    await expect(pinnedDispatcherFor('http://10.240.26.111:8000', { resolver })).rejects.toThrow(
      UnsafeUrlError,
    );
    // https-only and no-private-literal are check 1 (the URL as written);
    // failing there must not spend a DNS lookup on check 2.
    expect(resolver).not.toHaveBeenCalled();
  });

  it('refuses a hostname that resolves to a private address', async () => {
    const resolver: Resolver = async () => [{ address: '169.254.169.254', family: 4 }];
    await expect(
      pinnedDispatcherFor('https://looks-public.example.com', { resolver }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('refuses plain http, since a tenant token must not cross the network in clear', async () => {
    const resolver: Resolver = async () => [{ address: '203.0.113.10', family: 4 }];
    await expect(pinnedDispatcherFor('http://coolify.example.com', { resolver })).rejects.toThrow(
      UnsafeUrlError,
    );
  });
});
