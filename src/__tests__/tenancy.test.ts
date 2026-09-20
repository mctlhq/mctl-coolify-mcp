import { jest } from '@jest/globals';
import {
  MemoryTenantStore,
  NotEnrolledError,
  UnsafeInstanceError,
  VaultTenantStore,
  registryForCaller,
  subjectFromAuthInfo,
  tenantKey,
  type TenantRecord,
} from '../lib/tenancy.js';
import type { VerifiedIdentity } from '../lib/identity.js';
import type { VaultClient } from '../lib/vault.js';
import type { Resolver } from '../lib/ssrf.js';

/** A DNS answer that resolves every hostname to a fixed public address. */
function fakeResolver(address = '203.0.113.10'): Resolver {
  return async () => [{ address, family: 4 as const }];
}

const alice: VerifiedIdentity = { provider: 'github', sub: '1001', login: 'alice' };
const bob: VerifiedIdentity = { provider: 'github', sub: '2002', login: 'bob' };

function record(name: string, baseUrl: string, accessToken: string): TenantRecord {
  return { instances: [{ name, baseUrl, accessToken }], updatedAt: Date.now() };
}

describe('record keys', () => {
  it('hashes the subject rather than putting it in the path', () => {
    const key = tenantKey(alice);
    expect(key).toMatch(/^users\/[0-9a-f]{64}$/);
    expect(key).not.toContain('1001');
  });

  it('is stable for one subject and distinct between subjects', () => {
    expect(tenantKey(alice)).toBe(tenantKey({ provider: 'github', sub: '1001' }));
    expect(tenantKey(alice)).not.toBe(tenantKey(bob));
  });
});

describe('tenant isolation', () => {
  it('builds a registry from the caller record alone', async () => {
    const store = new MemoryTenantStore();
    await store.write(alice, record('default', 'https://alice.coolify.test', 'alice-token'));
    await store.write(bob, record('default', 'https://bob.coolify.test', 'bob-token'));

    const aliceRegistry = await registryForCaller(store, alice, { resolver: fakeResolver() });
    expect(aliceRegistry.all).toHaveLength(1);
    expect(aliceRegistry.default.baseUrl).toBe('https://alice.coolify.test');
    expect(aliceRegistry.default.accessToken).toBe('alice-token');

    // The property the whole design exists for: nothing of Bob's is reachable
    // from Alice's registry, including through the fleet fan-out.
    expect(JSON.stringify(aliceRegistry.all)).not.toContain('bob');
    expect(aliceRegistry.names).toEqual(['default']);
  });

  it('refuses to serve a caller who has enrolled nothing', async () => {
    const store = new MemoryTenantStore();
    await expect(registryForCaller(store, alice, { resolver: fakeResolver() })).rejects.toThrow(
      NotEnrolledError,
    );
  });

  it('treats an emptied record as not enrolled rather than as a fleet of none', async () => {
    const store = new MemoryTenantStore();
    await store.write(alice, { instances: [], updatedAt: Date.now() });
    await expect(registryForCaller(store, alice, { resolver: fakeResolver() })).rejects.toThrow(
      NotEnrolledError,
    );
  });

  it('stops serving immediately after a revocation', async () => {
    const store = new MemoryTenantStore();
    await store.write(alice, record('default', 'https://alice.coolify.test', 'alice-token'));
    await expect(
      registryForCaller(store, alice, { resolver: fakeResolver() }),
    ).resolves.toBeDefined();
    await store.revoke(alice);
    await expect(registryForCaller(store, alice, { resolver: fakeResolver() })).rejects.toThrow(
      NotEnrolledError,
    );
  });
});

describe('SSRF re-validation at request time', () => {
  it('re-resolves and pins the address on every call, not just at enrolment', async () => {
    const store = new MemoryTenantStore();
    await store.write(alice, record('default', 'https://alice.coolify.test', 'alice-token'));
    const resolver = jest.fn(fakeResolver());
    await registryForCaller(store, alice, { resolver });
    await registryForCaller(store, alice, { resolver });
    // Once per request, not cached across calls — a cached resolution would
    // be exactly the rebinding window this exists to close.
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it('refuses an instance whose stored address now resolves privately, and names it', async () => {
    // The scenario this guards against: DNS for an enrolled domain has been
    // repointed since enrolment, now landing inside the cluster's network.
    const store = new MemoryTenantStore();
    await store.write(alice, record('rebound', 'https://rebound.example.com', 'alice-token'));
    const resolver: Resolver = async () => [{ address: '10.0.0.5', family: 4 }];
    await expect(registryForCaller(store, alice, { resolver })).rejects.toThrow(
      UnsafeInstanceError,
    );
    await expect(registryForCaller(store, alice, { resolver })).rejects.toThrow(/rebound/);
  });

  it('refuses a literal private or loopback address given directly', async () => {
    const store = new MemoryTenantStore();
    await store.write(alice, record('default', 'http://10.255.0.101:8000', 'alice-token'));
    await expect(registryForCaller(store, alice)).rejects.toThrow(UnsafeInstanceError);
  });
});

describe('the Vault-backed store', () => {
  function fakeVault(read: unknown) {
    return {
      read: jest.fn(async () => read as Record<string, unknown> | undefined),
      write: jest.fn(async () => undefined),
      destroy: jest.fn(async () => undefined),
    } as unknown as VaultClient;
  }

  it('reads a record back through the JSON field', async () => {
    const stored = record('prod', 'https://coolify.test', 'tok');
    const vault = fakeVault({ instances_json: JSON.stringify(stored) });
    await expect(new VaultTenantStore(vault).read(alice)).resolves.toEqual(stored);
  });

  it('reads the empty value a revocation leaves behind as "no tenant"', async () => {
    // Revocation overwrites with an empty record before destroying versions;
    // a reader in that window must see absence, not a parse failure.
    await expect(
      new VaultTenantStore(fakeVault({ instances_json: '' })).read(alice),
    ).resolves.toBeUndefined();
    await expect(new VaultTenantStore(fakeVault({})).read(alice)).resolves.toBeUndefined();
    await expect(new VaultTenantStore(fakeVault(undefined)).read(alice)).resolves.toBeUndefined();
  });

  it('surfaces corrupt stored JSON instead of silently serving nothing', async () => {
    const vault = fakeVault({ instances_json: '{not json' });
    await expect(new VaultTenantStore(vault).read(alice)).rejects.toThrow(/not readable JSON/);
  });

  it('revokes by destroying, at the hashed key', async () => {
    const vault = fakeVault(undefined);
    await new VaultTenantStore(vault).revoke(alice);
    expect(vault.destroy).toHaveBeenCalledWith(tenantKey(alice));
  });
});

describe('subject from the verified token', () => {
  it('accepts a well-formed bag', () => {
    expect(subjectFromAuthInfo({ provider: 'github', sub: '1001' })).toEqual({
      provider: 'github',
      sub: '1001',
    });
  });

  it('accepts google, the second identity provider', () => {
    expect(subjectFromAuthInfo({ provider: 'google', sub: '1001' })).toEqual({
      provider: 'google',
      sub: '1001',
    });
  });

  it('refuses anything else rather than guessing which tenant was meant', () => {
    // A token minted before subject binding, or by another provider, must not
    // be resolved to a tenant by inference — that is how two tenants cross.
    expect(subjectFromAuthInfo(undefined)).toBeUndefined();
    expect(subjectFromAuthInfo({})).toBeUndefined();
    expect(subjectFromAuthInfo({ sub: '1001' })).toBeUndefined();
    expect(subjectFromAuthInfo({ provider: 'gitlab', sub: '1001' })).toBeUndefined();
    expect(subjectFromAuthInfo({ provider: 'github', sub: 1001 })).toBeUndefined();
  });
});
