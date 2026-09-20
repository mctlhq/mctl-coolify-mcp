import { jest } from '@jest/globals';
import { VaultClient, VaultError, vaultFromEnv } from '../lib/vault.js';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function recorder(
  handlers: Array<(call: Call) => { status?: number; body?: unknown } | undefined>,
) {
  const calls: Call[] = [];
  const fetchMock = jest.fn(async (url: unknown, init: unknown) => {
    const request = init as { method?: string; headers?: Record<string, string>; body?: string };
    const call: Call = {
      url: String(url),
      method: request?.method ?? 'GET',
      headers: request?.headers ?? {},
      body: request?.body,
    };
    calls.push(call);
    for (const handler of handlers) {
      const result = handler(call);
      if (result) {
        const status = result.status ?? 200;
        return {
          ok: status >= 200 && status < 300,
          status,
          json: async () => result.body ?? {},
          text: async () => JSON.stringify(result.body ?? {}),
        };
      }
    }
    return { ok: false, status: 500, json: async () => ({}), text: async () => 'unhandled' };
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  return calls;
}

const config = { address: 'https://vault.test', mount: 'coolify-mcp-users', token: 'root-token' };

afterEach(() => jest.restoreAllMocks());

describe('configuration', () => {
  it('is undefined until both the address and the mount are set', () => {
    expect(vaultFromEnv({})).toBeUndefined();
    expect(vaultFromEnv({ VAULT_ADDR: 'https://vault.test' })).toBeUndefined();
    expect(vaultFromEnv({ VAULT_ADDR: 'https://vault.test/', VAULT_KV_MOUNT: 'm' })).toMatchObject({
      address: 'https://vault.test',
      mount: 'm',
    });
  });
});

describe('reads and writes', () => {
  it('unwraps the KV v2 double envelope', async () => {
    recorder([
      (c) => (c.url.includes('/data/') ? { body: { data: { data: { k: 'v' } } } } : undefined),
    ]);
    await expect(new VaultClient(config).read('users/abc')).resolves.toEqual({ k: 'v' });
  });

  it('treats a missing record as absent, not as an error', async () => {
    recorder([() => ({ status: 404 })]);
    await expect(new VaultClient(config).read('users/none')).resolves.toBeUndefined();
  });

  it('sends the token as a header and wraps the payload for KV v2', async () => {
    const calls = recorder([() => ({ body: {} })]);
    await new VaultClient(config).write('users/abc', { instances_json: '[]' });
    const dataCall = calls.find((c) => c.url.includes('/data/'));
    expect(dataCall?.method).toBe('POST');
    expect(dataCall?.url).toBe('https://vault.test/v1/coolify-mcp-users/data/users/abc');
    expect(dataCall?.headers['x-vault-token']).toBe('root-token');
    expect(JSON.parse(dataCall?.body ?? '{}')).toEqual({ data: { instances_json: '[]' } });
  });

  it("sets this path's own max_versions on every write, since the mount default cannot be trusted", async () => {
    // Real-world reason this exists: the platform's actual Vault mount is
    // shared across every team and configured with max_versions: 0
    // (unlimited) — this client cannot assume otherwise.
    const calls = recorder([() => ({ body: {} })]);
    await new VaultClient(config).write('users/abc', { instances_json: '[]' });
    const metaCall = calls.find((c) => c.url.includes('/metadata/') && c.method === 'POST');
    expect(metaCall?.url).toBe('https://vault.test/v1/coolify-mcp-users/metadata/users/abc');
    expect(JSON.parse(metaCall?.body ?? '{}')).toEqual({ max_versions: 1 });
  });

  it('honors an explicit maxVersions instead of the default of 1', async () => {
    const calls = recorder([() => ({ body: {} })]);
    await new VaultClient({ ...config, maxVersions: 3 }).write('users/abc', {});
    const metaCall = calls.find((c) => c.url.includes('/metadata/') && c.method === 'POST');
    expect(JSON.parse(metaCall?.body ?? '{}')).toEqual({ max_versions: 3 });
  });

  it('reports an unreachable Vault as such rather than as a missing record', async () => {
    global.fetch = jest
      .fn<() => Promise<never>>()
      .mockRejectedValue(new Error('ECONNREFUSED')) as never;
    await expect(new VaultClient(config).read('users/abc')).rejects.toThrow(
      /Could not reach Vault/,
    );
  });
});

describe('revocation', () => {
  it('destroys every version and never uses delete, which only tombstones', async () => {
    const calls = recorder([
      (c) =>
        c.url.includes('/metadata/')
          ? { body: { data: { versions: { '1': {}, '2': {} } } } }
          : undefined,
      () => ({ body: {} }),
    ]);
    await new VaultClient(config).destroy('users/abc');

    // The trap this is built around: KV v2's `delete` hides the current
    // version and leaves earlier ones readable, so a revocation done with it
    // does not revoke.
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    expect(calls.some((c) => c.url.includes('/delete/'))).toBe(false);

    // Overwrite first, so a reader between the two calls sees nothing rather
    // than the old token.
    const overwrite = calls.find((c) => c.url.includes('/data/users/abc'));
    expect(JSON.parse(overwrite?.body ?? '{}')).toEqual({ data: {} });
    // And the overwrite must land before the metadata GET that decides what
    // to destroy, or a concurrent reader's window is exactly reversed.
    expect(calls.indexOf(overwrite!)).toBeLessThan(
      calls.findIndex((c) => c.url.includes('/metadata/') && c.method === 'GET'),
    );

    const destroy = calls.find((c) => c.url.includes('/destroy/'));
    expect(destroy).toBeDefined();
    expect(JSON.parse(destroy?.body ?? '{}')).toEqual({ versions: [1, 2] });
  });

  it('stops quietly when there is nothing left to destroy', async () => {
    const calls = recorder([
      // Only the metadata GET (destroy()'s "what versions exist" check) is
      // 404; the metadata POST write() makes to set max_versions must still
      // succeed, or the empty overwrite itself would fail.
      (c) => (c.url.includes('/metadata/') && c.method === 'GET' ? { status: 404 } : undefined),
      () => ({ body: {} }),
    ]);
    await new VaultClient(config).destroy('users/gone');
    expect(calls.some((c) => c.url.includes('/destroy/'))).toBe(false);
  });
});

describe('kubernetes auth', () => {
  const k8s = {
    address: 'https://vault.test',
    mount: 'm',
    role: 'coolify-mcp',
    authMount: 'kubernetes',
    serviceAccountTokenPath: '/nonexistent/sa-token',
  };

  it('says what to do when the service-account token is unreadable', async () => {
    recorder([() => ({ body: {} })]);
    await expect(new VaultClient(k8s).read('users/abc')).rejects.toThrow(/set VAULT_TOKEN/);
  });

  it('requires a role when there is no static token', async () => {
    recorder([() => ({ body: {} })]);
    await expect(
      new VaultClient({ address: 'https://vault.test', mount: 'm' }).read('users/abc'),
    ).rejects.toThrow(/VAULT_TOKEN or VAULT_ROLE/);
  });

  it('does not retry a 403 when the token is static, since re-login cannot help', async () => {
    const calls = recorder([() => ({ status: 403, body: { errors: ['permission denied'] } })]);
    await expect(new VaultClient(config).read('users/abc')).rejects.toThrow(VaultError);
    expect(calls).toHaveLength(1);
  });
});
