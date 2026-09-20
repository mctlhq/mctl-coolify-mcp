import { jest } from '@jest/globals';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StateFileVaultSync, hydrateStateFile } from '../lib/oauth-state-vault.js';
import type { VaultClient } from '../lib/vault.js';

function fakeVault(initial?: Record<string, unknown>): {
  vault: VaultClient;
  reads: number;
  writes: Array<Record<string, unknown>>;
} {
  let stored = initial;
  const writes: Array<Record<string, unknown>> = [];
  let reads = 0;
  const vault = {
    read: jest.fn(async () => {
      reads += 1;
      return stored;
    }),
    write: jest.fn(async (_key: string, data: Record<string, unknown>) => {
      stored = data;
      writes.push(data);
    }),
    destroy: jest.fn(async () => undefined),
  } as unknown as VaultClient;
  return {
    vault,
    get reads() {
      return reads;
    },
    writes,
  };
}

describe('hydrateStateFile', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oauth-state-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('does nothing on first boot, when Vault has no record yet', async () => {
    const { vault } = fakeVault(undefined);
    const stateFile = join(dir, 'state.json');
    await hydrateStateFile(vault, stateFile);
    expect(() => readFileSync(stateFile)).toThrow(/ENOENT/);
  });

  it('writes the stored state to the file, creating its directory', async () => {
    const { vault } = fakeVault({ state_json: '{"clients":[],"codes":[],"tokens":[]}' });
    const stateFile = join(dir, 'nested', 'state.json');
    await hydrateStateFile(vault, stateFile);
    expect(readFileSync(stateFile, 'utf8')).toBe('{"clients":[],"codes":[],"tokens":[]}');
    expect(statSync(stateFile).mode & 0o777).toBe(0o600);
  });

  it('treats a present but empty value as nothing to restore', async () => {
    const { vault } = fakeVault({ state_json: '' });
    const stateFile = join(dir, 'state.json');
    await hydrateStateFile(vault, stateFile);
    expect(() => readFileSync(stateFile)).toThrow(/ENOENT/);
  });
});

describe('StateFileVaultSync', () => {
  let dir: string;
  let stateFile: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oauth-state-'));
    stateFile = join(dir, 'state.json');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('mirrors the file to Vault on flush', async () => {
    const { vault, writes } = fakeVault();
    const { writeFile } = await import('node:fs/promises');
    await writeFile(stateFile, '{"clients":[{"client_id":"a"}]}');

    const sync = new StateFileVaultSync(vault, stateFile);
    await sync.flush();

    expect(writes).toEqual([{ state_json: '{"clients":[{"client_id":"a"}]}' }]);
  });

  it('does not write again when the file has not changed since the last sync', async () => {
    const { vault, writes } = fakeVault();
    const { writeFile } = await import('node:fs/promises');
    await writeFile(stateFile, '{"clients":[]}');

    const sync = new StateFileVaultSync(vault, stateFile);
    await sync.flush();
    await sync.flush();

    expect(writes).toHaveLength(1);
  });

  it('picks up a later change on the next flush', async () => {
    const { vault, writes } = fakeVault();
    const { writeFile } = await import('node:fs/promises');
    await writeFile(stateFile, '{"clients":[]}');

    const sync = new StateFileVaultSync(vault, stateFile);
    await sync.flush();

    // A distinct mtime is what "changed" is keyed on; some filesystems have
    // second-granularity mtimes, so nudge the clock forward for the write.
    await new Promise((resolve) => setTimeout(resolve, 20));
    await writeFile(stateFile, '{"clients":[{"client_id":"b"}]}');
    await sync.flush();

    expect(writes).toHaveLength(2);
    expect(writes[1]).toEqual({ state_json: '{"clients":[{"client_id":"b"}]}' });
  });

  it('does nothing when the file does not exist yet', async () => {
    const { vault, writes } = fakeVault();
    const sync = new StateFileVaultSync(vault, join(dir, 'never-written.json'));
    await sync.flush();
    expect(writes).toHaveLength(0);
  });

  it('logs and keeps serving rather than throwing when Vault is unreachable', async () => {
    const { writeFile } = await import('node:fs/promises');
    await writeFile(stateFile, '{"clients":[]}');
    const vault = {
      read: jest.fn(),
      write: jest.fn(async () => {
        throw new Error('ECONNREFUSED');
      }),
      destroy: jest.fn(),
    } as unknown as VaultClient;
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const sync = new StateFileVaultSync(vault, stateFile);
    await expect(sync.flush()).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('could not sync to Vault'));
    errorSpy.mockRestore();
  });

  it('stop() clears the interval so the process can exit', () => {
    const { vault } = fakeVault();
    const sync = new StateFileVaultSync(vault, stateFile);
    sync.start();
    expect(() => sync.stop()).not.toThrow();
  });
});

describe('the restart-survival property end to end', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oauth-state-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('a value written by one "process" is restored by hydrateStateFile for the next', async () => {
    const { vault, writes } = fakeVault();
    const stateFile1 = join(dir, 'state.json');
    const { writeFile } = await import('node:fs/promises');
    await writeFile(
      stateFile1,
      '{"clients":[{"client_id":"mcp_client_abc","redirect_uris":[]}],"codes":[],"tokens":[]}',
    );
    await new StateFileVaultSync(vault, stateFile1).flush();
    expect(writes).toHaveLength(1);

    // "Restart": a fresh, empty state file at a fresh path, as multi-tenant
    // mode's /tmp default would be after a pod restart.
    const stateFile2 = join(dir, 'after-restart', 'state.json');
    await hydrateStateFile(vault, stateFile2);
    expect(JSON.parse(readFileSync(stateFile2, 'utf8'))).toMatchObject({
      clients: [{ client_id: 'mcp_client_abc' }],
    });
  });
});
