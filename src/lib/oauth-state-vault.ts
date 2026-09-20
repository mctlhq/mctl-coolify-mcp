/**
 * Makes the OAuth state file survive a restart without a volume.
 *
 * ## Why this exists, and why it does not touch oauth.ts
 *
 * `OAuthProvider` reads and writes `stateFile` synchronously — a
 * `readFileSync` in its constructor, a debounced `writeFileSync` after every
 * registration or issued token. That is the right shape for a single
 * container with a mounted volume, which is what upstream is: `/data` is a
 * PersistentVolumeClaim, and the file survives a redeploy because the volume
 * does.
 *
 * Multi-tenant mode already needs a Vault client for tenant records, and
 * `registryForCaller` already established the pattern of treating Vault as
 * the durable store rather than provisioning another volume for one more
 * kilobyte-sized JSON blob (see tenancy.ts's note on why OAuth state lives
 * there too). Rather than teach `OAuthProvider` a second, async-shaped
 * persistence backend — which would mean either an async constructor
 * (rippling through every call site and the ~100 places `oauth.test.ts`
 * constructs one directly) or a load-after-boot race where a client that
 * registers in the first instant after a restart is told it does not exist —
 * this wraps the existing, synchronous, thoroughly-tested file mechanism
 * unchanged: hydrate the file from Vault just before `OAuthProvider` reads
 * it, then mirror the file back to Vault whenever it changes.
 *
 * The file itself lives under the container's own writable layer (`/tmp` by
 * default), not a mounted volume — ephemeral, gone on restart, which is
 * exactly why hydrating it first matters.
 *
 * ## What "when it changes" means without a hook into oauth.ts
 *
 * There is no seam to be called back from `writeState()` without editing it,
 * so this polls the file's mtime — the same idiom `token-source.ts` already
 * uses for its own restart-without-losing-rotation problem, at a matching
 * order of magnitude to the 250ms debounce the file write itself already
 * uses. A push that raced a concurrent write picks up the version on disk at
 * the next tick, a few seconds later; the state file is never the source of
 * truth for an in-flight request either way, since `OAuthProvider` answers
 * every request from its in-memory maps.
 */
import { readFile, stat, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { VaultClient } from './vault.js';

const VAULT_KEY = 'oauth-state';
const VAULT_FIELD = 'state_json';

/** Poll interval for picking up a local write and mirroring it to Vault. */
const SYNC_INTERVAL_MS = 3000;

/**
 * Restore the state file from Vault before `OAuthProvider` is constructed.
 *
 * A missing Vault record is first boot, not an error: `OAuthProvider.load()`
 * already treats a missing file exactly that way, so doing nothing here is
 * correct, not a fallback.
 */
export async function hydrateStateFile(vault: VaultClient, stateFile: string): Promise<void> {
  const record = await vault.read(VAULT_KEY);
  const raw = record?.[VAULT_FIELD];
  if (typeof raw !== 'string' || raw === '') return;
  await mkdir(dirname(stateFile), { recursive: true, mode: 0o700 });
  await writeFile(stateFile, raw, { mode: 0o600 });
}

/**
 * Mirrors a local state file to Vault whenever it changes, for as long as
 * {@link start} has been called and {@link stop} has not.
 */
export class StateFileVaultSync {
  private timer?: NodeJS.Timeout;
  private lastMtimeMs = 0;
  private syncing = false;

  constructor(
    private readonly vault: VaultClient,
    private readonly stateFile: string,
  ) {}

  start(): void {
    this.timer = setInterval(() => {
      void this.syncIfChanged();
    }, SYNC_INTERVAL_MS);
    // A poller with nothing left to poll for should not be why the process
    // does not exit — the same reasoning oauth.ts's own persist timer uses.
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Force one pass now, regardless of the poll interval — the shutdown hook. */
  async flush(): Promise<void> {
    await this.syncIfChanged();
  }

  private async syncIfChanged(): Promise<void> {
    // Never run two passes concurrently: a slow Vault write and the next
    // tick's stat() must not race to decide what "changed" means.
    if (this.syncing) return;
    this.syncing = true;
    try {
      const stats = await stat(this.stateFile).catch(() => undefined);
      if (!stats || stats.mtimeMs === this.lastMtimeMs) return;
      const content = await readFile(this.stateFile, 'utf8').catch(() => undefined);
      if (content === undefined) return;
      await this.vault.write(VAULT_KEY, { [VAULT_FIELD]: content });
      this.lastMtimeMs = stats.mtimeMs;
    } catch (error) {
      // Same posture as oauth.ts's own writeState(): a failed sync loses
      // nothing the server is currently using — the in-memory maps and the
      // local file are unaffected — only survival across the *next* restart
      // if Vault stays unreachable until then.
      console.error(
        `oauth-state: could not sync to Vault; local state still authoritative. ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      this.syncing = false;
    }
  }
}
