/**
 * Minimal Vault KV v2 client for the tenant store.
 *
 * ## Why hand-rolled
 *
 * We need four calls — log in, read, write, destroy — against an endpoint we
 * control. The official client pulls in a dependency tree far larger than that
 * for a server whose whole appeal is that it audits in an afternoon.
 *
 * ## Why not the External Secrets Operator
 *
 * ESO is how `projects-mcp` gets its grants, and it is the right tool there:
 * one operator-maintained file, mounted read-only. It cannot serve this server,
 * because enrolment is self-service — a tenant adds and revokes their own
 * record while the process runs, so there has to be a write path, and ESO
 * offers none.
 *
 * ## The deletion trap this is built around
 *
 * KV v2's `delete` is a tombstone: it hides the current version and leaves
 * every prior version readable. A revocation implemented with it does not
 * revoke. {@link VaultClient.destroy} therefore destroys versions outright, and
 * the mount is expected to carry `max_versions=1` so there is only ever one to
 * destroy.
 */
import { readFile } from 'node:fs/promises';

const FETCH_TIMEOUT_MS = 10_000;

/** Re-login this long before the lease actually ends, so no request races it. */
const RENEW_MARGIN_MS = 60_000;

const DEFAULT_K8S_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';

export class VaultError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

export interface VaultConfig {
  /** Base address, e.g. `https://vault.mctl.ai`. */
  address: string;
  /**
   * KV v2 mount holding tenant records. Not assumed to be dedicated to this
   * server or configured with any particular retention: {@link VaultConfig.maxVersions}
   * is what this client sets on its own paths regardless of what the mount's
   * default is. A shared, general-purpose mount (`secret/`, one per cluster)
   * is the common case, not an exception to plan for.
   */
  mount: string;
  /**
   * Every path this client writes gets its OWN `max_versions` set to this,
   * via KV v2's per-path metadata — not inherited from the mount. Vault's own
   * mount-wide default is unlimited (`max_versions: 0`) unless an operator
   * configured otherwise, and this client must not depend on that: a shared
   * mount serving many unrelated teams is not this server's to reconfigure.
   * Kept small on purpose — every version written before a revoke stays
   * readable to anyone with read access to the mount until that revoke
   * destroys it, so the fewer versions accumulate between writes, the
   * smaller that exposure. Default 1: a re-enrolled token immediately
   * supersedes, rather than joins, the one before it.
   */
  maxVersions?: number;
  /**
   * A static token. Development and tests only — in the cluster the token is
   * obtained by Kubernetes auth and rotated, which a static one never is.
   */
  token?: string;
  /** Kubernetes auth role. Required unless `token` is set. */
  role?: string;
  /** Path to the projected service-account token. */
  serviceAccountTokenPath?: string;
  /** Auth mount path, if it is not the default `kubernetes`. */
  authMount?: string;
}

export function vaultFromEnv(env: NodeJS.ProcessEnv): VaultConfig | undefined {
  const address = env.VAULT_ADDR?.trim();
  const mount = env.VAULT_KV_MOUNT?.trim();
  if (!address || !mount) return undefined;
  return {
    address: address.replace(/\/+$/, ''),
    mount,
    maxVersions: env.VAULT_MAX_VERSIONS ? Number(env.VAULT_MAX_VERSIONS) : undefined,
    token: env.VAULT_TOKEN?.trim() || undefined,
    role: env.VAULT_ROLE?.trim() || undefined,
    serviceAccountTokenPath: env.VAULT_K8S_TOKEN_PATH?.trim() || DEFAULT_K8S_TOKEN_PATH,
    authMount: env.VAULT_AUTH_MOUNT?.trim() || 'kubernetes',
  };
}

interface Lease {
  token: string;
  /** Epoch ms after which the token must not be used. Absent means no expiry. */
  expiresAt?: number;
}

export class VaultClient {
  private lease?: Lease;
  /** In-flight login, so a burst of requests logs in once rather than N times. */
  private pendingLogin?: Promise<Lease>;

  constructor(private readonly config: VaultConfig) {}

  /** The KV v2 data path for a record. */
  private dataUrl(key: string): string {
    return `${this.config.address}/v1/${this.config.mount}/data/${key}`;
  }

  private metadataUrl(key: string): string {
    return `${this.config.address}/v1/${this.config.mount}/metadata/${key}`;
  }

  private async token(): Promise<string> {
    const lease = this.lease;
    if (lease && (lease.expiresAt === undefined || lease.expiresAt > Date.now())) {
      return lease.token;
    }
    // A static token never expires from our side; treat it as a standing lease.
    if (this.config.token) {
      this.lease = { token: this.config.token };
      return this.config.token;
    }
    this.pendingLogin ??= this.login().finally(() => {
      this.pendingLogin = undefined;
    });
    this.lease = await this.pendingLogin;
    return this.lease.token;
  }

  private async login(): Promise<Lease> {
    if (!this.config.role) {
      throw new VaultError('Vault needs either VAULT_TOKEN or VAULT_ROLE to authenticate.');
    }
    let jwt: string;
    try {
      jwt = (
        await readFile(this.config.serviceAccountTokenPath ?? DEFAULT_K8S_TOKEN_PATH, 'utf8')
      ).trim();
    } catch {
      throw new VaultError(
        'Could not read the Kubernetes service-account token. Outside a cluster, set VAULT_TOKEN.',
      );
    }

    const response = await this.call(
      `${this.config.address}/v1/auth/${this.config.authMount ?? 'kubernetes'}/login`,
      { method: 'POST', body: JSON.stringify({ role: this.config.role, jwt }) },
    );
    const auth = (response as { auth?: { client_token?: unknown; lease_duration?: unknown } }).auth;
    if (!auth || typeof auth.client_token !== 'string') {
      throw new VaultError('Vault accepted the login but returned no token.');
    }
    const ttlSeconds = typeof auth.lease_duration === 'number' ? auth.lease_duration : 0;
    return {
      token: auth.client_token,
      expiresAt: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 - RENEW_MARGIN_MS : undefined,
    };
  }

  /** One HTTP call. `token` is omitted on the login call itself. */
  private async call(
    url: string,
    init: { method?: string; body?: string; token?: string },
  ): Promise<unknown> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (init.token) headers['x-vault-token'] = init.token;

    let response: Response;
    try {
      response = await fetch(url, {
        method: init.method ?? 'GET',
        headers,
        body: init.body,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      throw new VaultError('Could not reach Vault.');
    }

    if (response.status === 404) throw new VaultError('Not found in Vault.', 404);
    if (!response.ok) {
      // Vault's error bodies name the policy that refused, which is exactly
      // what an operator needs and contains no secret material.
      const detail = await response.text().catch(() => '');
      throw new VaultError(
        `Vault refused the request (${response.status}): ${detail.slice(0, 300)}`,
        response.status,
      );
    }
    if (response.status === 204) return {};
    return response.json().catch(() => ({}));
  }

  /**
   * Run a call, and retry once on a 403 after discarding the lease.
   *
   * A token revoked or expired early server-side reads as a permission failure,
   * not as an expiry we can see coming. One re-login turns that from an error
   * the tenant sees into one they never do.
   */
  private async authed(
    url: string,
    init: { method?: string; body?: string } = {},
  ): Promise<unknown> {
    try {
      return await this.call(url, { ...init, token: await this.token() });
    } catch (error) {
      if (error instanceof VaultError && error.status === 403 && !this.config.token) {
        this.lease = undefined;
        return this.call(url, { ...init, token: await this.token() });
      }
      throw error;
    }
  }

  /** Read a record's fields, or `undefined` when it does not exist. */
  async read(key: string): Promise<Record<string, unknown> | undefined> {
    let body: unknown;
    try {
      body = await this.authed(this.dataUrl(key));
    } catch (error) {
      if (error instanceof VaultError && error.status === 404) return undefined;
      throw error;
    }
    const data = (body as { data?: { data?: unknown } }).data?.data;
    if (data === null || data === undefined) return undefined;
    return data as Record<string, unknown>;
  }

  /**
   * Write a record, replacing whatever was there.
   *
   * Sets this path's own `max_versions` metadata every time, not once: the
   * cost is one extra idempotent call, and skipping it after the first write
   * would mean a path created before this client existed (or written by some
   * other caller) keeps whatever retention it already had.
   */
  async write(key: string, data: Record<string, unknown>): Promise<void> {
    await this.authed(this.metadataUrl(key), {
      method: 'POST',
      body: JSON.stringify({ max_versions: this.config.maxVersions ?? 1 }),
    });
    await this.authed(this.dataUrl(key), { method: 'POST', body: JSON.stringify({ data }) });
  }

  /**
   * Remove a record so that nothing readable remains.
   *
   * Deliberately not `delete`: that leaves prior versions readable, so a
   * revocation done with it would not revoke. We overwrite with an empty
   * record first — so a reader between the two calls sees nothing rather than
   * the old token — and then destroy every version that ever existed.
   */
  async destroy(key: string): Promise<void> {
    await this.write(key, {});
    const metadata = (await this.authed(this.metadataUrl(key)).catch((error) => {
      if (error instanceof VaultError && error.status === 404) return undefined;
      throw error;
    })) as { data?: { versions?: Record<string, unknown> } } | undefined;

    const versions = Object.keys(metadata?.data?.versions ?? {})
      .map(Number)
      .filter((version) => Number.isInteger(version));
    if (versions.length === 0) return;

    await this.authed(`${this.config.address}/v1/${this.config.mount}/destroy/${key}`, {
      method: 'POST',
      body: JSON.stringify({ versions }),
    });
  }
}
